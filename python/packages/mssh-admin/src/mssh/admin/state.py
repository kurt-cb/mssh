"""Deployment-state detection for `mssh-admin status` / `mssh-admin next`.

Walks the CA directory + admin API and returns a list of named checks,
each with an ok/not-ok verdict and (when not ok) a concrete suggested
next step. The CLI renders this as either a full status table or just
the first failure.

The same detector serves both `status` (show everything) and `next`
(show only the first thing to do). Adding a phase to the adoption
journey is a single new ``StateNode`` here; the CLI doesn't need to
change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from .client import CAClient


# Files mssh-admin init lays down in a CA directory. Drift from the
# init() implementation in main.py would surface as a false negative
# here, so this list is kept in sync intentionally.
_CA_BOOTSTRAP_FILES = [
    'signing-key.pem', 'signing-cert.pem',
    'bootstrap-admin-cert.pem', 'bootstrap-admin-key.pem',
    'tls-server-cert.pem', 'tls-server-key.pem',
    'tls-ca-cert.pem',
    'enrollment.yaml', 'ca-config.yaml',
]


@dataclass
class StateNode:
    """One observation about the deployment. Either ok or not."""
    id: str
    ok: bool
    message: str
    next_step: str | None = None
    next_command: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class DeploymentState:
    ca_dir: Path | None
    nodes: list[StateNode]

    @property
    def first_failure(self) -> StateNode | None:
        """The first not-ok node with a usable next_step, or None."""
        for n in self.nodes:
            if not n.ok and n.next_step:
                return n
        return None

    @property
    def all_ok(self) -> bool:
        return all(n.ok for n in self.nodes)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detect_state(*, ca_dir: Path | None = None,
                 ca_client: 'CAClient | None' = None,
                 detect_legacy: bool = True) -> DeploymentState:
    """Walk the adoption journey and report current state.

    Detection runs in phases; later phases skip if earlier phases haven't
    succeeded enough to make them meaningful (no point checking enrollment
    counts if the CA is unreachable).
    """
    nodes: list[StateNode] = []

    # Phase A: CA directory + bootstrap files on disk.
    #
    # ca_dir is only meaningful when the operator is **on the CA host
    # itself** — e.g. checking whether a fresh `init` has been run. From
    # a remote operator workstation, the CA dir lives on a different
    # machine and is irrelevant; only the admin client (mTLS creds) and
    # API reachability matter. So: if no ca_dir was given but we DO have
    # an admin client, skip the filesystem checks and let Phase B / C
    # report against the live CA.
    if ca_dir is None:
        if ca_client is None:
            nodes.append(StateNode(
                id='ca_dir_set', ok=False,
                message='no --ca-dir and no admin client',
                next_step='Initialize a fresh CA, or provide admin creds '
                          '(--ca-url + --admin-cert + --admin-key + --ca-cert) '
                          'to inspect an existing one',
                next_command='mssh-admin init --ca-dir /etc/mssh-ca'))
            return DeploymentState(ca_dir=None, nodes=nodes)
        # Have a client → skip the filesystem phase entirely.
    else:
        ca_dir = Path(ca_dir)
        if not ca_dir.is_dir():
            nodes.append(StateNode(
                id='ca_dir_exists', ok=False,
                message=f'{ca_dir} does not exist',
                next_step='Initialize the CA here',
                next_command=f'mssh-admin init --ca-dir {ca_dir}'))
            return DeploymentState(ca_dir=ca_dir, nodes=nodes)

        nodes.append(StateNode(
            id='ca_dir_exists', ok=True,
            message=f'CA directory present at {ca_dir}'))

        missing = [f for f in _CA_BOOTSTRAP_FILES if not (ca_dir / f).exists()]
        if missing:
            nodes.append(StateNode(
                id='ca_bootstrap_files', ok=False,
                message=f'CA bootstrap incomplete; missing: '
                        f'{", ".join(missing)}',
                next_step='Re-run init (refuses to overwrite existing '
                          'certs — either move them aside or use a fresh '
                          'directory)',
                next_command=f'mssh-admin init --ca-dir {ca_dir}'))
            return DeploymentState(ca_dir=ca_dir, nodes=nodes)

        nodes.append(StateNode(
            id='ca_bootstrap_files', ok=True,
            message='CA signing key + admin cert + TLS material present'))

    # Phase B: API reachability.
    if ca_client is None:
        # Caller didn't pass one. Without API access we can't go further.
        nodes.append(StateNode(
            id='admin_client_configured', ok=False,
            message='no admin client configured — file-system checks only',
            next_step='Provide --ca-url + --admin-cert + --admin-key + --ca-cert '
                      '(or write them to ~/.mssh-admin/config) and re-run'))
        return DeploymentState(ca_dir=ca_dir, nodes=nodes)

    try:
        admins = ca_client.admin_list()
    except Exception as e:
        nodes.append(StateNode(
            id='ca_reachable', ok=False,
            message=f'CA not reachable: {e}',
            next_step='Start the CA service if it is not running',
            next_command='systemctl start mssh-ca   '
                         '# or run mssh-ca --config <ca-config> directly'))
        return DeploymentState(ca_dir=ca_dir, nodes=nodes)

    nodes.append(StateNode(
        id='ca_reachable', ok=True,
        message=f'CA reachable at {ca_client.base_url}'))

    try:
        servers = ca_client.server_list()
    except Exception:
        servers = []
    try:
        users = ca_client.user_list()
    except Exception:
        users = []

    # Phase C: enrollment state.
    admin_count = len(admins) if isinstance(admins, list) else 0
    server_count = len(servers) if isinstance(servers, list) else 0
    user_count = len(users) if isinstance(users, list) else 0

    if admin_count == 0:
        nodes.append(StateNode(
            id='admins_enrolled', ok=False,
            message='no admins enrolled at all (bootstrap admin missing?)',
            next_step='Re-run init or restore the bootstrap admin in '
                      f'{ca_dir}/enrollment.yaml'))
    else:
        nodes.append(StateNode(
            id='admins_enrolled', ok=True,
            message=f'{admin_count} admin(s) enrolled'))

    if server_count == 0:
        nodes.append(StateNode(
            id='servers_enrolled', ok=False,
            message='no servers enrolled — no host can call the CA yet',
            next_step='Enrol your first server',
            next_command='mssh-admin server add --name srv-example '
                         '--groups production --out-dir ./creds'))
    else:
        sample = ', '.join(s.get('name', '?') for s in servers[:5])
        more = ' …' if server_count > 5 else ''
        nodes.append(StateNode(
            id='servers_enrolled', ok=True,
            message=f'{server_count} server(s) enrolled: {sample}{more}'))

    if user_count == 0:
        nodes.append(StateNode(
            id='users_enrolled', ok=False,
            message='no users enrolled — nobody can authenticate yet',
            next_step='Enrol your first user',
            next_command='mssh-admin user add --user alice '
                         '--key /path/to/alice.pub'))
    else:
        nodes.append(StateNode(
            id='users_enrolled', ok=True,
            message=f'{user_count} user(s) enrolled'))

    # Per-user fanout: keys + policies.
    if user_count > 0:
        users_no_key = [u['username'] for u in users if not u.get('keys')]
        users_no_policy = [u['username'] for u in users
                           if not u.get('policies')]

        if users_no_key:
            nodes.append(StateNode(
                id='users_have_keys', ok=False,
                message=f'users without any keys: {", ".join(users_no_key)}',
                next_step='Add at least one SSH pubkey for each enrolled user',
                next_command=f'mssh-admin user add --user {users_no_key[0]} '
                             '--key /path/to/key.pub'))
        else:
            nodes.append(StateNode(
                id='users_have_keys', ok=True,
                message='every enrolled user has at least one key'))

        if users_no_policy:
            nodes.append(StateNode(
                id='users_have_policies', ok=False,
                message=f'users without policies: {", ".join(users_no_policy)} '
                        '— they can authenticate but reach no host',
                next_step='Attach a policy for each user (which server groups, '
                          'channels, optional CIDRs / time windows)',
                next_command=f'mssh-admin policy add --user {users_no_policy[0]} '
                             '--server-groups production --channels session'))
        else:
            nodes.append(StateNode(
                id='users_have_policies', ok=True,
                message='every enrolled user has at least one policy'))

    # Phase D: optional legacy-config detection. Informational — surfaces
    # the existence of an existing sshd configuration on this host that
    # could feed a future `mssh-admin import` flow (legacy capture +
    # dual-enforce, see design/future-ideas.md §13).
    if detect_legacy:
        findings = detect_legacy_config()
        if findings:
            nodes.append(StateNode(
                id='legacy_config_detected', ok=True,
                message=f'legacy SSH auth artifacts on this host: '
                        f'{", ".join(findings[:3])}'
                        f'{" + more" if len(findings) > 3 else ""}',
                notes=[
                    'A future `mssh-admin import` will produce a draft '
                    'enrollment from existing authorized_keys / sshd_config '
                    'so adoption preserves current access patterns. Not yet '
                    'implemented; see design/future-ideas.md §13.',
                ]))

    return DeploymentState(ca_dir=ca_dir, nodes=nodes)


def _path_exists(p: Path) -> bool:
    """Like Path.exists(), but treats PermissionError as 'unknown' and
    returns False rather than raising. We can't enrol a path we can't
    read anyway."""
    try:
        return p.exists()
    except (PermissionError, OSError):
        return False


def detect_legacy_config(scan_homes: bool = True) -> list[str]:
    """Return a list of legacy SSH auth artifacts found on this host.

    Looks for `/etc/ssh/sshd_config` and any `~/.ssh/authorized_keys`
    files under `/root` and `/home/<user>`. Caller-bounded: stops at
    5 findings so the message stays readable. Permission errors on any
    candidate path are silently ignored — if we can't read it, we can't
    import from it either.
    """
    findings: list[str] = []
    sshd_config = Path('/etc/ssh/sshd_config')
    if _path_exists(sshd_config):
        findings.append(str(sshd_config))

    if not scan_homes:
        return findings

    candidates = [Path('/root')]
    home = Path('/home')
    try:
        if home.is_dir():
            candidates.extend(p for p in sorted(home.iterdir()) if p.is_dir())
    except (PermissionError, OSError):
        pass

    for h in candidates:
        ak = h / '.ssh' / 'authorized_keys'
        if _path_exists(ak):
            findings.append(str(ak))
            if len(findings) >= 5:
                break
    return findings


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------


def render_status(state: DeploymentState) -> str:
    """Render the full state as a human-readable multi-line string."""
    lines: list[str] = []
    if state.ca_dir:
        lines.append(f'CA directory: {state.ca_dir}')
        lines.append('')
    for node in state.nodes:
        mark = '✓' if node.ok else '✗'
        lines.append(f'  {mark}  {node.message}')
        for note in node.notes:
            lines.append(f'         note: {note}')
    lines.append('')

    nxt = state.first_failure
    if nxt is None:
        lines.append('All checks passed. Test a connection from a client to '
                     'confirm end-to-end.')
    else:
        lines.append(f'Next: {nxt.next_step}')
        if nxt.next_command:
            lines.append('')
            lines.append(f'    {nxt.next_command}')
    return '\n'.join(lines)


def render_next(state: DeploymentState) -> str:
    """Render just the next-step message for `mssh-admin next`."""
    nxt = state.first_failure
    if nxt is None:
        return ('Deployment looks fully provisioned. Test a connection '
                'from a client to confirm.')

    lines: list[str] = []
    lines.append(nxt.message)
    lines.append('')
    if nxt.next_step:
        lines.append(f'Next: {nxt.next_step}')
    if nxt.next_command:
        lines.append('')
        lines.append(f'    {nxt.next_command}')
    return '\n'.join(lines)


def ca_url_from_config(ca_dir: Path) -> str | None:
    """Read the CA's listen address out of ca-config.yaml and turn it into
    a client-callable URL. Returns None if config is unreadable. Treats
    0.0.0.0 as 127.0.0.1 (clients can't connect to wildcard)."""
    cfg_path = ca_dir / 'ca-config.yaml'
    if not cfg_path.exists():
        return None
    try:
        cfg = yaml.safe_load(cfg_path.read_text()) or {}
    except Exception:
        return None
    listen = cfg.get('listen')
    if isinstance(listen, str) and ':' in listen:
        host, port = listen.rsplit(':', 1)
    elif isinstance(listen, dict):
        host = listen.get('host', '127.0.0.1')
        port = listen.get('port', 8443)
    else:
        return None
    if host in ('0.0.0.0', '::'):
        host = '127.0.0.1'
    return f'https://{host}:{port}'
