"""mssh-admin CLI entry point (click-based)."""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

import click
import yaml

from mssh.ca.cert_minter import bootstrap_ca

from . import formatters
from .client import CAClient, CAClientError
from .key_parser import b64_blob, parse_key_file


CONFIG_PATH_DEFAULT = Path.home() / '.mssh-admin' / 'config'


def _load_cli_config(path: str | Path | None) -> dict[str, Any]:
    p = Path(path) if path else CONFIG_PATH_DEFAULT
    if not p.exists():
        return {}
    with p.open() as f:
        return yaml.safe_load(f) or {}


def _make_client(ctx: click.Context) -> CAClient:
    conf = ctx.obj.get('_config', {})
    ca_url = ctx.obj.get('ca_url') or conf.get('ca_url')
    cert = ctx.obj.get('admin_cert') or conf.get('admin_cert')
    key = ctx.obj.get('admin_key') or conf.get('admin_key')
    ca_cert = ctx.obj.get('ca_cert') or conf.get('ca_cert')
    if not all([ca_url, cert, key, ca_cert]):
        raise click.UsageError(
            'must provide --ca-url, --admin-cert, --admin-key, --ca-cert '
            '(or set them in ~/.mssh-admin/config)')
    return CAClient(base_url=ca_url, admin_cert=cert, admin_key=key,
                    ca_cert=ca_cert)


def _output(ctx: click.Context, data: Any) -> None:
    click.echo(formatters.render(data, fmt=ctx.obj.get('format', 'table')))


def _handle_call(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except CAClientError as e:
        click.echo(f'error: HTTP {e.status}: {e.body}', err=True)
        raise SystemExit(1)


# Poll interval + total timeout when waiting on a 2FA ceremony. The
# broker's TTL sweeper is the authoritative deadline; we just need to
# poll often enough to feel responsive without spamming.
_PASSKEY_POLL_INTERVAL_SECONDS = 2.0
_PASSKEY_POLL_TIMEOUT_SECONDS = 180.0


def _handle_2fa_call(client, fn, *args, **kwargs):
    """Like `_handle_call`, but recognises the 2FA challenge protocol.

    Server returns ``{'status': 'pending_2fa', ...}`` when the
    operation needs a passkey ceremony. We print the URL, poll the
    ceremony, and on approval retry the original request — the second
    call hits the 2FA cache and proceeds.
    """
    resp = _handle_call(fn, *args, **kwargs)
    if not isinstance(resp, dict) or resp.get('status') != 'pending_2fa':
        return resp
    ceremony_id = resp.get('ceremony_id')
    url = resp.get('url') or '(no URL)'
    click.echo(f'2FA required — approve on your phone:\n    {url}',
               err=True)
    deadline = time.monotonic() + _PASSKEY_POLL_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        time.sleep(_PASSKEY_POLL_INTERVAL_SECONDS)
        poll = _handle_call(client.passkey_poll, ceremony_id)
        if poll.get('status') == 'pending':
            continue
        outcome = poll.get('outcome')
        if outcome == 'approved':
            click.echo('  ✓ approved — retrying operation', err=True)
            return _handle_call(fn, *args, **kwargs)
        if outcome == 'denied':
            click.echo('error: 2FA denied by user', err=True)
            raise SystemExit(2)
        if outcome == 'expired':
            click.echo('error: 2FA ceremony expired', err=True)
            raise SystemExit(2)
        click.echo(f'error: unexpected 2FA outcome: {outcome!r}', err=True)
        raise SystemExit(2)
    click.echo('error: 2FA timed out waiting for approval', err=True)
    raise SystemExit(2)


# ---------------------------------------------------------------------------
# Group + global options
# ---------------------------------------------------------------------------

@click.group()
@click.option('--config', 'config_path', type=click.Path(),
              help='Path to mssh-admin config (default: ~/.mssh-admin/config).')
@click.option('--ca-url')
@click.option('--admin-cert', type=click.Path())
@click.option('--admin-key', type=click.Path())
@click.option('--ca-cert', type=click.Path())
@click.option('--format', 'output_format',
              type=click.Choice(['table', 'json', 'yaml']), default='table')
@click.pass_context
def cli(ctx, config_path, ca_url, admin_cert, admin_key, ca_cert, output_format):
    """mssh-admin — management CLI for mssh."""
    ctx.ensure_object(dict)
    ctx.obj['_config'] = _load_cli_config(config_path)
    ctx.obj['ca_url'] = ca_url
    ctx.obj['admin_cert'] = admin_cert
    ctx.obj['admin_key'] = admin_key
    ctx.obj['ca_cert'] = ca_cert
    ctx.obj['format'] = output_format


# ---------------------------------------------------------------------------
# init (no CA call — writes config + bootstrap admin cert)
# ---------------------------------------------------------------------------

@cli.command()
@click.option('--ca-dir', required=True, type=click.Path(),
              help='Directory to write CA keys and certs into.')
@click.option('--bootstrap-admin', default='bootstrap-admin',
              help='CN for the initial superuser admin cert.')
@click.option('--tls-server-cn', default='mssh-ca',
              help='CN for the CA\'s TLS server cert.')
@click.option('--tls-server-san', multiple=True,
              help='SubjectAltName for the CA\'s TLS server cert (repeatable). '
                   'Default: DNS:localhost, IP:127.0.0.1.')
def init(ca_dir, bootstrap_admin, tls_server_cn, tls_server_san):
    """Initialize a fresh CA: signing key + bootstrap admin cert."""
    ca_dir = Path(ca_dir)
    if any(ca_dir.glob('*.pem')) and ca_dir.exists():
        raise click.UsageError(f'{ca_dir} already contains certs; refusing to overwrite')
    sans = list(tls_server_san) or ['DNS:localhost', 'IP:127.0.0.1']
    artifacts = bootstrap_ca(
        ca_dir, bootstrap_admin_cn=bootstrap_admin,
        tls_server_cn=tls_server_cn, tls_server_sans=sans,
    )

    # Drop a default ca-config.yaml so the user can run the server immediately.
    ca_config = {
        'listen': '127.0.0.1:8443',
        'signing_key': str(ca_dir / 'signing-key.pem'),
        'signing_cert': str(ca_dir / 'signing-cert.pem'),
        'tls_cert': str(ca_dir / 'tls-server-cert.pem'),
        'tls_key': str(ca_dir / 'tls-server-key.pem'),
        'client_ca_cert': str(ca_dir / 'tls-ca-cert.pem'),
        'identity_trust_roots': [],
        'enrollment': {'type': 'file', 'path': str(ca_dir / 'enrollment.yaml')},
        'audit': {'type': 'file', 'path': str(ca_dir / 'audit.jsonl')},
        'defaults': {'max_cert_validity_seconds': 3600,
                     'timestamp_drift_seconds': 60},
        'cert_generation': {'key_type': 'ec',
                            'server_cert_validity_days': 365,
                            'admin_cert_validity_days': 365},
    }
    (ca_dir / 'ca-config.yaml').write_text(yaml.safe_dump(ca_config, sort_keys=True))

    # Empty enrollment file so the CA can boot. Seed it with the bootstrap admin.
    enroll = {
        'admins': {
            bootstrap_admin: {
                'role': 'superuser',
                'mtls_subject': f'CN={bootstrap_admin}',
                'enrolled_at': '', 'enrolled_by': 'init',
            }
        }
    }
    (ca_dir / 'enrollment.yaml').write_text(yaml.safe_dump(enroll, sort_keys=True))

    click.echo(f'CA initialized in {ca_dir}')
    click.echo(f'Bootstrap admin cert: {ca_dir}/bootstrap-admin-cert.pem')
    click.echo(f'Bootstrap admin key:  {ca_dir}/bootstrap-admin-key.pem')
    click.echo(f'CA config:            {ca_dir}/ca-config.yaml')


# ---------------------------------------------------------------------------
# status / next — adoption-state introspection
# ---------------------------------------------------------------------------

def _build_state_client(ctx, ca_dir):
    """Best-effort CAClient builder for status/next. Returns None if we
    can't construct one — state.detect_state() reports the gap as one of
    its checks rather than crashing."""
    from .client import CAClient
    from . import state as _state

    # First try the global --ca-url / --admin-cert / etc. options.
    try:
        return _make_client(ctx)
    except click.UsageError:
        pass

    # Fall back to bootstrap creds inside ca_dir, if it exists.
    if not ca_dir:
        return None
    ca_dir = Path(ca_dir)
    if not ca_dir.is_dir():
        return None
    url = _state.ca_url_from_config(ca_dir)
    cert = ca_dir / 'bootstrap-admin-cert.pem'
    key = ca_dir / 'bootstrap-admin-key.pem'
    root = ca_dir / 'tls-ca-cert.pem'
    if not (url and cert.exists() and key.exists() and root.exists()):
        return None
    return CAClient(base_url=url, admin_cert=str(cert),
                    admin_key=str(key), ca_cert=str(root))


@cli.command()
@click.option('--ca-dir', type=click.Path(),
              help='CA directory to inspect (default: try config-defined dir).')
@click.option('--no-legacy-detect', is_flag=True,
              help='Skip detection of existing sshd_config / authorized_keys '
                   'on the local host.')
@click.pass_context
def status(ctx, ca_dir, no_legacy_detect):
    """Show current deployment state — what's set up, what's not."""
    from . import state as _state
    ca_dir_path = Path(ca_dir) if ca_dir else None
    client = _build_state_client(ctx, ca_dir_path)
    s = _state.detect_state(ca_dir=ca_dir_path, ca_client=client,
                            detect_legacy=not no_legacy_detect)
    click.echo(_state.render_status(s))


@cli.command(name='next')
@click.option('--ca-dir', type=click.Path())
@click.option('--no-legacy-detect', is_flag=True)
@click.pass_context
def next_cmd(ctx, ca_dir, no_legacy_detect):
    """Show only the next step in adoption — what to do right now."""
    from . import state as _state
    ca_dir_path = Path(ca_dir) if ca_dir else None
    client = _build_state_client(ctx, ca_dir_path)
    s = _state.detect_state(ca_dir=ca_dir_path, ca_client=client,
                            detect_legacy=not no_legacy_detect)
    click.echo(_state.render_next(s))


# ---------------------------------------------------------------------------
# server commands
# ---------------------------------------------------------------------------

@cli.group()
def server():
    """Server enrollment commands."""


@server.command('add')
@click.option('--name', required=True)
@click.option('--groups', default='', help='Comma-separated group list.')
@click.option('--out-dir', type=click.Path(),
              help='If set, write the issued mTLS cert/key into this directory.')
@click.pass_context
def server_add(ctx, name, groups, out_dir):
    groups_list = [g.strip() for g in groups.split(',') if g.strip()]
    c = _make_client(ctx)
    resp = _handle_call(c.server_add, name, groups_list)
    if out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        (od / f'{name}-cert.pem').write_text(resp['credentials']['cert_pem'])
        (od / f'{name}-key.pem').write_text(resp['credentials']['key_pem'])
        os.chmod(od / f'{name}-key.pem', 0o600)
        (od / 'ca-cert.pem').write_text(resp['credentials']['ca_cert_pem'])
        click.echo(f'wrote {od}/{name}-cert.pem and {od}/{name}-key.pem')
    _output(ctx, resp['server'])


@server.command('remove')
@click.option('--name', required=True)
@click.pass_context
def server_remove(ctx, name):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.server_remove, name))


@server.command('list')
@click.option('--group', help='Filter to a specific group.')
@click.option('--name', help='Filter to servers whose name starts with this prefix.')
@click.pass_context
def server_list(ctx, group, name):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.server_list, group=group, name_prefix=name))


@server.command('show')
@click.option('--name', required=True,
              help='Server canonical name to look up.')
@click.pass_context
def server_show(ctx, name):
    """Inspect a single server's enrollment record."""
    c = _make_client(ctx)
    matches = _handle_call(c.server_list, name_prefix=name)
    # Walk for an exact name match; --name as prefix is a filter.
    exact = [s for s in matches if s.get('name') == name]
    if not exact:
        click.echo(f'error: no server named {name!r}', err=True)
        ctx.exit(1)
    _output(ctx, exact[0])


@server.command('groups')
@click.option('--name', required=True, help='Server to modify.')
@click.option('--add', multiple=True,
              help='Add this group (repeatable). e.g. --add ops --add prod')
@click.option('--remove', multiple=True,
              help='Remove this group (repeatable).')
@click.option('--set', 'set_groups', default=None,
              help='Replace the group list with this comma-separated list. '
                   'Mutually exclusive with --add / --remove.')
@click.pass_context
def server_groups(ctx, name, add, remove, set_groups):
    """Manage a server's group memberships at runtime.

    Group changes take effect on the next authorize call (CA cache is
    keyed by principal, not by server-groups).
    """
    if set_groups is not None and (add or remove):
        click.echo('error: --set is mutually exclusive with --add/--remove',
                   err=True)
        ctx.exit(2)
    c = _make_client(ctx)
    if set_groups is not None:
        new_groups = [g.strip() for g in set_groups.split(',') if g.strip()]
    else:
        # Compute from current state + add/remove.
        matches = _handle_call(c.server_list, name_prefix=name)
        srv = next((s for s in matches if s.get('name') == name), None)
        if srv is None:
            click.echo(f'error: no server named {name!r}', err=True)
            ctx.exit(1)
        current = set(srv.get('groups') or [])
        new_groups = sorted(current.union(add) - set(remove))
    _output(ctx, _handle_call(c.server_set_groups, name, new_groups))


# ---------------------------------------------------------------------------
# user commands
# ---------------------------------------------------------------------------

@cli.group()
def user():
    """User enrollment commands."""


@user.command('add')
@click.option('--user', 'username', required=True)
@click.option('--key', 'key_path', type=click.Path(exists=True),
              help='SSH pubkey or OpenSSH cert file. Creates user if missing.')
@click.option('--cert', 'cert_path', type=click.Path(exists=True),
              help='OpenSSH cert file (alias of --key for clarity).')
@click.pass_context
def user_add(ctx, username, key_path, cert_path):
    c = _make_client(ctx)
    try:
        _handle_call(c.user_add, username)
    except SystemExit:
        # user may already exist — continue and let the key add report
        pass
    path = key_path or cert_path
    if path:
        parsed = parse_key_file(path)
        resp = _handle_call(c.user_key_add, username, parsed.type, b64_blob(parsed))
        _output(ctx, resp['key'])
    else:
        _output(ctx, {'user_added': username})


@user.command('remove')
@click.option('--user', 'username', required=True)
@click.pass_context
def user_remove(ctx, username):
    c = _make_client(ctx)
    _output(ctx, _handle_2fa_call(c, c.user_remove, username))


@user.command('remove-key')
@click.option('--user', 'username', required=True)
@click.option('--fingerprint', required=True)
@click.pass_context
def user_remove_key(ctx, username, fingerprint):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.user_key_remove, username, fingerprint))


@user.command('list')
@click.option('--user', 'username')
@click.pass_context
def user_list(ctx, username):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.user_list, username=username))


@user.command('show')
@click.option('--user', 'username', required=True,
              help='User to look up.')
@click.pass_context
def user_show(ctx, username):
    """Inspect a single user's enrollment record. Same data as
    `user list --user X` but errors clearly if the user isn't enrolled."""
    c = _make_client(ctx)
    users = _handle_call(c.user_list, username=username)
    exact = [u for u in users if u.get('username') == username]
    if not exact:
        click.echo(f'error: no user named {username!r}', err=True)
        ctx.exit(1)
    _output(ctx, exact[0])


# ---------------------------------------------------------------------------
# user passkey commands — admin-2FA enrollment (design/admin-2fa.md)
# ---------------------------------------------------------------------------

@user.group('passkey')
def user_passkey():
    """Manage admin passkey credentials for 2FA on privileged operations."""


@user_passkey.command('enroll')
@click.option('--user', 'admin_name', required=True,
              help='The enrolled admin whose phone will register a passkey.')
@click.option('--label', default='',
              help='Operator-visible label for the credential, e.g. '
                   '"alice yubikey 5C".')
@click.option('--display-name', default='',
              help='Display name shown on the registration page '
                   '(defaults to the admin name).')
@click.pass_context
def user_passkey_enroll_cmd(ctx, admin_name, label, display_name):
    """Mint a one-time URL the admin opens on their phone to register
    a new passkey.

    The URL expires in 5 minutes. mssh-ca records the credential
    against the admin's enrollment record when the broker callback
    fires after the WebAuthn ceremony completes.
    """
    c = _make_client(ctx)
    out = _handle_call(c.passkey_admin_enroll, admin_name,
                       label=label, display_name=display_name)
    click.echo('passkey enrollment URL (1-time, expires in 5 min):', err=True)
    click.echo(f'  {out["url"]}', err=True)
    click.echo('Open this on the admin\'s phone and follow the prompts.', err=True)
    _output(ctx, {
        'ceremony_id': out['ceremony_id'],
        'expires_at': out['expires_at'],
    })


@user_passkey.command('list')
@click.option('--user', 'admin_name', required=True)
@click.pass_context
def user_passkey_list_cmd(ctx, admin_name):
    """List registered passkey credentials for an admin."""
    c = _make_client(ctx)
    out = _handle_call(c.passkey_admin_list, admin_name)
    _output(ctx, out['credentials'])


@user_passkey.command('revoke')
@click.option('--user', 'admin_name', required=True)
@click.option('--credential-id', required=True,
              help='base64url credential ID, as shown by `list`.')
@click.pass_context
def user_passkey_revoke_cmd(ctx, admin_name, credential_id):
    """Revoke one passkey credential.

    Active 2FA cache entries for this admin are also invalidated.
    """
    c = _make_client(ctx)
    out = _handle_call(c.passkey_admin_revoke, admin_name, credential_id)
    _output(ctx, out)


# ---------------------------------------------------------------------------
# policy commands
# ---------------------------------------------------------------------------

@cli.group()
def policy():
    """Policy commands."""


@policy.command('add')
@click.option('--user', 'username', required=True)
@click.option('--servers', default='', help='Comma-separated server canonical names.')
@click.option('--server-groups', default='', help='Comma-separated group names.')
@click.option('--channels', required=True,
              help='Comma-separated channel types (e.g. session,direct-tcpip).')
@click.option('--source-cidrs', default='')
@click.option('--max-validity', 'max_validity', default=3600, type=int)
@click.option('--force-command', default=None)
@click.option('--require-2fa', 'require_2fa',
              type=click.Choice(['none', 'passkey']), default='none',
              help='Require an additional factor for actions matching '
                   'this policy. "passkey" triggers a mssh-passkey '
                   'ceremony before mssh-ca executes the action; the '
                   'CLI shows a one-time URL the operator opens on '
                   'their phone.')
@click.option('--2fa-within-seconds', 'twofa_within_seconds',
              type=int, default=60,
              help='Cache window (seconds) after a successful 2FA. '
                   'Subsequent matching actions within the window '
                   'skip the prompt. Default 60.')
@click.pass_context
def policy_add(ctx, username, servers, server_groups, channels, source_cidrs,
               max_validity, force_command, require_2fa, twofa_within_seconds):
    def _split(s): return [x.strip() for x in s.split(',') if x.strip()]
    policy = {
        'servers': _split(servers),
        'server_groups': _split(server_groups),
        'channels': _split(channels),
        'source_cidrs': _split(source_cidrs),
        'max_cert_validity_seconds': max_validity,
        'force_command': force_command,
        'require_2fa': require_2fa,
        'twofa_within_seconds': twofa_within_seconds,
    }
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.policy_add, username, policy))


@policy.command('remove')
@click.option('--id', 'policy_id', required=True)
@click.pass_context
def policy_remove(ctx, policy_id):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.policy_remove, policy_id))


# ---------------------------------------------------------------------------
# admin commands
# ---------------------------------------------------------------------------

@cli.group()
def admin():
    """Admin user commands (superuser-only operations)."""


@admin.command('add')
@click.option('--name', required=True)
@click.option('--role', required=True,
              type=click.Choice(['superuser', 'server-admin', 'user-admin', 'auditor']))
@click.option('--out-dir', type=click.Path(),
              help='If set, write the issued mTLS cert/key into this directory.')
@click.pass_context
def admin_add(ctx, name, role, out_dir):
    c = _make_client(ctx)
    resp = _handle_2fa_call(c, c.admin_add, name, role)
    if out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        (od / f'{name}-cert.pem').write_text(resp['credentials']['cert_pem'])
        (od / f'{name}-key.pem').write_text(resp['credentials']['key_pem'])
        os.chmod(od / f'{name}-key.pem', 0o600)
        click.echo(f'wrote {od}/{name}-cert.pem and {od}/{name}-key.pem')
    _output(ctx, resp['admin'])


@admin.command('remove')
@click.option('--name', required=True)
@click.pass_context
def admin_remove(ctx, name):
    c = _make_client(ctx)
    _output(ctx, _handle_2fa_call(c, c.admin_remove, name))


@admin.command('list')
@click.pass_context
def admin_list(ctx):
    c = _make_client(ctx)
    _output(ctx, _handle_call(c.admin_list))


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

@cli.command('audit')
@click.option('--type', 'type_', default='all')
@click.option('--decision')
@click.option('--user', 'username')
@click.option('--server', 'srv')
@click.option('--limit', default=100, type=int)
@click.pass_context
def audit(ctx, type_, decision, username, srv, limit):
    c = _make_client(ctx)
    out = _handle_call(c.audit, type=type_, decision=decision,
                       username=username, server=srv, limit=limit)
    _output(ctx, out.get('entries', []))


# ---------------------------------------------------------------------------
# template — per-scope inner sshd_config templates (Phase 1d)
# ---------------------------------------------------------------------------

@cli.group('template')
def template_group():
    """Manage CA-side inner sshd config templates."""


def _resolve_scope(scope: str, name: str | None) -> tuple[str, str | None]:
    if scope not in ('default', 'group', 'server'):
        raise click.UsageError(
            "--scope must be one of: default, group, server")
    if scope in ('group', 'server') and not name:
        raise click.UsageError(f'--scope {scope} requires --name')
    if scope == 'default' and name:
        raise click.UsageError("--scope default doesn't take --name")
    return scope, name


@template_group.command('list')
@click.pass_context
def template_list_cmd(ctx):
    """Show all stored templates (built-in + default + groups + servers)."""
    c = _make_client(ctx)
    out = _handle_call(c.template_list)
    _output(ctx, out.get('templates', {}))


@template_group.command('show')
@click.option('--scope', default='default',
              help='default | group | server | effective')
@click.option('--name',
              help='Required for scope=group/server/effective.')
@click.option('--kind', default='openssh')
@click.pass_context
def template_show(ctx, scope, name, kind):
    """Print the template for a scope to stdout. For scope=effective the
    output is what would actually be used at session time (after
    walking per-server → per-group → default → built-in precedence)."""
    c = _make_client(ctx)
    if scope == 'effective':
        if not name:
            raise click.UsageError('--scope effective requires --name')
        out = _handle_call(c.template_effective, name, kind=kind)
        click.echo(f'# source={out["source"]} '
                   f'detail={out.get("source_detail") or "-"}',
                   err=True)
        click.echo(out['content'], nl=False)
        return
    out = _handle_call(c.template_list)
    tpls = out.get('templates', {})
    if scope == 'default':
        content = tpls.get('default', {}).get(kind)
    elif scope == 'group':
        _resolve_scope('group', name)
        content = (tpls.get('groups', {}).get(name) or {}).get(kind)
    elif scope == 'server':
        _resolve_scope('server', name)
        content = (tpls.get('servers', {}).get(name) or {}).get(kind)
    else:
        raise click.UsageError(
            "--scope must be one of: default, group, server, effective")
    if content is None:
        click.echo(f'(no override for scope={scope} name={name} '
                   f'kind={kind}; showing built-in)', err=True)
        click.echo(tpls.get('builtin', {}).get(kind, ''), nl=False)
    else:
        click.echo(content, nl=False)


@template_group.command('set')
@click.option('--scope', required=True, help='default | group | server')
@click.option('--name', help='Required for scope=group/server.')
@click.option('--kind', default='openssh')
@click.option('--content-file', type=click.Path(exists=False),
              help='Read template from this file. Use - for stdin.')
@click.pass_context
def template_set_cmd(ctx, scope, name, kind, content_file):
    """Set the template at this scope from a file or stdin."""
    scope, name = _resolve_scope(scope, name)
    if not content_file:
        raise click.UsageError('--content-file is required')
    if content_file == '-':
        content = click.get_text_stream('stdin').read()
    else:
        p = Path(content_file)
        if not p.exists():
            raise click.UsageError(f'no such file: {content_file}')
        content = p.read_text()
    c = _make_client(ctx)
    out = _handle_call(c.template_set, scope, kind, content, scope_name=name)
    _output(ctx, out)


@template_group.command('unset')
@click.option('--scope', required=True, help='default | group | server')
@click.option('--name', help='Required for scope=group/server.')
@click.option('--kind', default='openssh')
@click.pass_context
def template_unset_cmd(ctx, scope, name, kind):
    """Remove the template override at this scope (revert to the
    next-level fallback). Idempotent."""
    scope, name = _resolve_scope(scope, name)
    c = _make_client(ctx)
    out = _handle_call(c.template_unset, scope, kind, scope_name=name)
    _output(ctx, out)


@template_group.command('edit')
@click.option('--scope', required=True, help='default | group | server')
@click.option('--name', help='Required for scope=group/server.')
@click.option('--kind', default='openssh')
@click.pass_context
def template_edit(ctx, scope, name, kind):
    """Open the current template in $EDITOR; save back on exit.

    For default: starts from the existing override or the built-in.
    For group / server: starts from the current effective template (so
    the editor opens the directives that are actually in force, ready
    to override). Saving with no changes is a no-op.
    """
    import subprocess
    import tempfile
    scope, name = _resolve_scope(scope, name)
    c = _make_client(ctx)

    if scope == 'default':
        snapshot = _handle_call(c.template_list).get('templates', {})
        current = (snapshot.get('default', {}).get(kind)
                   or snapshot.get('builtin', {}).get(kind, ''))
    elif scope == 'server':
        eff = _handle_call(c.template_effective, name, kind=kind)
        current = eff['content']
    else:  # group
        snapshot = _handle_call(c.template_list).get('templates', {})
        current = ((snapshot.get('groups', {}).get(name) or {}).get(kind)
                   or snapshot.get('default', {}).get(kind)
                   or snapshot.get('builtin', {}).get(kind, ''))

    editor = os.environ.get('VISUAL') or os.environ.get('EDITOR') or 'vi'
    with tempfile.NamedTemporaryFile(
            mode='w', suffix='.sshd_config.template', delete=False) as f:
        f.write(current)
        tmp_path = f.name
    try:
        rc = subprocess.call([editor, tmp_path])
        if rc != 0:
            click.echo(f'editor exited {rc}; not saving', err=True)
            return
        new_content = Path(tmp_path).read_text()
        if new_content == current:
            click.echo('no changes; not saving.', err=True)
            return
        out = _handle_call(c.template_set, scope, kind, new_content,
                           scope_name=name)
        _output(ctx, out)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@template_group.command('diff')
@click.argument('server_name')
@click.option('--kind', default='openssh')
@click.option('--against', default='builtin',
              help='What to diff against: builtin | default')
@click.pass_context
def template_diff(ctx, server_name, kind, against):
    """Show how a server's effective template differs from baseline.

    Useful for audits — "which hosts are special, and why?"
    """
    import difflib
    c = _make_client(ctx)
    eff = _handle_call(c.template_effective, server_name, kind=kind)
    snapshot = _handle_call(c.template_list).get('templates', {})
    if against == 'builtin':
        baseline = snapshot.get('builtin', {}).get(kind, '')
        baseline_label = f'builtin/{kind}'
    elif against == 'default':
        baseline = (snapshot.get('default', {}).get(kind)
                    or snapshot.get('builtin', {}).get(kind, ''))
        baseline_label = f'default/{kind}'
    else:
        raise click.UsageError("--against must be 'builtin' or 'default'")
    eff_label = f'{eff["source"]}/{eff.get("source_detail") or kind}'
    diff_lines = difflib.unified_diff(
        baseline.splitlines(keepends=True),
        eff['content'].splitlines(keepends=True),
        fromfile=baseline_label,
        tofile=f'{server_name} ({eff_label})',
    )
    diff_text = ''.join(diff_lines)
    if not diff_text:
        click.echo(f"(no difference between {server_name}'s effective "
                   f'template and {baseline_label})')
    else:
        click.echo(diff_text, nl=False)


# ---------------------------------------------------------------------------
# CA-bypass cert
# ---------------------------------------------------------------------------

@cli.group('bypass-cert')
def bypass_cert_group():
    """Mint operator-presentable CA-bypass authz certs.

    A bypass cert is a normal authz cert with one extra marker
    extension. The operator stores it offline; when presented via
    `mssh --inject-bypass-cert <cert>`, msshd validates the cert and
    injects it directly into its authz cache without a live CA call.
    Lets the operator reach msshd hosts whose CA is currently
    unreachable. See archive/design/notes-bypass-cache.md.
    """


def _read_ssh_pubkey_blob(path: str) -> bytes:
    """Read an OpenSSH-format ``.pub`` file and return the raw
    wire-format pubkey blob (the bit between ``ssh-ed25519 `` and the
    optional comment)."""
    text = Path(path).read_text().strip()
    parts = text.split()
    if len(parts) < 2:
        raise click.ClickException(
            f'{path}: not an SSH public key (expected '
            f'"<type> <base64> [comment]")')
    import base64 as _b64
    try:
        return _b64.b64decode(parts[1], validate=True)
    except Exception as e:
        raise click.ClickException(f'{path}: bad base64: {e}')


@bypass_cert_group.command('mint')
@click.argument('username')
@click.option('--pubkey', 'pubkey_path', required=True,
              type=click.Path(exists=True, dir_okay=False),
              help="Path to the user's .pub file (the SSH pubkey to "
                   'bind into the bypass cert).')
@click.option('--valid-days', type=int, default=90,
              show_default=True,
              help='Bypass cert validity window in days.')
@click.option('--source-bind', default=None,
              help='Restrict bypass to a source CIDR. Default: any.')
@click.option('--server-bind', default=None,
              help='Restrict bypass to a server pattern. '
                   'Default: any.')
@click.option('--force-command', default=None,
              help='Force a specific command for bypass sessions '
                   '(e.g. /usr/local/bin/emergency-shell).')
@click.option('--max-session-seconds', type=int, default=None,
              help='Cap each bypass session duration.')
@click.option('--out', 'out_path',
              type=click.Path(dir_okay=False),
              help='Write the minted PEM cert to this path '
                   '(default: stdout).')
@click.pass_context
def bypass_cert_mint_cmd(ctx, username, pubkey_path, valid_days,
                         source_bind, server_bind, force_command,
                         max_session_seconds, out_path):
    """Mint a CA-bypass authz cert for USERNAME and write the PEM.

    Example:
        mssh-admin bypass-cert mint alice \
            --pubkey ~/.ssh/alice.pub \
            --valid-days 90 \
            --out alice-bypass.crt
    """
    import base64 as _b64
    c = _make_client(ctx)
    pubkey_blob = _read_ssh_pubkey_blob(pubkey_path)
    pubkey_b64 = _b64.b64encode(pubkey_blob).decode('ascii')

    out = _handle_call(
        c.bypass_cert_mint, username, pubkey_b64,
        validity_days=valid_days,
        source_bind=source_bind, server_bind=server_bind,
        force_command=force_command,
        max_session_seconds=max_session_seconds,
    )

    cert_pem = out.get('cert_pem', '')
    if out_path:
        Path(out_path).write_text(cert_pem)
        click.echo(f'wrote {out_path}', err=True)
    else:
        click.echo(cert_pem, nl=False)
    click.echo(
        f'\n# username={out["username"]} serial={out["serial"]} '
        f'not_after={out["not_after"]}',
        err=True)


# ---------------------------------------------------------------------------
# CRL / cert revocation
# ---------------------------------------------------------------------------

@cli.group('cert')
def cert_group():
    """Manage authz certs minted by this CA (revoke, §5 mint, …)."""


@cert_group.command('mint')
@click.option('--type', 'cert_type',
              type=click.Choice(['tls-server', 'https-user', 'code-sign']),
              required=True,
              help='Cert flavor. tls-server: serverAuth EKU + optional SANs. '
                   'https-user: clientAuth EKU, browser-importable. '
                   'code-sign: codeSigning EKU.')
@click.option('--cn', required=True, help='Common Name on the leaf cert.')
@click.option('--san', 'sans', multiple=True,
              help='SubjectAltName (tls-server only). '
                   'Forms: DNS:foo.example.com, IP:10.0.0.1, or bare host. '
                   'Repeat for multiple.')
@click.option('--validity-days', type=int, default=None,
              help='Cert validity in days (default per type; capped at 825).')
@click.option('--out', 'out_prefix', default=None, type=click.Path(),
              help='Write outputs to OUT-cert.pem, OUT-key.pem, OUT-ca.pem. '
                   'For --type https-user also writes OUT.p12 if --p12-password '
                   'is set. Without --out, the cert + key are printed to stdout.')
@click.option('--p12-password', default=None,
              help='Password for PKCS#12 export (https-user only). '
                   'If unset, no .p12 is generated.')
@click.pass_context
def cert_mint_cmd(ctx, cert_type, cn, sans, validity_days, out_prefix,
                  p12_password):
    """Mint a §5 cert via the CA.

    Examples:

      \b
      # TLS server cert for an internal HTTPS endpoint:
      mssh-admin cert mint --type tls-server \\
                           --cn grafana.internal.example.com \\
                           --san DNS:grafana.internal.example.com \\
                           --san IP:10.10.0.42 \\
                           --validity-days 30 \\
                           --out grafana

      \b
      # Browser-importable HTTPS client cert:
      mssh-admin cert mint --type https-user --cn alice \\
                           --p12-password CHANGEME --out alice

      \b
      # Code-signing cert:
      mssh-admin cert mint --type code-sign --cn 'Build agent 03' \\
                           --validity-days 180 --out build03
    """
    if sans and cert_type != 'tls-server':
        click.echo(f'error: --san is only valid for --type tls-server '
                   f'(got --type {cert_type})', err=True)
        ctx.exit(2)
    if p12_password and cert_type != 'https-user':
        click.echo('error: --p12-password is only valid for '
                   '--type https-user', err=True)
        ctx.exit(2)

    c = _make_client(ctx)
    resp = _handle_call(c.cert_mint, cert_type, cn,
                        sans=list(sans) if sans else None,
                        validity_days=validity_days)
    creds = resp['credentials']
    if out_prefix:
        od = Path(out_prefix)
        if od.suffix:                       # e.g. --out alice.pem.bad
            od = od.with_suffix('')
        od.parent.mkdir(parents=True, exist_ok=True)
        cert_path = od.with_name(f'{od.name}-cert.pem')
        key_path  = od.with_name(f'{od.name}-key.pem')
        ca_path   = od.with_name(f'{od.name}-ca.pem')
        cert_path.write_text(creds['cert_pem'])
        key_path.write_text(creds['key_pem'])
        ca_path.write_text(creds['ca_cert_pem'])
        os.chmod(key_path, 0o600)
        click.echo(f'wrote {cert_path}, {key_path}, {ca_path}', err=True)
        if cert_type == 'https-user' and p12_password:
            p12_path = od.with_name(f'{od.name}.p12')
            _write_pkcs12(creds['cert_pem'], creds['key_pem'],
                          friendly_name=cn,
                          password=p12_password.encode('utf-8'),
                          out_path=p12_path)
            click.echo(f'wrote {p12_path} (PKCS#12, encrypted)', err=True)
    else:
        click.echo('--- cert ---', err=True)
        click.echo(creds['cert_pem'])
        click.echo('--- key ---', err=True)
        click.echo(creds['key_pem'])
    _output(ctx, resp['cert'])


def _write_pkcs12(cert_pem: str, key_pem: str, *,
                  friendly_name: str, password: bytes,
                  out_path: Path) -> None:
    """Convert PEM cert + key to a password-encrypted PKCS#12 blob.

    Browsers (Chrome, Firefox, Safari) accept .p12 imports natively;
    this saves the operator from running ``openssl pkcs12 -export``
    by hand after every mint.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
    key  = serialization.load_pem_private_key(key_pem.encode('ascii'),
                                              password=None)
    p12 = pkcs12.serialize_key_and_certificates(
        name=friendly_name.encode('utf-8'),
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )
    out_path.write_bytes(p12)
    os.chmod(out_path, 0o600)


@cert_group.command('renew')
@click.option('--cert', 'cert_path', required=True, type=click.Path(),
              help='Path to the cert being renewed. Used as the mTLS '
                   'client cert when calling the CA.')
@click.option('--key', 'key_path', required=True, type=click.Path(),
              help='Path to the cert\'s private key.')
@click.option('--ca-cert', 'ca_cert_path', default=None, type=click.Path(),
              help='CA trust root for verifying mssh-ca\'s TLS server '
                   'cert. Defaults to the value in ~/.mssh-admin/config.')
@click.option('--ca-url', 'ca_url', default=None,
              help='mssh-ca URL. Defaults to the value in '
                   '~/.mssh-admin/config.')
@click.option('--out-cert', 'out_cert_path', required=True, type=click.Path(),
              help='Write the renewed cert here (atomic rename).')
@click.option('--out-key', 'out_key_path', required=True, type=click.Path(),
              help='Write the renewed key here (mode 0600).')
@click.option('--threshold-days', type=int, default=14, show_default=True,
              help='Renew only if the cert expires within this many '
                   'days. Otherwise exit 0 silently (cron-friendly).')
@click.option('--revoke-old', is_flag=True, default=False,
              help='Also revoke the old cert (CRL append). Default: '
                   'old cert remains valid until its not_after.')
@click.option('--on-renew', 'on_renew_cmd', default=None,
              help='Shell command to run after a successful renewal. '
                   'E.g. "systemctl reload nginx".')
@click.pass_context
def cert_renew_cmd(ctx, cert_path, key_path, ca_cert_path, ca_url,
                   out_cert_path, out_key_path, threshold_days,
                   revoke_old, on_renew_cmd):
    """Renew a cert that mssh-ca has previously issued.

    The endpoint is auth-by-cert — the cert at ``--cert`` IS the
    credential. mssh-ca validates the chain at the TLS layer, checks
    the CRL, and re-mints with the same CN/SAN/EKU/validity_days
    when within the renewable window (default 30 days from expiry,
    7-day grace past expiry).

    Designed for daily systemd-timer execution per service. Exits 0
    silently when the cert is more than ``--threshold-days`` from
    expiry, so cron entries can fire daily without churning.

    Example (systemd unit):

      \b
      ExecStart=mssh-admin cert renew \\
          --cert /etc/grafana/tls.crt --key /etc/grafana/tls.key \\
          --out-cert /etc/grafana/tls.crt --out-key /etc/grafana/tls.key \\
          --threshold-days 14 --on-renew "systemctl reload grafana"
    """
    from datetime import datetime, timezone
    from cryptography import x509

    cp = Path(cert_path)
    if not cp.exists():
        click.echo(f'error: --cert not found: {cp}', err=True)
        ctx.exit(2)
    try:
        cert = x509.load_pem_x509_certificate(cp.read_bytes())
    except Exception as e:
        click.echo(f'error: --cert at {cp} not parseable: {e}', err=True)
        ctx.exit(2)

    not_after = cert.not_valid_after_utc
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    days_to_expiry = (not_after
                      - datetime.now(timezone.utc)).total_seconds() / 86400

    if days_to_expiry > threshold_days:
        click.echo(
            f'cert valid until {not_after.isoformat()} '
            f'({int(days_to_expiry)} days); nothing to do '
            f'(threshold {threshold_days})',
            err=True)
        ctx.exit(0)

    # Build a CAClient using the cert/key being renewed as the mTLS
    # client identity, NOT the admin creds.
    conf = ctx.obj.get('_config', {})
    base_url = ca_url or conf.get('ca_url')
    ca_root = ca_cert_path or conf.get('ca_cert')
    if not base_url or not ca_root:
        click.echo('error: --ca-url and --ca-cert required (or set in '
                   '~/.mssh-admin/config)', err=True)
        ctx.exit(2)

    renew_client = CAClient(
        base_url=base_url,
        admin_cert=str(cp),
        admin_key=str(key_path),
        ca_cert=str(ca_root),
    )

    try:
        resp = renew_client.cert_renew(revoke_predecessor=revoke_old)
    except CAClientError as e:
        click.echo(f'renewal failed: HTTP {e.status} — {e.body}', err=True)
        ctx.exit(3)

    if resp.get('status') == 'too_early':
        click.echo(f'cert not yet renewable: {resp.get("detail")}',
                   err=True)
        ctx.exit(0)
    if resp.get('status') != 'ok':
        click.echo(f'unexpected response: {resp}', err=True)
        ctx.exit(4)

    # Atomic write: write to a tmp file, fsync, rename. Same pattern
    # the broker uses for hosts_live.py.
    creds = resp['credentials']
    _atomic_write(out_cert_path, creds['cert_pem'].encode('ascii'),
                   mode=0o644)
    _atomic_write(out_key_path, creds['key_pem'].encode('ascii'),
                   mode=0o600)

    cert_info = resp['cert']
    click.echo(
        f'renewed {cert_info["subject_cn"]} '
        f'(old serial {cert_info["old_serial"]}); '
        f'validity {cert_info["validity_days"]} days',
        err=True)

    if on_renew_cmd:
        click.echo(f'running --on-renew: {on_renew_cmd}', err=True)
        import subprocess
        rc = subprocess.run(on_renew_cmd, shell=True).returncode
        if rc != 0:
            click.echo(f'warning: --on-renew exited {rc}', err=True)
            ctx.exit(5)


def _atomic_write(path, data, *, mode=0o644):
    """Write bytes to ``path`` atomically via rename. Inherits the
    target's directory."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + '.tmp')
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(str(tmp), str(p))
    os.chmod(str(p), mode)


@cert_group.command('revoke')
@click.argument('serials', nargs=-1, required=True)
@click.option('--reason', default='',
              help='Free-text reason recorded in the CRL entry + audit.')
@click.pass_context
def cert_revoke_cmd(ctx, serials, reason):
    """Revoke one or more cert SERIALS (lowercase hex).

    Appends a CRL entry; the fleet picks it up on next authorize
    call. Affects both normal CA-grant entries AND bypass-injected
    entries in each msshd's authz cache. See
    archive/design/notes-bypass-cache.md "CRL Amendment".

    Example:
        mssh-admin cert revoke deadbeef abcd1234 --reason 'key rotation'
    """
    c = _make_client(ctx)
    out = _handle_2fa_call(c, c.cert_revoke, list(serials), reason=reason)
    click.echo(f'revoked seq={out["seq"]} serials={out["serials"]}',
               err=True)
    _output(ctx, out)


@cli.group('crl')
def crl_group():
    """View the CA's CRL (revocation log)."""


@crl_group.command('list')
@click.option('--after', type=int, default=0,
              help='Return entries with seq > AFTER.')
@click.option('--limit', type=int, default=None,
              help='Cap the number of entries returned.')
@click.pass_context
def crl_list_cmd(ctx, after, limit):
    """List CRL entries, optionally filtered by seq."""
    c = _make_client(ctx)
    out = _handle_call(c.crl_list, after, limit)
    _output(ctx, out)


@cli.group('openvpn')
def openvpn_group():
    """Issue OpenVPN client bundles signed by this CA's TLS hierarchy.

    Output is a single ``.ovpn`` file with the client cert + key + CA
    inlined plus the connection metadata. Drop into the user's OpenVPN
    client; revocation goes through ``mssh-admin cert revoke <serial>``
    (OpenVPN server polls the CA's CRL).
    """


@openvpn_group.command('issue')
@click.option('--cn', required=True,
              help='Common Name on the client cert (typically the username).')
@click.option('--server-endpoint', required=True,
              help='"host port" form for the .ovpn remote directive, '
                   'e.g. "vpn.example.com 1194".')
@click.option('--proto', type=click.Choice(['udp', 'tcp']), default='udp',
              show_default=True)
@click.option('--dev', type=click.Choice(['tun', 'tap']), default='tun',
              show_default=True)
@click.option('--validity-days', type=int, default=None,
              help='Cert validity in days (default 90; capped at 825).')
@click.option('--out', 'out_path', default=None, type=click.Path(),
              help='Write the .ovpn bundle to this path. '
                   'Without --out, the .ovpn is printed to stdout.')
@click.pass_context
def openvpn_issue_cmd(ctx, cn, server_endpoint, proto, dev,
                      validity_days, out_path):
    """Issue an OpenVPN client bundle.

    Example:

      \b
      mssh-admin openvpn issue --cn alice \\
                                --server-endpoint "vpn.example.com 1194" \\
                                --validity-days 30 \\
                                --out alice-vpn.ovpn
    """
    c = _make_client(ctx)
    resp = _handle_call(c.openvpn_issue, cn, server_endpoint,
                        proto=proto, dev=dev,
                        validity_days=validity_days)
    creds = resp['credentials']
    meta  = resp['openvpn']
    ovpn  = _format_ovpn_bundle(
        ca_pem=creds['ca_cert_pem'],
        cert_pem=creds['cert_pem'],
        key_pem=creds['key_pem'],
        server_endpoint=meta['server_endpoint'],
        proto=meta['proto'],
        dev=meta['dev'],
    )
    if out_path:
        op = Path(out_path)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(ovpn)
        os.chmod(op, 0o600)
        click.echo(f'wrote {op}', err=True)
    else:
        click.echo(ovpn)
    _output(ctx, meta)


def _format_ovpn_bundle(*, ca_pem: str, cert_pem: str, key_pem: str,
                        server_endpoint: str, proto: str, dev: str) -> str:
    """Assemble a single-file .ovpn config with inline cert/key/ca."""
    return (
        f'# mssh-admin openvpn issue — single-file client config\n'
        f'client\n'
        f'dev {dev}\n'
        f'proto {proto}\n'
        f'remote {server_endpoint}\n'
        f'resolv-retry infinite\n'
        f'nobind\n'
        f'persist-key\n'
        f'persist-tun\n'
        f'remote-cert-tls server\n'
        f'cipher AES-256-GCM\n'
        f'auth SHA256\n'
        f'verb 3\n'
        f'\n'
        f'<ca>\n{ca_pem.strip()}\n</ca>\n'
        f'<cert>\n{cert_pem.strip()}\n</cert>\n'
        f'<key>\n{key_pem.strip()}\n</key>\n'
    )


@cli.group('wireguard')
def wireguard_group():
    """Manage WireGuard servers + peers signed by this CA's catalog.

    The CA owns the server's keypair and tracks IP allocation; peer
    issuance returns a wg-quick config the recipient drops into their
    laptop. Server-side, the operator runs ``wireguard server show``
    periodically to refresh ``/etc/wireguard/<server>.conf`` and
    reload the WireGuard daemon — revocation propagates that way.
    """


@wireguard_group.command('server-init')
@click.option('--name', required=True,
              help='Server (interface) name, e.g. wg0.')
@click.option('--network', required=True,
              help='Address pool in CIDR form, e.g. 10.20.0.0/24. '
                   'First usable IP becomes the server\'s address; '
                   'subsequent peers take the next free addresses.')
@click.option('--endpoint', required=True,
              help='Public endpoint peers connect to, '
                   'e.g. vpn.example.com:51820.')
@click.option('--listen-port', type=int, default=51820, show_default=True)
@click.pass_context
def wireguard_server_init_cmd(ctx, name, network, endpoint, listen_port):
    """Create a new WireGuard server (interface)."""
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_server_init,
                       name, network, endpoint,
                       listen_port=listen_port)
    click.echo(f'created WireGuard server {name!r} '
               f'(pubkey {out["server"]["public_key_b64"][:12]}...)',
               err=True)
    _output(ctx, out['server'])


@wireguard_group.command('server-show')
@click.option('--name', required=True)
@click.option('--out', 'out_path', default=None, type=click.Path(),
              help='Write the wg0.conf-style server config to this path.')
@click.pass_context
def wireguard_server_show_cmd(ctx, name, out_path):
    """Emit the server-side ``/etc/wireguard/<name>.conf``.

    Contains the server's private key + every active peer's PublicKey
    + AllowedIPs. Re-run this after every issue/revoke and reload
    WireGuard on the server (``wg syncconf <name> <(wg-quick strip <name>)``).
    """
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_server_show, name)
    if out_path:
        op = Path(out_path)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(out['server_config'])
        os.chmod(op, 0o600)
        click.echo(f'wrote {op}', err=True)
    else:
        click.echo(out['server_config'])
    _output(ctx, out['server'])


@wireguard_group.command('server-list')
@click.pass_context
def wireguard_server_list_cmd(ctx):
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_server_list)
    _output(ctx, out['servers'])


@wireguard_group.command('server-remove')
@click.option('--name', required=True)
@click.pass_context
def wireguard_server_remove_cmd(ctx, name):
    """Delete the server and ALL its peers. Irreversible."""
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_server_remove, name)
    _output(ctx, out)


@wireguard_group.command('issue')
@click.option('--name', required=True,
              help='Peer name (typically the username).')
@click.option('--server', required=True,
              help='Server (interface) name the peer joins.')
@click.option('--persistent-keepalive', type=int, default=0,
              help='Seconds between WireGuard keepalive packets. '
                   '0 disables. Use 25 for peers behind NAT.')
@click.option('--dns', default=None,
              help='DNS to push into the peer config '
                   '(written as the [Interface] DNS = ... line).')
@click.option('--out', 'out_path', default=None, type=click.Path(),
              help='Write the wg-quick client config to this path.')
@click.pass_context
def wireguard_peer_issue_cmd(ctx, name, server, persistent_keepalive,
                             dns, out_path):
    """Mint a peer keypair, allocate the next free IP, return the
    client wg-quick config.

    The private key in the returned config is generated on the CA
    and returned exactly once — write it somewhere safe before
    delivering to the user.
    """
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_peer_issue,
                       name, server,
                       persistent_keepalive=persistent_keepalive,
                       dns=dns)
    if out_path:
        op = Path(out_path)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(out['client_config'])
        os.chmod(op, 0o600)
        click.echo(f'wrote {op} (mode 0600 — contains private key)', err=True)
    else:
        click.echo(out['client_config'])
    _output(ctx, out['peer'])


@wireguard_group.command('revoke')
@click.option('--name', required=True)
@click.option('--server', required=True)
@click.pass_context
def wireguard_peer_revoke_cmd(ctx, name, server):
    """Revoke a peer. The peer is removed from the catalog
    immediately; for the change to take effect on a running
    WireGuard server, re-run ``wireguard server-show`` and reload."""
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_peer_revoke, name, server)
    _output(ctx, out['revoked'])


@wireguard_group.command('peer-list')
@click.option('--server', default=None,
              help='Filter to peers on this server only.')
@click.pass_context
def wireguard_peer_list_cmd(ctx, server):
    c = _make_client(ctx)
    out = _handle_call(c.wireguard_peer_list, server)
    _output(ctx, out['peers'])


@cli.group('external-tool')
def external_tool_group():
    """Manage external tools that use mssh-ca as their WebAuthn RP.

    See [design/ca-integration.md § Passkey RP service for external
    tools].
    """


@external_tool_group.command('add')
@click.option('--name', required=True,
              help='Operator-visible tool name (also used as the mTLS CN '
                   'prefix for the tool\'s client cert).')
@click.option('--rp-id', required=True,
              help='WebAuthn RP ID. Usually the broker\'s public '
                   'hostname.')
@click.option('--outcome-url-prefix', required=True,
              help='Allowed prefix for the tool\'s outcome callback URLs. '
                   'A compromised tool cert can only deliver outcomes to '
                   'URLs under this prefix.')
@click.option('--out-dir', default=None, type=click.Path(),
              help='Write the tool\'s mTLS cert + key here (mode 600 on '
                   'the key file).')
@click.pass_context
def external_tool_add_cmd(ctx, name, rp_id, outcome_url_prefix, out_dir):
    """Enroll an external tool. Mints an mTLS client cert the tool
    presents when calling /v1/external/passkey/*."""
    c = _make_client(ctx)
    out = _handle_call(c.external_tool_add, name, rp_id, outcome_url_prefix)
    creds = out['credentials']
    if out_dir:
        od = Path(out_dir)
        od.mkdir(parents=True, exist_ok=True)
        (od / f'{name}-cert.pem').write_text(creds['cert_pem'])
        kp = od / f'{name}-key.pem'
        kp.write_text(creds['key_pem'])
        os.chmod(kp, 0o600)
        (od / f'{name}-ca.pem').write_text(creds['ca_cert_pem'])
        click.echo(f'wrote {od}/{name}-cert.pem, {name}-key.pem, '
                   f'{name}-ca.pem', err=True)
    _output(ctx, out['tool'])


@external_tool_group.command('list')
@click.pass_context
def external_tool_list_cmd(ctx):
    c = _make_client(ctx)
    out = _handle_call(c.external_tool_list)
    _output(ctx, out['tools'])


@external_tool_group.command('remove')
@click.option('--name', required=True)
@click.pass_context
def external_tool_remove_cmd(ctx, name):
    """Delete an external tool. The tool's stored user-passkey
    credentials are removed too."""
    c = _make_client(ctx)
    out = _handle_call(c.external_tool_remove, name)
    _output(ctx, out)


if __name__ == '__main__':
    sys.exit(cli())  # pragma: no cover
