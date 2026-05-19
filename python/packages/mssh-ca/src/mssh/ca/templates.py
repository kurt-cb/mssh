"""Template store + resolver for inner-sshd config templates.

Templates are stored in the same ``enrollment.yaml`` as users / servers /
policies (see [mssh.ca.enrollment.Enrollment](enrollment.py) — three
new dict attributes: ``templates_default``, ``templates_groups``,
``templates_servers``). This module wraps that storage with a
resolver that walks the precedence (per-server > per-server-group >
fleet-default > built-in) and CRUD helpers.

Each template is keyed by ``inner_sshd_kind`` — v1 only knows
``"openssh"``, but the data model accommodates ``"dropbear"`` and
others without schema changes.

A built-in default template ships with mssh
(`BUILTIN_TEMPLATES['openssh']`); operators are not required to set
a fleet-default explicitly. Use the built-in as the editing starting
point if you want to deviate.
"""
from __future__ import annotations

from typing import Any

from .enrollment import Enrollment, EnrollmentError


# ---------------------------------------------------------------------------
# Built-in defaults — shipped templates, no operator config required.
# ---------------------------------------------------------------------------

# Note: the marker grammar is documented in mssh.ca.render.
# - {LOCAL_*}  → substituted by msshd at session-establish time.
# - {FROMCA_*} → substituted by the CA from policy evaluation.
#   :default after the name supplies a fallback when the CA omits the value.
BUILTIN_OPENSSH_TEMPLATE = """\
# mssh hermetic inner sshd_config — built-in default.
#
# Operators may override at: fleet-default (`mssh-admin template edit`),
# per-server-group (`mssh-admin server-group template edit <group>`), or
# per-server (`mssh-admin server template edit <name>`).
#
# Marker grammar:
#   {LOCAL_*}            substituted by msshd at session-establish time
#   {FROMCA_*}           required value from the CA's policy decision
#   {FROMCA_*:fallback}  CA value if present, else literal fallback

# msshd-local values.
Port              {LOCAL_PORT}
HostKey           {LOCAL_HOST_KEY}
TrustedUserCAKeys {LOCAL_USER_CA_PUBKEY}
Banner            {LOCAL_BANNER_FILE}

# Authentication — locked down. Operators should rarely change these.
PermitRootLogin                  no
PasswordAuthentication           no
KbdInteractiveAuthentication     no
ChallengeResponseAuthentication  no
GSSAPIAuthentication             no
HostbasedAuthentication          no
PermitEmptyPasswords             no
UsePAM                           no
AuthenticationMethods            publickey
PubkeyAuthentication             yes
AuthorizedKeysFile               none
AuthorizedKeysCommand            none
AuthorizedPrincipalsFile         none

# Per-session policy from the CA. Operator-side defaults if CA omits.
ForceCommand              {FROMCA_FORCE_COMMAND:none}
AllowTcpForwarding        {FROMCA_ALLOW_TCP_FORWARDING:no}
X11Forwarding             {FROMCA_X11_FORWARDING:no}
AllowAgentForwarding      {FROMCA_ALLOW_AGENT_FORWARDING:no}
PermitUserEnvironment     {FROMCA_PERMIT_USER_ENVIRONMENT:no}

# Crypto floor — modern only (assumes OpenSSH 8.9+).
KexAlgorithms             curve25519-sha256,curve25519-sha256@libssh.org
Ciphers                   chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs                      hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms         ssh-ed25519
# Must include ssh-ed25519-cert-v01@openssh.com — the algorithm name
# for the ephemeral OpenSSH user cert msshd mints per session. Omitting
# it makes the inner sshd reject the cert with "Permission denied" and
# the per-connection flip silently revert.
PubkeyAcceptedAlgorithms  ssh-ed25519,ssh-ed25519-cert-v01@openssh.com

# Forwarding shut off unless the per-session policy reopens it via the
# corresponding FROMCA_ marker above.
PermitTunnel              no
AllowStreamLocalForwarding no
GatewayPorts              no

Subsystem      sftp internal-sftp
LogLevel       VERBOSE
SyslogFacility AUTH
"""


BUILTIN_TEMPLATES: dict[str, str] = {
    'openssh': BUILTIN_OPENSSH_TEMPLATE,
}


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

# Sentinel for the source of an effective template.
SOURCE_BUILTIN = 'builtin'
SOURCE_DEFAULT = 'default'      # CA-stored fleet-default
SOURCE_GROUP = 'group'          # per-server-group override
SOURCE_SERVER = 'server'        # per-server override


def get_effective_template(
    enrollment: Enrollment,
    server_name: str | None,
    kind: str = 'openssh',
) -> tuple[str, str, str | None]:
    """Resolve the effective template for a (server, kind).

    Precedence: per-server > per-server-group > fleet-default > built-in.

    Returns a 3-tuple: (template_text, source, source_detail).

      - ``source`` is one of SOURCE_SERVER / SOURCE_GROUP / SOURCE_DEFAULT /
        SOURCE_BUILTIN.
      - ``source_detail`` is the specific server name (for SOURCE_SERVER) or
        group name (for SOURCE_GROUP); None for default/builtin.

    Raises ``EnrollmentError`` if ``kind`` has no built-in default
    (i.e. unknown kind).
    """
    # Per-server override.
    if server_name is not None:
        per_server = (enrollment.templates_servers.get(server_name) or {}).get(kind)
        if per_server is not None:
            return per_server, SOURCE_SERVER, server_name

        # Per-server-group override. Walk the server's groups in order.
        srv = enrollment.servers.get(server_name)
        if srv is not None:
            for group in srv.groups:
                per_group = (enrollment.templates_groups.get(group) or {}).get(kind)
                if per_group is not None:
                    return per_group, SOURCE_GROUP, group

    # Fleet-default.
    fleet = enrollment.templates_default.get(kind)
    if fleet is not None:
        return fleet, SOURCE_DEFAULT, None

    # Built-in default.
    builtin = BUILTIN_TEMPLATES.get(kind)
    if builtin is None:
        raise EnrollmentError(f'no built-in template for inner_sshd_kind: {kind!r}')
    return builtin, SOURCE_BUILTIN, None


# ---------------------------------------------------------------------------
# CRUD helpers
# ---------------------------------------------------------------------------

def set_default_template(
    enrollment: Enrollment, kind: str, content: str,
) -> None:
    """Set the fleet-default template for a given inner_sshd_kind."""
    _require_known_kind(kind)
    with enrollment._lock:                              # noqa: SLF001
        enrollment.templates_default[kind] = content
        enrollment.save()


def unset_default_template(enrollment: Enrollment, kind: str) -> None:
    """Remove the fleet-default override (revert to built-in)."""
    with enrollment._lock:                              # noqa: SLF001
        enrollment.templates_default.pop(kind, None)
        enrollment.save()


def set_group_template(
    enrollment: Enrollment, group: str, kind: str, content: str,
) -> None:
    """Set a per-server-group template override."""
    _require_known_kind(kind)
    with enrollment._lock:                              # noqa: SLF001
        enrollment.templates_groups.setdefault(group, {})[kind] = content
        enrollment.save()


def unset_group_template(
    enrollment: Enrollment, group: str, kind: str,
) -> None:
    with enrollment._lock:                              # noqa: SLF001
        bk = enrollment.templates_groups.get(group)
        if bk is not None:
            bk.pop(kind, None)
            if not bk:
                enrollment.templates_groups.pop(group, None)
        enrollment.save()


def set_server_template(
    enrollment: Enrollment, server: str, kind: str, content: str,
) -> None:
    """Set a per-server template override.

    Raises ``EnrollmentError`` if ``server`` is not enrolled — operators
    shouldn't accumulate templates for servers that don't exist.
    """
    _require_known_kind(kind)
    with enrollment._lock:                              # noqa: SLF001
        if server not in enrollment.servers:
            raise EnrollmentError(f'server not enrolled: {server}')
        enrollment.templates_servers.setdefault(server, {})[kind] = content
        enrollment.save()


def unset_server_template(
    enrollment: Enrollment, server: str, kind: str,
) -> None:
    with enrollment._lock:                              # noqa: SLF001
        bk = enrollment.templates_servers.get(server)
        if bk is not None:
            bk.pop(kind, None)
            if not bk:
                enrollment.templates_servers.pop(server, None)
        enrollment.save()


def list_templates(enrollment: Enrollment) -> dict[str, Any]:
    """Return a structured view of all stored templates.

    Shape::

        {
          'builtin': {'openssh': '...', ...},
          'default': {<kind>: <content>, ...},
          'groups':  {<group>: {<kind>: <content>, ...}, ...},
          'servers': {<server>: {<kind>: <content>, ...}, ...},
        }

    Useful for ``mssh-admin template diff`` / inspection.
    """
    with enrollment._lock:                              # noqa: SLF001
        return {
            'builtin': dict(BUILTIN_TEMPLATES),
            'default': dict(enrollment.templates_default),
            'groups': {
                g: dict(byk) for g, byk in enrollment.templates_groups.items()
            },
            'servers': {
                s: dict(byk) for s, byk in enrollment.templates_servers.items()
            },
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_known_kind(kind: str) -> None:
    """v1: only ``openssh`` is supported. Future versions will add dropbear,
    etc."""
    if kind not in BUILTIN_TEMPLATES:
        raise EnrollmentError(
            f'unknown inner_sshd_kind: {kind!r} (known: '
            f'{sorted(BUILTIN_TEMPLATES.keys())})'
        )
