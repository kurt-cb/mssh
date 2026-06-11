"""Wire-protocol versions exposed to all mssh packages.

Design: §3.2 (msshd↔CA wire) + §14.1 (REST envelope `protocol_version`).

Lives in mssh-common so every wheel can ``from mssh._protocol import
PROTOCOL_VERSION`` without needing to import the others.

PROTOCOL_VERSION
    The CA's authorize/admin REST protocol version. Bumped when the
    request / response shapes change in a way clients need to adapt
    to. The CA and msshd both send their supported value on every
    request; mismatch handling is documented in design/api.md.

    1.0  Baseline.
    1.1  authz request carries inner_sshd_kind, inner_sshd_version,
         msshd_version, protocol_version. Response carries
         inner_sshd_config (rendered per-session sshd_config),
         protocol_version. See design/api.md § Protocol-1.1 additions.
"""
PROTOCOL_VERSION = '1.1'
