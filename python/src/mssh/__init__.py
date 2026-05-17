"""mssh — runtime, CA-mediated SSH authorization. Python implementation.

Subpackages:
  ca/            CA server (Flask + mTLS).
  admin/         mssh-admin CLI (operator-facing).
  shim/          AuthorizedKeysCommand-style authorization shim.
  debug_sshd/    Debug-only AsyncSSH server that calls the shim — kept
                 as a minimal CA-call surface for debugging the CA /
                 shim path in isolation. Not a production server.
  akc_shim/      OpenSSH AuthorizedKeysCommand entry point (unmodified-
                 OpenSSH compatibility path).
  msshd/         Gateway daemon (msshd) — terminates outer mTLS, calls
                 the CA, runs a hermetic inner sshd.
  client         mssh client CLI (single module).

Future siblings: ../go/, ../c/ (placeholder skeletons today).

Operator-facing docs / configs live at the repo root
(INSTALLATION.md, config/, scripts/, systemd/).
"""

__version__ = '0.1.0'

# Wire-protocol version for the CA's authorize / admin endpoints.
# Bumped when the request / response shapes change in a way clients
# need to adapt to. The CA and msshd both send their supported value
# on every request; mismatch handling is documented in design/api.md.
#
# 1.0  Baseline. mssh in production at this version.
# 1.1  Added: authz request carries inner_sshd_kind, inner_sshd_version,
#      msshd_version, protocol_version. Response carries
#      inner_sshd_config (rendered per-session sshd_config), protocol_version.
PROTOCOL_VERSION = '1.1'
