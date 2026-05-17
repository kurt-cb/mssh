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
