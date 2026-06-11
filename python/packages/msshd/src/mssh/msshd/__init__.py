"""msshd — server-side gateway daemon. Python implementation.

See:
- design/architecture.md — components, modes, hermetic inner sshd
- design/api.md — REST + admin API contract

Modes (selected via msshd.yaml):
  fallback — pure TCP proxy to operator's existing sshd; no CA call.
  gated    — mTLS + CA approval, forward to operator's sshd. Deferred.
  enforce  — mTLS + CA call + ephemeral OpenSSH cert + hermetic inner sshd.

Design: §5.3 (see design/mssh_design_v1.md) — msshd subsystem; the
per-file mapping lives in the modules themselves.
"""
