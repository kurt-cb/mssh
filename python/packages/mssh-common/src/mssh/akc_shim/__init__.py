"""mssh integration with unmodified OpenSSH (sshd).

This package contains the AuthorizedKeysCommand-based shim that lets stock
OpenSSH (no source patch) consult the mssh CA for every SSH
authentication attempt. See ``openssh_shim.py`` for the executable.

Design: §9.3.4 + §15.6 (see design/mssh_design_v1.md) — OpenSSH AKC entry
point. The stdin/argv/stdout/exit-code shape is the §15.6 frozen contract.
"""
