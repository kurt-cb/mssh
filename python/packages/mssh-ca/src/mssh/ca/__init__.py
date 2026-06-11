"""mssh authorization CA.

Design: §4 (see design/mssh_design_v1.md)

Per-module owning subsystems:
server.py §4.3.13, authorize.py §4.3.1, enrollment.py §4.3.2,
policy.py §4.3.3, cert_minter.py §4.3.4, crl.py §4.3.5,
admin.py §4.3.6, audit.py §4.3.7, passkey.py §4.3.8 + §4.3.9,
passkey_broker.py §3.6, render.py + templates.py §4.3.12,
wireguard.py §4.3.11 / §13.7, config.py §14.3.2.
"""
