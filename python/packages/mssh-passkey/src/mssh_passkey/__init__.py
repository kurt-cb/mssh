"""mssh-passkey — public-facing WebAuthn ceremony broker.

Standalone module. Owns no keys; relays opaque blobs between
back-end clients (mssh-ca, msshd, future consumers) over mTLS
and the user's phone browser over HTTPS.

See design/mssh-passkey-module.md.
"""
from .app import create_app

__all__ = ['create_app']
