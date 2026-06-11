"""mssh-admin web — Flask portal that exposes mssh-admin operations
in a browser. Designed to be reached via mssh's local port forward
(see design/future-ideas.md §26) — bind to 127.0.0.1 only; trust the
mssh-mediated tunnel for authentication.

Design: §11 (mssh-admin-web).
"""
from .app import create_app

__all__ = ['create_app']
