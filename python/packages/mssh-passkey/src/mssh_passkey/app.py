"""Flask app factory.

Two route groups:

  /broker/...   — mTLS-authenticated, called by back-end clients
                  (mssh-ca, etc.). In production behind Apache2
                  which validates the client cert and sets
                  X-Client-CN; in dev mode the Flask in-process
                  TLS listener validates and the same header is
                  populated by our own request-handler.

  /register/<id>, /approve/<id>, /  — public HTTPS, called by
                  end-user phone browsers. No auth — the
                  unguessable ceremony_id is the auth.

Design: §8 mssh-passkey broker; §8.3.6 dual-listener (apache vs.
dev front_end) — see design/mssh_design_v1.md.
"""

from __future__ import annotations

from flask import Flask

from .config import Config
from .storage import CeremonyStore
from .views_broker import bp_broker
from .views_public import bp_public


def create_app(config: Config) -> Flask:
    """Build the Flask app, register both blueprints."""
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')
    app.config['PASSKEY_CONFIG'] = config
    app.config['CEREMONY_STORE'] = CeremonyStore(config.database_path)

    app.register_blueprint(bp_broker, url_prefix='/broker')
    app.register_blueprint(bp_public)
    return app
