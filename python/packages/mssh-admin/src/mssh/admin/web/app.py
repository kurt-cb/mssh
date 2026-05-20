"""Flask application factory.

Threading model: Flask's built-in werkzeug dev server is fine for v1
(single admin in front of localhost). A production WSGI server is
out of scope until per-admin attribution lands (§26 identity-
propagation open question).
"""

from __future__ import annotations

from typing import Optional

from flask import Flask

from ..client import CAClient
from .views import register_views


def create_app(client: CAClient, *, dev_mode: bool = False) -> Flask:
    """Build a Flask app wired to ``client``.

    ``dev_mode`` enables Flask's debug reloader and CORS-permissive
    behaviour. Off by default — the portal binds to localhost only
    and should not surface a debug page on a live operator's box.
    """
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')
    app.config['CA_CLIENT'] = client
    app.config['DEV_MODE'] = dev_mode
    register_views(app)
    return app


def _ca_client_from_config(config_path: Optional[str] = None) -> CAClient:
    """Build a CAClient from ~/.mssh-admin/config (or override path).

    Same lookup the CLI uses — keeps the operator's existing creds
    working without re-typing.
    """
    import os
    from pathlib import Path

    if config_path is None:
        config_path = os.environ.get(
            'MSSH_ADMIN_CONFIG',
            str(Path.home() / '.mssh-admin' / 'config'))

    cfg: dict[str, str] = {}
    p = Path(config_path)
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.split('#', 1)[0].strip()
            if not line or ':' not in line:
                continue
            k, _, v = line.partition(':')
            cfg[k.strip()] = v.strip()

    required = ('ca_url', 'admin_cert', 'admin_key', 'ca_cert')
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        raise RuntimeError(
            f'mssh-admin config at {config_path} missing: {", ".join(missing)}. '
            f'Run mssh-admin init or set environment overrides.')

    return CAClient(
        base_url=cfg['ca_url'],
        admin_cert=cfg['admin_cert'],
        admin_key=cfg['admin_key'],
        ca_cert=cfg['ca_cert'],
    )
