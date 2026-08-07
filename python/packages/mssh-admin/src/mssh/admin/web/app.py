"""Flask application factory.

Threading model: Flask's built-in werkzeug dev server is fine for v1
(single admin in front of localhost). A production WSGI server is
out of scope until per-admin attribution lands (§11.3.3 identity-
propagation open question).

Design: §11 (mssh-admin-web) + §11.3.4 (auth model — operator
identity arrives via the mssh-mediated localhost tunnel, not a
browser session) + §14.3.5 (config schema, R-10 YAML loader).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from flask import Flask, request

from ..client import CAClient
from .views import register_views


@dataclass
class WebConfig:
    """R-10 §14.3.5 — mssh-admin-web YAML config.

    Two file shapes are supported, distinguished by extension + content:

      * **Flat ``key: value``** (legacy / shared with the CLI). Carries
        the CA-client creds: ``ca_url``, ``admin_cert``, ``admin_key``,
        ``ca_cert``. No flask / apache_integration fields — those land
        only in the YAML form.

      * **YAML** (R-10 §14.3.5 canonical). Adds ``flask:`` and
        ``apache_integration:`` blocks. Both blocks are optional;
        when absent, behavior matches the flat-file form
        byte-identical.

    YAML shape::

        ca:
          url:         https://mssh-ca.example.com:4443
          admin_cert:  /etc/mssh-admin-web/admin-cert.pem
          admin_key:   /etc/mssh-admin-web/admin-key.pem
          ca_cert:     /etc/mssh-admin-web/ca-cert.pem

        flask:
          secret_key_file: /etc/mssh-admin-web/secret-key

        apache_integration:
          trusted_client_cn_header: X-Apache-Client-CN
    """
    ca_url: str = ''
    admin_cert: str = ''
    admin_key: str = ''
    ca_cert: str = ''

    flask_secret_key_file: str = ''

    apache_trusted_client_cn_header: str = ''

    @classmethod
    def load(cls, path: str | Path) -> 'WebConfig':
        """Load a config file. Detects YAML vs. flat by content.

        Files whose first non-comment line contains ``:`` followed by a
        dict-shaped block or a list are parsed as YAML; otherwise flat
        ``key: value`` (legacy CLI shape).
        """
        p = Path(path)
        if not p.exists():
            raise RuntimeError(f'config file not found: {path}')
        raw = p.read_text()
        cfg = cls()

        # YAML form: top-level keys are mappings (``ca:`` block) rather
        # than scalar values. The legacy flat form has scalar values
        # exclusively. yaml.safe_load handles both; distinguish by
        # whether any top-level value is itself a dict.
        import yaml as _yaml
        data = _yaml.safe_load(raw) or {}
        if not isinstance(data, dict):
            raise RuntimeError(
                f'config {path} did not parse as a YAML mapping')
        if any(isinstance(v, dict) for v in data.values()):
            # YAML structured form (R-10 §14.3.5).
            ca = data.get('ca') or {}
            cfg.ca_url = str(ca.get('url') or '')
            cfg.admin_cert = str(ca.get('admin_cert') or '')
            cfg.admin_key = str(ca.get('admin_key') or '')
            cfg.ca_cert = str(ca.get('ca_cert') or '')
            flask_sec = data.get('flask') or {}
            cfg.flask_secret_key_file = str(
                flask_sec.get('secret_key_file') or '')
            apache = data.get('apache_integration') or {}
            cfg.apache_trusted_client_cn_header = str(
                apache.get('trusted_client_cn_header') or '')
        else:
            # Flat ``key: value`` legacy form.
            cfg.ca_url = str(data.get('ca_url') or '')
            cfg.admin_cert = str(data.get('admin_cert') or '')
            cfg.admin_key = str(data.get('admin_key') or '')
            cfg.ca_cert = str(data.get('ca_cert') or '')

        required = ('ca_url', 'admin_cert', 'admin_key', 'ca_cert')
        missing = [k for k in required if not getattr(cfg, k)]
        if missing:
            raise RuntimeError(
                f'mssh-admin-web config at {path} missing: '
                f'{", ".join(missing)}. Run mssh-admin init or set '
                f'environment overrides.')
        return cfg


def create_app(client: CAClient, *,
               dev_mode: bool = False,
               web_config: WebConfig | None = None) -> Flask:
    """Build a Flask app wired to ``client``.

    ``dev_mode`` enables Flask's debug reloader and CORS-permissive
    behaviour. Off by default — the portal binds to localhost only
    and should not surface a debug page on a live operator's box.

    ``web_config`` carries optional R-10 §14.3.5 fields:
      * ``flask.secret_key_file`` — if set, the file's bytes become
        Flask's ``SECRET_KEY``. Required only when Flask sessions or
        flashed messages are in use (neither is in v1; this is
        forward-compat for §11.3.3 mutating CRUD).
      * ``apache_integration.trusted_client_cn_header`` — if set,
        route handlers read the operator identity from this request
        header instead of the mssh-mediated tunnel marker. Used when
        apache2 fronts the portal and terminates mTLS itself.
    """
    app = Flask(__name__,
                template_folder='templates',
                static_folder='static')
    app.config['CA_CLIENT'] = client
    app.config['DEV_MODE'] = dev_mode
    app.config['WEB_CONFIG'] = web_config or WebConfig()

    # R-10 §14.3.5 — Flask secret key, if configured.
    if web_config and web_config.flask_secret_key_file:
        key_path = Path(web_config.flask_secret_key_file)
        if key_path.exists():
            app.config['SECRET_KEY'] = key_path.read_bytes()

    # R-10 §14.3.5 — apache_integration. Helper exposed via
    # `flask.current_app.config['CALLER_CN_HEADER']`; route handlers
    # can consult it to attribute the request to an operator-CN.
    app.config['CALLER_CN_HEADER'] = (
        web_config.apache_trusted_client_cn_header if web_config else '')

    register_views(app)
    return app


def caller_cn_from_request() -> str:
    """R-10 §14.3.5 — return the operator identity attributed to the
    current request, honoring ``apache_integration.trusted_client_cn_header``
    when configured. Empty string when no attribution is available
    (the v0.4.x default — mssh-mediated tunnel without per-request CN)."""
    from flask import current_app
    header = current_app.config.get('CALLER_CN_HEADER') or ''
    if not header:
        return ''
    return (request.headers.get(header) or '').strip()


def _ca_client_from_config(config_path: Optional[str] = None
                            ) -> tuple[CAClient, WebConfig]:
    """Build a CAClient + WebConfig from the operator's config file.

    Returns ``(client, web_config)`` so the caller can thread the
    R-10 §14.3.5 fields into ``create_app``.

    Same lookup the CLI uses — keeps the operator's existing creds
    working without re-typing. Supports either the flat legacy form
    or the new YAML form (auto-detected by ``WebConfig.load``).
    """
    import os
    if config_path is None:
        config_path = os.environ.get(
            'MSSH_ADMIN_CONFIG',
            str(Path.home() / '.mssh-admin' / 'config'))

    web_config = WebConfig.load(config_path)
    client = CAClient(
        base_url=web_config.ca_url,
        admin_cert=web_config.admin_cert,
        admin_key=web_config.admin_key,
        ca_cert=web_config.ca_cert,
    )
    return client, web_config
