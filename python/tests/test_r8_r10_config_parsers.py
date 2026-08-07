"""R-8 supplement + R-10 §14.3.5/§14.3.6 config-parser tests.

R-8 supplement: parse new ca-config.yaml sections (mcp, audit.rotation,
audit.integrity, ratelimits, templates.builtin_dir).

R-10 §14.3.5: mssh-admin-web YAML config loader (flask.secret_key_file,
apache_integration.trusted_client_cn_header).

R-10 §14.3.6: MCP capability allow-list moves from a hard-coded
frozenset in admin.py to an operator-tunable knob in
ca-config.yaml::mcp.capability_allow_list, with the v0.4.0 set as
the fallback when the operator's config has no `mcp:` block.

Tests: §12.4.3, §14.3.2, §14.3.5, §14.3.6
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mssh.ca import admin as admin_handlers
from mssh.ca.config import (
    AuditIntegrityPolicy,
    AuditRotationPolicy,
    CAConfig,
    DEFAULT_MCP_ALLOWED_ACTIONS,
    MCPPolicy,
    RateLimitsPolicy,
    TemplatesPolicy,
)
from mssh.ca.enrollment import Admin


# ---- R-8 supplement: ca-config.yaml new-section parsers ------------------


def _write_ca_yaml(tmp_path, extra: dict) -> str:
    """Verifies §14.3.2 — helper: write a minimal R-9-valid ca-config.yaml
    with the operator-supplied sections layered on top."""
    sk = tmp_path / 'signing-key.pem'; sk.write_text('-key-')
    sc = tmp_path / 'signing-cert.pem'; sc.write_text('-cert-')
    tc = tmp_path / 'tls-cert.pem'; tc.write_text('-cert-')
    tk = tmp_path / 'tls-key.pem'; tk.write_text('-key-')
    cca = tmp_path / 'client-ca-cert.pem'; cca.write_text('-cert-')
    base = {
        'listen': '127.0.0.1:4443',
        'signing_key': str(sk),
        'signing_cert': str(sc),
        'tls_cert': str(tc),
        'tls_key': str(tk),
        'client_ca_cert': str(cca),
        'identity_trust_roots': [str(sc)],
    }
    base.update(extra)
    p = tmp_path / 'ca-config.yaml'
    p.write_text(yaml.safe_dump(base))
    return str(p)


def test_default_mcp_policy_when_no_section(tmp_path):
    """Verifies §14.3.6 / R-10 — v0.4.x configs that lack `mcp:` get
    an empty MCPPolicy(); effective allow-list = built-in default."""
    cfg = CAConfig.load(_write_ca_yaml(tmp_path, {}))
    assert isinstance(cfg.mcp, MCPPolicy)
    assert cfg.mcp.enabled is False
    assert cfg.mcp.capability_allow_list is None
    assert cfg.mcp.effective_allow_list() == DEFAULT_MCP_ALLOWED_ACTIONS


def test_mcp_policy_round_trips_operator_overrides(tmp_path):
    """Verifies §14.3.6 / R-10 — operator-set capability_allow_list
    replaces (not augments) the default, and `enabled` is parsed."""
    cfg = CAConfig.load(_write_ca_yaml(tmp_path, {
        'mcp': {
            'enabled': True,
            'capability_allow_list': ['server.list', 'audit.read'],
        },
    }))
    assert cfg.mcp.enabled is True
    assert cfg.mcp.capability_allow_list == frozenset(
        {'server.list', 'audit.read'})
    # Operator's set is the effective set (NOT a union with the default).
    assert cfg.mcp.effective_allow_list() == frozenset(
        {'server.list', 'audit.read'})


def test_mcp_policy_empty_list_is_strict_subset(tmp_path):
    """Verifies §14.3.6 — operator can set an empty allow-list to
    effectively disable MCP (CA refuses every mcp-origin call)."""
    cfg = CAConfig.load(_write_ca_yaml(tmp_path, {
        'mcp': {'enabled': True, 'capability_allow_list': []},
    }))
    assert cfg.mcp.effective_allow_list() == frozenset()


def test_audit_rotation_defaults(tmp_path):
    """Verifies §14.3.2 / R-8 supplement — missing audit.rotation block
    yields a zero-cap policy (rotation enforcement disabled)."""
    cfg = CAConfig.load(_write_ca_yaml(tmp_path, {}))
    assert isinstance(cfg.audit_rotation, AuditRotationPolicy)
    assert cfg.audit_rotation.max_bytes == 0
    assert cfg.audit_rotation.keep_files == 0


def test_audit_rotation_parsed(tmp_path):
    """Verifies §14.3.2 / R-8 supplement — operator-set rotation knobs
    land on the dataclass."""
    cfg = CAConfig.load(_write_ca_yaml(tmp_path, {
        'audit': {
            'rotation': {'max_bytes': 100_000_000, 'keep_files': 30},
        },
    }))
    assert cfg.audit_rotation.max_bytes == 100_000_000
    assert cfg.audit_rotation.keep_files == 30


def test_audit_integrity_parsed(tmp_path):
    """Verifies §14.3.2 / R-8 supplement — audit.integrity.signed_checkpoints
    + checkpoint_interval_seconds populate the dataclass."""
    cfg = CAConfig.load(_write_ca_yaml(tmp_path, {
        'audit': {
            'integrity': {'signed_checkpoints': True,
                          'checkpoint_interval_seconds': 3600},
        },
    }))
    assert isinstance(cfg.audit_integrity, AuditIntegrityPolicy)
    assert cfg.audit_integrity.signed_checkpoints is True
    assert cfg.audit_integrity.checkpoint_interval_seconds == 3600


def test_ratelimits_parsed(tmp_path):
    """Verifies §14.3.2 / R-8 supplement — per-endpoint rate-limit
    entries land on RateLimitsPolicy.per_endpoint."""
    cfg = CAConfig.load(_write_ca_yaml(tmp_path, {
        'ratelimits': {
            'authorize': {'calls_per_minute': 600},
            'intermediate.rotate': {'calls_per_minute': 5},
        },
    }))
    assert isinstance(cfg.ratelimits, RateLimitsPolicy)
    assert cfg.ratelimits.per_endpoint == {
        'authorize': {'calls_per_minute': 600},
        'intermediate.rotate': {'calls_per_minute': 5},
    }


def test_templates_builtin_dir_parsed(tmp_path):
    """Verifies §14.3.2 / R-8 supplement — templates.builtin_dir
    overrides the package default."""
    cfg = CAConfig.load(_write_ca_yaml(tmp_path, {
        'templates': {'builtin_dir': '/etc/mssh-ca/templates'},
    }))
    assert isinstance(cfg.templates, TemplatesPolicy)
    assert cfg.templates.builtin_dir == '/etc/mssh-ca/templates'


def test_audit_section_without_subkeys_safe(tmp_path):
    """Verifies §14.3.2 — `audit:` section that ONLY carries the
    existing `path` field still parses (no rotation/integrity present)."""
    cfg = CAConfig.load(_write_ca_yaml(tmp_path, {
        'audit': {'type': 'file', 'path': str(tmp_path / 'audit.jsonl')},
    }))
    assert cfg.audit_rotation.max_bytes == 0
    assert cfg.audit_integrity.signed_checkpoints is False


# ---- R-10 §14.3.6 MCP allow-list runtime override ----------------------


def test_set_mcp_allow_list_overrides_module_global():
    """Verifies §14.3.6 / R-10 — set_mcp_allow_list installs the
    operator's frozenset; passing None restores the default."""
    # Snapshot.
    original = admin_handlers.MCP_ALLOWED_ACTIONS
    try:
        admin_handlers.set_mcp_allow_list(frozenset({'server.list'}))
        assert admin_handlers.MCP_ALLOWED_ACTIONS == frozenset({'server.list'})
        admin_handlers.set_mcp_allow_list(None)
        assert admin_handlers.MCP_ALLOWED_ACTIONS == DEFAULT_MCP_ALLOWED_ACTIONS
    finally:
        admin_handlers.MCP_ALLOWED_ACTIONS = original


def test_check_uses_module_allow_list():
    """Verifies §14.3.6 / R-10 — _check() consults the module-level
    MCP_ALLOWED_ACTIONS so set_mcp_allow_list() takes effect even for
    in-flight admin handlers."""
    superuser = Admin(name='boot', role='superuser', mtls_subject='CN=boot')
    original = admin_handlers.MCP_ALLOWED_ACTIONS
    try:
        # Default: server.list is allowed for origin=mcp.
        admin_handlers.set_mcp_allow_list(None)
        assert admin_handlers._check(
            'server.list', superuser, origin='mcp') is None
        # Operator tightens the list to drop server.list — should now reject.
        admin_handlers.set_mcp_allow_list(frozenset({'audit.read'}))
        status, body = admin_handlers._check(
            'server.list', superuser, origin='mcp')
        assert status == 403
        assert body['reason'] == 'mcp_capability_denied'
        # And operator's audit.read is now permitted via origin=mcp.
        assert admin_handlers._check(
            'audit.read', superuser, origin='mcp') is None
    finally:
        admin_handlers.set_mcp_allow_list(None)
        admin_handlers.MCP_ALLOWED_ACTIONS = original


# ---- R-10 §14.3.5 admin-web YAML config loader -------------------------


def _write_admin_web_yaml(tmp_path, body: dict) -> Path:
    p = tmp_path / 'admin-web.yaml'
    p.write_text(yaml.safe_dump(body))
    return p


def test_admin_web_loads_yaml_form(tmp_path):
    """Verifies §14.3.5 / R-10 — the new YAML form with `ca:` +
    `flask:` + `apache_integration:` blocks loads correctly."""
    from mssh.admin.web.app import WebConfig
    secret_file = tmp_path / 'flask-secret'
    secret_file.write_bytes(b'super-secret-key-bytes')
    p = _write_admin_web_yaml(tmp_path, {
        'ca': {
            'url': 'https://mssh-ca.example.com:4443',
            'admin_cert': str(tmp_path / 'ac.pem'),
            'admin_key': str(tmp_path / 'ak.pem'),
            'ca_cert': str(tmp_path / 'cc.pem'),
        },
        'flask': {'secret_key_file': str(secret_file)},
        'apache_integration': {
            'trusted_client_cn_header': 'X-Apache-Client-CN',
        },
    })
    cfg = WebConfig.load(p)
    assert cfg.ca_url == 'https://mssh-ca.example.com:4443'
    assert cfg.flask_secret_key_file == str(secret_file)
    assert cfg.apache_trusted_client_cn_header == 'X-Apache-Client-CN'


def test_admin_web_loads_flat_legacy_form(tmp_path):
    """Verifies §14.3.5 / R-10 — flat ``key: value`` form (shared with
    the CLI) still parses; flask + apache fields default to empty."""
    from mssh.admin.web.app import WebConfig
    p = tmp_path / 'admin-web-flat'
    p.write_text(
        'ca_url: https://mssh-ca.example.com:4443\n'
        f'admin_cert: {tmp_path / "ac.pem"}\n'
        f'admin_key: {tmp_path / "ak.pem"}\n'
        f'ca_cert: {tmp_path / "cc.pem"}\n'
    )
    cfg = WebConfig.load(p)
    assert cfg.ca_url == 'https://mssh-ca.example.com:4443'
    assert cfg.flask_secret_key_file == ''
    assert cfg.apache_trusted_client_cn_header == ''


def test_admin_web_missing_required_field_raises(tmp_path):
    """Verifies §14.3.5 / R-10 + §13.9.7 default-deny — config missing
    any of {ca_url, admin_cert, admin_key, ca_cert} raises."""
    from mssh.admin.web.app import WebConfig
    p = _write_admin_web_yaml(tmp_path, {
        'ca': {'url': 'https://x', 'admin_cert': '/a'},
    })
    with pytest.raises(RuntimeError) as exc:
        WebConfig.load(p)
    assert 'missing' in str(exc.value)
    assert 'admin_key' in str(exc.value)
    assert 'ca_cert' in str(exc.value)


def test_admin_web_secret_key_loaded_into_flask(tmp_path):
    """Verifies §14.3.5 / R-10 — when secret_key_file is present, its
    bytes become the Flask app's SECRET_KEY."""
    from mssh.admin.web.app import WebConfig, create_app
    secret_file = tmp_path / 'flask-secret'
    secret_file.write_bytes(b'top-secret-bytes')
    cfg = WebConfig(
        ca_url='x', admin_cert='x', admin_key='x', ca_cert='x',
        flask_secret_key_file=str(secret_file),
    )
    # Stub CAClient so create_app doesn't try a real connection.
    class _StubClient:
        pass
    app = create_app(_StubClient(), web_config=cfg)
    assert app.config['SECRET_KEY'] == b'top-secret-bytes'


def test_admin_web_apache_header_threaded_to_flask(tmp_path):
    """Verifies §14.3.5 / R-10 — apache_integration.trusted_client_cn_header
    surfaces as app.config['CALLER_CN_HEADER'] and caller_cn_from_request()
    reads it."""
    from mssh.admin.web.app import (
        WebConfig, caller_cn_from_request, create_app)
    cfg = WebConfig(
        ca_url='x', admin_cert='x', admin_key='x', ca_cert='x',
        apache_trusted_client_cn_header='X-My-Apache-Header',
    )
    class _StubClient:
        pass
    app = create_app(_StubClient(), web_config=cfg)
    assert app.config['CALLER_CN_HEADER'] == 'X-My-Apache-Header'
    # Helper reads from the configured header inside a request context.
    with app.test_request_context(
            '/', headers={'X-My-Apache-Header': 'alice'}):
        assert caller_cn_from_request() == 'alice'
    # And ignores the header when not configured.
    cfg2 = WebConfig(ca_url='x', admin_cert='x', admin_key='x', ca_cert='x')
    app2 = create_app(_StubClient(), web_config=cfg2)
    with app2.test_request_context(
            '/', headers={'X-My-Apache-Header': 'alice'}):
        assert caller_cn_from_request() == ''
