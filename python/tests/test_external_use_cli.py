"""§15.19 / §15.20 external-use CLI + REST wiring tests.

Exercises the CLI (`mssh-admin cert external-use`,
`mssh-admin intermediate mint-external --profile`) + client method
+ Flask route as a whole — end-to-end from the operator's command
down to the mint function.

Tests: §15.19, §15.20, §15.22
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mssh.admin import client as admin_client
from mssh.admin import main as admin_main
from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter


# ---- CAClient method: cert_external_use_mint --------------------------


def test_client_cert_external_use_mint_shape_matches_endpoint():
    """Verifies §15.19 — client method exists and accepts the
    documented kw args."""
    assert hasattr(admin_client.CAClient, 'cert_external_use_mint')
    sig = admin_client.CAClient.cert_external_use_mint
    # Signature-shape smoke: keyword-only args match the request body
    # documented in the admin handler.
    import inspect
    params = inspect.signature(sig).parameters
    assert 'cn' in params
    assert 'csr_pem' in params
    assert 'issuer_intermediate' in params
    assert 'validity_days' in params
    assert 'never_expires' in params
    assert 'custom_oids' in params


def test_client_intermediate_mint_external_accepts_new_flags():
    """Verifies §15.20 / §15.22 — client method accepts profile,
    new_root, root_name."""
    import inspect
    sig = admin_client.CAClient.intermediate_mint_external
    params = inspect.signature(sig).parameters
    assert 'profile' in params
    assert 'new_root' in params
    assert 'root_name' in params
    # `profile` defaults to `generic` (preserves v0.4.x behavior).
    assert params['profile'].default == 'generic'
    assert params['new_root'].default is False


# ---- CLI: mssh-admin cert external-use --help -------------------------


def test_cli_cert_external_use_verb_registered():
    """Verifies §15.19 — the `mssh-admin cert external-use` subcommand
    is registered and its help mentions the CSR + issuer flags."""
    runner = CliRunner()
    res = runner.invoke(admin_main.cli, ['cert', 'external-use', '--help'])
    assert res.exit_code == 0, res.output
    assert '--csr' in res.output
    assert '--issuer-intermediate' in res.output
    assert '--never-expires' in res.output
    assert '--custom-oid' in res.output


def test_cli_mint_external_verb_has_profile_flag():
    """Verifies §15.20 — `mssh-admin intermediate mint-external` has
    the new --profile / --new-root / --root flags."""
    runner = CliRunner()
    res = runner.invoke(admin_main.cli,
                         ['intermediate', 'mint-external', '--help'])
    assert res.exit_code == 0, res.output
    assert '--profile' in res.output
    assert 'device-identity' in res.output
    assert '--new-root' in res.output
    assert '--root ' in res.output or '--root\n' in res.output


def test_cli_cert_external_use_rejects_conflicting_flags(tmp_path):
    """Verifies §15.19 — --validity-days and --never-expires are
    mutually exclusive at the CLI layer."""
    csr_path = tmp_path / 'x.csr'
    csr_path.write_text('-----BEGIN CERTIFICATE REQUEST-----\n')
    runner = CliRunner()
    res = runner.invoke(admin_main.cli, [
        'cert', 'external-use',
        '--cn', 'x',
        '--csr', str(csr_path),
        '--issuer-intermediate', 'nope',
        '--validity-days', '100',
        '--never-expires',
        '--out', str(tmp_path / 'out'),
    ])
    assert res.exit_code == 2
    assert 'mutually exclusive' in res.output


def test_cli_cert_external_use_rejects_bad_custom_oid(tmp_path):
    """Verifies §15.21 — CLI --custom-oid without = is rejected."""
    csr_path = tmp_path / 'x.csr'
    csr_path.write_text('-----BEGIN CERTIFICATE REQUEST-----\n')
    runner = CliRunner()
    res = runner.invoke(admin_main.cli, [
        'cert', 'external-use',
        '--cn', 'x',
        '--csr', str(csr_path),
        '--issuer-intermediate', 'nope',
        '--custom-oid', 'no_equals_sign',
        '--out', str(tmp_path / 'out'),
    ])
    assert res.exit_code == 2
    assert 'NAME=VALUE' in res.output


# ---- Flask route: POST /v1/admin/cert/external-use ---------------------


def _make_csr(cn: str) -> bytes:
    """Verifies §15.18 — helper: build a PEM CSR."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


def _client_test_ca(ca_dir):
    """Verifies §15.19 — build a Flask test client wired to a
    bootstrapped CA. Uses the standard `ca_dir` fixture; skips admin
    mTLS by installing a stub admin resolver."""
    import mssh.ca.server as srv
    from flask import g
    app = srv.create_app_from_ca_dir(ca_dir)

    # Stub admin resolver — the real one requires mTLS handshake state.
    from mssh.ca.enrollment import Admin
    fake_admin = Admin(
        name='boot', role='superuser', mtls_subject='CN=boot')

    @app.before_request
    def _stub_admin():
        g.admin = fake_admin
        g.client_origin = ''

    return app.test_client()


def test_rest_route_registered(ca_dir):
    """Verifies §15.19 — POST /v1/admin/cert/external-use is in the
    server's URL map. Builds a Flask app with a minimally-configured
    CAConfig pointing at the bootstrapped ca_dir + asserts the route
    exists and is POST-accessible."""
    from mssh.ca.config import CAConfig
    from mssh.ca.server import create_app

    # Minimum CAConfig for create_app to succeed. Points at the
    # bootstrapped files the ca_dir fixture already produced.
    cfg = CAConfig(
        listen_host='127.0.0.1', listen_port=4443,
        signing_key=str(ca_dir / 'signing-key.pem'),
        signing_cert=str(ca_dir / 'signing-cert.pem'),
        tls_cert=str(ca_dir / 'tls-server-cert.pem'),
        tls_key=str(ca_dir / 'tls-server-key.pem'),
        client_ca_cert=str(ca_dir / 'tls-ca-cert.pem'),
        identity_trust_roots=[str(ca_dir / 'signing-cert.pem')],
        enrollment_path=str(ca_dir / 'enrollment.yaml'),
        audit_path=str(ca_dir / 'audit.jsonl'),
    )
    app = create_app(cfg)
    routes = {(r.rule, tuple(sorted(r.methods or ())))
              for r in app.url_map.iter_rules()}
    matching = [rule for rule, methods in routes
                if rule == '/v1/admin/cert/external-use'
                   and 'POST' in methods]
    assert matching, f'route not registered; routes: {sorted(r for r,_ in routes)}'


# ---- End-to-end: admin handler via CAClient (bypasses HTTP) -----------


def test_e2e_admin_handler_reachable_via_client_body_shape(ca_dir):
    """Verifies §15.19 — end-to-end from client-method body-shape into
    the admin handler. We don't spin the HTTP server; we invoke the
    admin handler directly with the same body a real POST would carry."""
    # Bootstrap a device-identity intermediate + drop key.pem beside cert.pem.
    _mint_intermediate(Path(ca_dir), name='mfg', profile='device-identity')
    csr_pem = _make_csr('device-0001').decode('ascii')

    # Build an AdminContext identical to what server.py would create.
    from mssh.ca.audit import AuditLog
    from mssh.ca.config import CertKindsPolicy, CustomOIDAllowlist
    from mssh.ca.enrollment import Admin, Enrollment
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    ctx = admin_handlers.AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        ca_dir=str(ca_dir),
        cert_kinds=CertKindsPolicy(),
        custom_oids=CustomOIDAllowlist(),
    )
    superuser = Admin(name='boot', role='superuser', mtls_subject='CN=boot')

    # Body shape matches what the CLI/client would send.
    status, body = admin_handlers.external_use_cert_mint(
        ctx, superuser, {
            'cn': 'device-0001',
            'csr': csr_pem,
            'issuer_intermediate': 'mfg',
            'validity_days': 100,
        })
    assert status == 201, body
    assert body['cert']['type'] == 'external-use'
    assert body['cert']['subject_cn'] == 'device-0001'


def _mint_intermediate(ca_dir: Path, *, name: str, profile: str):
    """Helper mirroring test_external_use_cert.py — mint an external
    intermediate and persist its key.pem so external-use leaf mints
    can find it."""
    import json
    root_cert = cert_minter.load_root_cert(ca_dir)
    root_key = cert_minter.load_private_key(ca_dir / 'root-key.pem')
    key, cert = cert_minter.issue_external_intermediate(
        name, root_key=root_key, root_cert=root_cert,
        path_length=0, validity_days=10950, profile=profile)
    target = ca_dir / 'external' / name
    target.mkdir(parents=True, exist_ok=True)
    (target / 'cert.pem').write_bytes(cert_minter.serialize_certificate(cert))
    (target / 'key.pem').write_bytes(cert_minter.serialize_private_key(key))
    (target / 'profile.json').write_text(json.dumps({'profile': profile}))
