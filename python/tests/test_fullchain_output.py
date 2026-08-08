"""v0.5.5 fullchain-output tests (backward-compat semantics).

`IssuedClientCert.cert_pem` follows v0.5.3 semantics — leaf-only in
the legacy positional path (which is what every admin.py callsite
uses), leaf+chain in the multi-intermediate path. A new
`full_chain_pem` field is ALWAYS the leaf + issuing intermediate.

Operators opt into fullchain output via
`mssh-admin cert mint --fullchain`; without the flag the v0.5.3 file
layout is preserved byte-identical.

Post-fix invariants:
  - IssuedClientCert.cert_pem      = legacy: leaf-only (v0.5.3 compat)
  - IssuedClientCert.full_chain_pem = always leaf + issuing intermediate
  - admin handlers surface both fields in `credentials`
  - CLI `cert mint --out X`            → X-cert.pem = leaf-only, X-ca.pem, X-key.pem
  - CLI `cert mint --out X --fullchain` → X-cert.pem = leaf+intermediate

Tests: §14.8, §14.2.2, §7.3.1
"""
from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography import x509

from mssh.admin import main as admin_main
from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.config import CertKindsPolicy, CustomOIDAllowlist
from mssh.ca.enrollment import Admin, Enrollment


@pytest.fixture
def adminctx(ca_dir):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        ca_dir=str(ca_dir),
        cert_kinds=CertKindsPolicy(),
        custom_oids=CustomOIDAllowlist(),
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


def _parse_pem_certs(pem: str) -> list[x509.Certificate]:
    """Parse a multi-cert PEM into an ordered list."""
    return x509.load_pem_x509_certificates(pem.encode('ascii'))


# ---- IssuedClientCert dataclass shape -----------------------------------


def test_issued_client_cert_exposes_full_chain_pem():
    """Verifies §14.8 — dataclass has both cert_pem (legacy leaf-only)
    and the always-fullchain full_chain_pem field."""
    from dataclasses import fields
    field_names = {f.name for f in fields(cert_minter.IssuedClientCert)}
    assert 'cert_pem' in field_names
    assert 'full_chain_pem' in field_names
    assert 'ca_cert_pem' in field_names
    assert 'key_pem' in field_names


# ---- cert_mint admin handler --------------------------------------------


def test_cert_pem_stays_leaf_only_in_legacy_path(adminctx, superuser):
    """Verifies §14.8 — v0.5.3 backward compat: cert_pem in the
    legacy positional path is leaf-only. Scripts that rely on this
    (concat with ca_cert_pem to build fullchain) keep working."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'sans': ['DNS:web.example.com'],
    })
    assert status == 201, body
    certs = _parse_pem_certs(body['credentials']['cert_pem'])
    assert len(certs) == 1


def test_full_chain_pem_present_and_carries_chain(adminctx, superuser):
    """Verifies §14.8 — full_chain_pem is present in the response
    and always contains leaf + issuing intermediate."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'sans': ['DNS:web.example.com'],
    })
    assert status == 201
    assert 'full_chain_pem' in body['credentials']
    chain = _parse_pem_certs(body['credentials']['full_chain_pem'])
    assert len(chain) >= 2, 'full_chain_pem must include the intermediate'
    # Leaf in chain matches cert_pem's leaf.
    leaf = _parse_pem_certs(body['credentials']['cert_pem'])[0]
    assert chain[0].serial_number == leaf.serial_number


def test_full_chain_pem_matches_cert_plus_ca_cert(adminctx, superuser):
    """Verifies §14.8 — an operator that concats cert_pem + ca_cert_pem
    gets the same fullchain the API produces in full_chain_pem
    (invariant so old scripts + new field are byte-equivalent
    modulo whitespace)."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server', 'cn': 'web.example.com',
        'sans': ['DNS:web.example.com'],
    })
    assert status == 201
    from_api = _parse_pem_certs(body['credentials']['full_chain_pem'])
    concat = _parse_pem_certs(
        body['credentials']['cert_pem'] + body['credentials']['ca_cert_pem'])
    assert [c.serial_number for c in from_api] == \
           [c.serial_number for c in concat]


# ---- other cert-emitting handlers land the same shape -------------------


def test_server_add_exposes_full_chain_pem(adminctx, superuser):
    """Verifies §14.8 — server enrollment surfaces full_chain_pem."""
    status, body = admin_handlers.server_add(adminctx, superuser, {
        'name': 'msshd-01', 'groups': ['prod'],
    })
    assert status == 201
    assert 'full_chain_pem' in body['credentials']
    assert len(_parse_pem_certs(body['credentials']['full_chain_pem'])) >= 2


def test_admin_add_exposes_full_chain_pem(adminctx, superuser):
    """Verifies §14.8 — admin enrollment surfaces full_chain_pem."""
    status, body = admin_handlers.admin_add(adminctx, superuser, {
        'name': 'alice-admin', 'role': 'superuser',
    })
    assert status == 201
    assert 'full_chain_pem' in body['credentials']
    assert len(_parse_pem_certs(body['credentials']['full_chain_pem'])) >= 2


def test_openvpn_issue_exposes_full_chain_pem(adminctx, superuser):
    """Verifies §14.8 — openvpn cert surfaces full_chain_pem."""
    status, body = admin_handlers.openvpn_issue(adminctx, superuser, {
        'cn': 'bob', 'server_endpoint': 'vpn.example.com 1194',
    })
    assert status == 201
    assert 'full_chain_pem' in body['credentials']
    assert len(_parse_pem_certs(body['credentials']['full_chain_pem'])) >= 2


# ---- CLI without --fullchain preserves v0.5.3 layout --------------------


def test_cli_default_writes_leaf_only_v053_layout(tmp_path, monkeypatch):
    """Verifies §14.2.2 — without --fullchain, OUT-cert.pem contains
    only the leaf (v0.5.3 backward compat)."""
    class _StubClient:
        def cert_mint(self, cert_type, cn, *, sans=None, validity_days=None,
                       csr_pem=None):
            return {
                'status': 'ok',
                'cert': {'type': cert_type, 'subject_cn': cn,
                          'validity_days': validity_days or 90,
                          'csr_based': False, 'sans': sans or []},
                'credentials': {
                    'cert_pem':       '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n',
                    'full_chain_pem': '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n'
                                      '-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n',
                    'ca_cert_pem':    '-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n',
                    'key_pem':        '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n',
                },
            }
    monkeypatch.setattr(admin_main, '_make_client',
                         lambda ctx: _StubClient())

    out_prefix = str(tmp_path / 'web')
    runner = CliRunner()
    res = runner.invoke(admin_main.cli, [
        'cert', 'mint', '--type', 'tls-server',
        '--cn', 'web.example.com',
        '--san', 'DNS:web.example.com',
        '--out', out_prefix,
    ])
    assert res.exit_code == 0, res.output
    cert_path = tmp_path / 'web-cert.pem'
    ca_path   = tmp_path / 'web-ca.pem'
    key_path  = tmp_path / 'web-key.pem'
    leaf_path = tmp_path / 'web-leaf.pem'
    assert cert_path.exists() and ca_path.exists() and key_path.exists()
    # v0.5.3 layout — NO OUT-leaf.pem file.
    assert not leaf_path.exists()
    # OUT-cert.pem is leaf-only.
    body = cert_path.read_text()
    assert 'LEAF' in body
    assert 'INT' not in body


def test_cli_fullchain_flag_writes_chain(tmp_path, monkeypatch):
    """Verifies §14.2.2 — with --fullchain, OUT-cert.pem contains
    leaf + intermediate. OUT-ca.pem still contains the intermediate
    on its own (unchanged)."""
    class _StubClient:
        def cert_mint(self, cert_type, cn, *, sans=None, validity_days=None,
                       csr_pem=None):
            return {
                'status': 'ok',
                'cert': {'type': cert_type, 'subject_cn': cn,
                          'validity_days': validity_days or 90,
                          'csr_based': False, 'sans': sans or []},
                'credentials': {
                    'cert_pem':       '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n',
                    'full_chain_pem': '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n'
                                      '-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n',
                    'ca_cert_pem':    '-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n',
                    'key_pem':        '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n',
                },
            }
    monkeypatch.setattr(admin_main, '_make_client',
                         lambda ctx: _StubClient())

    out_prefix = str(tmp_path / 'web')
    runner = CliRunner()
    res = runner.invoke(admin_main.cli, [
        'cert', 'mint', '--type', 'tls-server',
        '--cn', 'web.example.com',
        '--san', 'DNS:web.example.com',
        '--fullchain',
        '--out', out_prefix,
    ])
    assert res.exit_code == 0, res.output
    cert_path = tmp_path / 'web-cert.pem'
    ca_path   = tmp_path / 'web-ca.pem'
    body = cert_path.read_text()
    assert 'LEAF' in body and 'INT' in body
    # OUT-ca.pem still has just the intermediate (unchanged).
    ca_body = ca_path.read_text()
    assert 'INT' in ca_body
    assert 'LEAF' not in ca_body


def test_cli_help_documents_fullchain_flag():
    """Verifies §14.2.2 — --fullchain is registered on `cert mint`
    and the help text explains what changes."""
    runner = CliRunner()
    res = runner.invoke(admin_main.cli, ['cert', 'mint', '--help'])
    assert res.exit_code == 0, res.output
    assert '--fullchain' in res.output
    # Mentions the v0.5.3 backward-compat behavior.
    assert 'leaf-only' in res.output or 'concat' in res.output
