"""v0.5.4 fullchain-output tests.

Verifies the fix for the systemic bug where `cert_pem` in every
IssuedClientCert response was silently leaf-only (legacy positional
path), causing TLS handshake failures at server-side because the
intermediate wasn't present in the handshake bundle.

Post-fix invariants:
  - IssuedClientCert.cert_pem      = leaf + issuing intermediate (fullchain)
  - IssuedClientCert.leaf_only_pem = leaf on its own
  - admin handlers surface both fields in `credentials`
  - CLI `cert mint --out X` writes:
      X-cert.pem  (fullchain)
      X-leaf.pem  (leaf only)
      X-ca.pem    (intermediate)
      X-key.pem   (private key; omitted with --csr)

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
    """Verifies §14.8 — parse a multi-cert PEM into an ordered list."""
    return x509.load_pem_x509_certificates(pem.encode('ascii'))


# ---- IssuedClientCert dataclass shape -----------------------------------


def test_issued_client_cert_carries_leaf_only_pem_field():
    """Verifies §14.8 — the dataclass exposes both fullchain and
    leaf-only fields."""
    from dataclasses import fields
    field_names = {f.name for f in fields(cert_minter.IssuedClientCert)}
    assert 'cert_pem' in field_names
    assert 'leaf_only_pem' in field_names
    assert 'ca_cert_pem' in field_names
    assert 'key_pem' in field_names


# ---- cert_mint admin handler --------------------------------------------


def test_cert_mint_returns_fullchain_and_leaf_separately(
        adminctx, superuser):
    """Verifies §14.8 — cert_mint response's cert_pem is leaf+chain
    (>= 2 certs) and leaf_only_pem is just the leaf."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'sans': ['DNS:web.example.com'],
    })
    assert status == 201, body
    fullchain = _parse_pem_certs(body['credentials']['cert_pem'])
    leaf_only = _parse_pem_certs(body['credentials']['leaf_only_pem'])
    assert len(fullchain) >= 2, 'cert_pem must include the intermediate'
    assert len(leaf_only) == 1
    # The leaf in the fullchain is the same cert as leaf_only.
    assert fullchain[0].serial_number == leaf_only[0].serial_number


def test_fullchain_verifies_against_trust_anchor(adminctx, superuser, ca_dir):
    """Verifies §14.8 — client trusting only the trust anchor
    (host-mint / auth intermediate as used at the CA today) can
    validate the fullchain end-to-end without needing the intermediate
    supplied separately."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'sans': ['DNS:web.example.com'],
    })
    assert status == 201
    fullchain = _parse_pem_certs(body['credentials']['cert_pem'])
    # Verify: leaf must be signed by the second cert in the chain.
    leaf, intermediate = fullchain[0], fullchain[1]
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.hazmat.primitives.asymmetric.ec import (
        ECDSA, EllipticCurvePublicKey)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey)
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    issuer_key = intermediate.public_key()
    # The verifier signature-check varies by key type — try each.
    try:
        if isinstance(issuer_key, RSAPublicKey):
            issuer_key.verify(
                leaf.signature, leaf.tbs_certificate_bytes,
                _pad.PKCS1v15(), leaf.signature_hash_algorithm)
        elif isinstance(issuer_key, EllipticCurvePublicKey):
            issuer_key.verify(
                leaf.signature, leaf.tbs_certificate_bytes,
                ECDSA(leaf.signature_hash_algorithm))
        elif isinstance(issuer_key, Ed25519PublicKey):
            issuer_key.verify(leaf.signature, leaf.tbs_certificate_bytes)
    except InvalidSignature:
        pytest.fail('leaf signature did not verify against '
                    'intermediate in fullchain')


def test_ca_cert_pem_matches_second_cert_in_fullchain(
        adminctx, superuser):
    """Verifies §14.8 — ca_cert_pem is exactly the intermediate that
    appears as the second cert in the fullchain (invariant that
    downstream tooling like `install_mssh.sh` can rely on)."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server', 'cn': 'web.example.com',
        'sans': ['DNS:web.example.com'],
    })
    assert status == 201
    fullchain = _parse_pem_certs(body['credentials']['cert_pem'])
    ca_cert = _parse_pem_certs(body['credentials']['ca_cert_pem'])
    assert len(ca_cert) == 1
    assert fullchain[1].serial_number == ca_cert[0].serial_number


# ---- other cert-emitting handlers land the same shape -------------------


def test_server_add_returns_leaf_only_field(adminctx, superuser):
    """Verifies §14.8 — server enrollment (mTLS cert path) also
    surfaces leaf_only_pem."""
    status, body = admin_handlers.server_add(adminctx, superuser, {
        'name': 'msshd-01', 'groups': ['prod'],
    })
    assert status == 201
    assert 'leaf_only_pem' in body['credentials']
    fullchain = _parse_pem_certs(body['credentials']['cert_pem'])
    assert len(fullchain) >= 2


def test_admin_add_returns_leaf_only_field(adminctx, superuser):
    """Verifies §14.8 — admin enrollment (mTLS cert path) also
    surfaces leaf_only_pem."""
    status, body = admin_handlers.admin_add(adminctx, superuser, {
        'name': 'alice-admin', 'role': 'superuser',
    })
    assert status == 201
    assert 'leaf_only_pem' in body['credentials']
    fullchain = _parse_pem_certs(body['credentials']['cert_pem'])
    assert len(fullchain) >= 2


def test_openvpn_issue_returns_leaf_only_field(adminctx, superuser):
    """Verifies §14.8 — openvpn cert path also surfaces leaf_only_pem
    (needed for .ovpn assembly + client-side trust)."""
    status, body = admin_handlers.openvpn_issue(adminctx, superuser, {
        'cn': 'bob', 'server_endpoint': 'vpn.example.com 1194',
    })
    assert status == 201
    assert 'leaf_only_pem' in body['credentials']
    fullchain = _parse_pem_certs(body['credentials']['cert_pem'])
    assert len(fullchain) >= 2


# ---- CLI writes the four-file layout ------------------------------------


def test_cli_cert_mint_writes_four_files_ca_generated_key(
        tmp_path, monkeypatch):
    """Verifies §14.2.2 — `cert mint --out X` writes X-cert.pem (chain),
    X-leaf.pem, X-ca.pem, X-key.pem (mode 0600) when the CA generates
    the key."""
    # Stub CAClient so we don't need a live server.
    class _StubClient:
        def cert_mint(self, cert_type, cn, *, sans=None, validity_days=None,
                       csr_pem=None):
            return {
                'status': 'ok',
                'cert': {'type': cert_type, 'subject_cn': cn,
                          'validity_days': validity_days or 90,
                          'csr_based': csr_pem is not None,
                          'sans': sans or []},
                'credentials': {
                    'cert_pem': '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n'
                                '-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n',
                    'leaf_only_pem': '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n',
                    'ca_cert_pem': '-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n',
                    'key_pem': '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n',
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
    leaf_path = tmp_path / 'web-leaf.pem'
    ca_path   = tmp_path / 'web-ca.pem'
    key_path  = tmp_path / 'web-key.pem'
    assert cert_path.exists()
    assert leaf_path.exists()
    assert ca_path.exists()
    assert key_path.exists()
    # Fullchain has both LEAF + INT markers; leaf-only file has just LEAF.
    fc = cert_path.read_text()
    assert 'LEAF' in fc and 'INT' in fc
    assert 'LEAF' in leaf_path.read_text()
    assert 'INT' not in leaf_path.read_text()
    # Key is mode 0600.
    assert key_path.stat().st_mode & 0o777 == 0o600


def test_cli_cert_mint_writes_no_key_file_with_csr(tmp_path, monkeypatch):
    """Verifies §14.2.2 — `cert mint --csr X` writes X-cert.pem +
    X-leaf.pem + X-ca.pem but NOT X-key.pem (private key stays on
    the target host)."""
    class _StubClient:
        def cert_mint(self, cert_type, cn, *, sans=None, validity_days=None,
                       csr_pem=None):
            assert csr_pem is not None  # CLI must forward CSR
            return {
                'status': 'ok',
                'cert': {'type': cert_type, 'subject_cn': cn,
                          'validity_days': validity_days or 90,
                          'csr_based': True, 'sans': sans or []},
                'credentials': {
                    'cert_pem': '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n'
                                '-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n',
                    'leaf_only_pem': '-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n',
                    'ca_cert_pem': '-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n',
                    'key_pem': '',
                },
            }
    monkeypatch.setattr(admin_main, '_make_client',
                         lambda ctx: _StubClient())

    csr_path = tmp_path / 'web.csr'
    csr_path.write_text('-----BEGIN CERTIFICATE REQUEST-----\nx\n'
                         '-----END CERTIFICATE REQUEST-----')
    out_prefix = str(tmp_path / 'web')
    runner = CliRunner()
    res = runner.invoke(admin_main.cli, [
        'cert', 'mint', '--type', 'tls-server',
        '--cn', 'web.example.com',
        '--csr', str(csr_path),
        '--out', out_prefix,
    ])
    assert res.exit_code == 0, res.output

    assert (tmp_path / 'web-cert.pem').exists()
    assert (tmp_path / 'web-leaf.pem').exists()
    assert (tmp_path / 'web-ca.pem').exists()
    assert not (tmp_path / 'web-key.pem').exists()
