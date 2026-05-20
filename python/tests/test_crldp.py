"""CRLDP coverage: leaves carry the extension when ctx.crl_url is set,
and the X.509 CRL emission round-trips through cryptography."""
from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.x509 import oid

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter, crl as crl_module
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import Admin, Enrollment


@pytest.fixture
def adminctx(ca_dir, tmp_path):
    """Adminctx with a CRL store + crl_url set."""
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    crl_store = crl_module.CRLStore(tmp_path / 'crl.jsonl')
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        crl=crl_store,
        crl_url='https://ca.example.com:8443/v1/crl.pem',
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


def _crldp_urls(cert_pem: str) -> list[str]:
    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
    try:
        ext = cert.extensions.get_extension_for_oid(
            oid.ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return []
    out = []
    for dp in ext:
        for name in dp.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                out.append(name.value)
    return out


def test_tls_server_carries_crldp(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server', 'cn': 'x.example.com',
    })
    assert status == 201
    assert _crldp_urls(body['credentials']['cert_pem']) == [
        'https://ca.example.com:8443/v1/crl.pem',
    ]


def test_https_user_carries_crldp(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'https-user', 'cn': 'alice',
    })
    assert status == 201
    assert _crldp_urls(body['credentials']['cert_pem']) == [
        'https://ca.example.com:8443/v1/crl.pem',
    ]


def test_code_sign_skips_crldp(adminctx, superuser):
    """Code-signing certs intentionally don't carry CRLDP (docs note)."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'code-sign', 'cn': 'Build agent',
    })
    assert status == 201
    assert _crldp_urls(body['credentials']['cert_pem']) == []


def test_openvpn_carries_crldp(adminctx, superuser):
    status, body = admin_handlers.openvpn_issue(adminctx, superuser, {
        'cn': 'alice', 'server_endpoint': 'vpn.example.com 1194',
    })
    assert status == 201
    assert _crldp_urls(body['credentials']['cert_pem']) == [
        'https://ca.example.com:8443/v1/crl.pem',
    ]


def test_no_crldp_when_unset(ca_dir, superuser, tmp_path):
    """When ctx.crl_url is None, leaves do NOT carry the extension."""
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    ctx = AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        crl_url=None,
    )
    status, body = admin_handlers.cert_mint(ctx, superuser, {
        'type': 'tls-server', 'cn': 'x.example.com',
    })
    assert status == 201
    assert _crldp_urls(body['credentials']['cert_pem']) == []


def test_x509_crl_round_trip(adminctx):
    """build_x509_crl signs a real CRL containing every revoked serial."""
    adminctx.crl.append(['deadbeef', 'abc123'],
                        revoked_by='boot', reason='key rotation')
    adminctx.crl.append(['1111aaaa'],
                        revoked_by='boot', reason='lost key')
    pem = crl_module.build_x509_crl(
        adminctx.crl,
        signing_key=adminctx.tls_ca_key,
        signing_cert=adminctx.tls_ca_cert,
    )
    crl = x509.load_pem_x509_crl(pem)
    serials = {r.serial_number for r in crl}
    assert int('deadbeef', 16) in serials
    assert int('abc123', 16) in serials
    assert int('1111aaaa', 16) in serials
    # Verify signature against issuer pubkey.
    assert crl.is_signature_valid(adminctx.tls_ca_cert.public_key())


def test_x509_crl_empty_log(adminctx):
    """Empty CRL log → valid CRL with zero entries."""
    pem = crl_module.build_x509_crl(
        adminctx.crl,
        signing_key=adminctx.tls_ca_key,
        signing_cert=adminctx.tls_ca_cert,
    )
    crl = x509.load_pem_x509_crl(pem)
    assert list(crl) == []
    assert crl.is_signature_valid(adminctx.tls_ca_cert.public_key())
