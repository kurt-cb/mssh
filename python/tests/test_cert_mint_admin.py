"""Unit tests for §5 cert minting (cert_mint + openvpn_issue handlers).

Exercises the admin-handler layer directly — no HTTP. Reuses the
`ca_dir` fixture from conftest (a populated bootstrap directory).
"""
from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.x509 import oid

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
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
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


@pytest.fixture
def auditor():
    return Admin(name='audit-bob', role='auditor', mtls_subject='CN=audit-bob')


# ---- cert_mint -------------------------------------------------------------

def _eku_oids(cert_pem: str) -> set:
    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
    ext = cert.extensions.get_extension_for_oid(
        oid.ExtensionOID.EXTENDED_KEY_USAGE).value
    return {e.dotted_string for e in ext}


def _san_strings(cert_pem: str) -> set:
    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
    try:
        ext = cert.extensions.get_extension_for_oid(
            oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return set()
    out = set()
    for entry in ext:
        if isinstance(entry, x509.DNSName):
            out.add(f'DNS:{entry.value}')
        elif isinstance(entry, x509.IPAddress):
            out.add(f'IP:{entry.value}')
    return out


def test_mint_tls_server_with_sans(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'grafana.internal.example.com',
        'sans': ['DNS:grafana.internal.example.com', 'IP:10.10.0.42',
                 'localhost'],
        'validity_days': 30,
    })
    assert status == 201, body
    cert_pem = body['credentials']['cert_pem']
    assert _eku_oids(cert_pem) == {oid.ExtendedKeyUsageOID.SERVER_AUTH.dotted_string}
    assert _san_strings(cert_pem) == {
        'DNS:grafana.internal.example.com',
        'IP:10.10.0.42',
        'DNS:localhost',
    }
    assert body['cert']['validity_days'] == 30


def test_mint_https_user(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'https-user', 'cn': 'alice',
    })
    assert status == 201
    cert_pem = body['credentials']['cert_pem']
    assert _eku_oids(cert_pem) == {oid.ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string}
    # https-user defaults to 90 days.
    assert body['cert']['validity_days'] == 90


def test_mint_code_sign(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'code-sign', 'cn': 'Build agent 03',
    })
    assert status == 201
    cert_pem = body['credentials']['cert_pem']
    eku = _eku_oids(cert_pem)
    # code-signing only — no clientAuth/serverAuth
    assert eku == {oid.ExtendedKeyUsageOID.CODE_SIGNING.dotted_string}
    # default 365
    assert body['cert']['validity_days'] == 365


def test_mint_validates_type(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'nope', 'cn': 'x',
    })
    assert status == 400
    assert 'tls-server' in body['detail']


def test_mint_validates_cn(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server', 'cn': '',
    })
    assert status == 400
    assert 'cn' in body['detail']


def test_mint_rejects_sans_on_https_user(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'https-user', 'cn': 'alice',
        'sans': ['DNS:alice.example.com'],
    })
    assert status == 400
    assert 'tls-server' in body['detail']


def test_mint_rejects_bad_san(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server', 'cn': 'x.example.com',
        'sans': ['IP:not-an-ip'],
    })
    assert status == 400


def test_mint_validity_cap(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server', 'cn': 'x.example.com',
        'validity_days': 10_000,
    })
    assert status == 400
    assert 'cap' in body['detail']


def test_mint_validity_zero(adminctx, superuser):
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server', 'cn': 'x.example.com',
        'validity_days': 0,
    })
    assert status == 400


def test_mint_forbidden_for_auditor(adminctx, auditor):
    status, body = admin_handlers.cert_mint(adminctx, auditor, {
        'type': 'tls-server', 'cn': 'x.example.com',
    })
    assert status == 403
    assert body['reason'] == 'forbidden'


# ---- openvpn_issue ---------------------------------------------------------

def test_openvpn_issue_basic(adminctx, superuser):
    status, body = admin_handlers.openvpn_issue(adminctx, superuser, {
        'cn': 'alice',
        'server_endpoint': 'vpn.example.com 1194',
    })
    assert status == 201, body
    cert_pem = body['credentials']['cert_pem']
    assert _eku_oids(cert_pem) == {oid.ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string}
    assert body['openvpn']['proto'] == 'udp'
    assert body['openvpn']['dev'] == 'tun'
    assert body['openvpn']['server_endpoint'] == 'vpn.example.com 1194'


def test_openvpn_issue_tcp_tap(adminctx, superuser):
    status, body = admin_handlers.openvpn_issue(adminctx, superuser, {
        'cn': 'bob', 'server_endpoint': 'vpn.example.com 443',
        'proto': 'tcp', 'dev': 'tap',
    })
    assert status == 201
    assert body['openvpn']['proto'] == 'tcp'
    assert body['openvpn']['dev'] == 'tap'


def test_openvpn_issue_endpoint_shape(adminctx, superuser):
    status, body = admin_handlers.openvpn_issue(adminctx, superuser, {
        'cn': 'alice', 'server_endpoint': 'vpn.example.com',  # missing port
    })
    assert status == 400


def test_openvpn_issue_rejects_bad_proto(adminctx, superuser):
    status, body = admin_handlers.openvpn_issue(adminctx, superuser, {
        'cn': 'alice', 'server_endpoint': 'vpn.example.com 1194',
        'proto': 'sctp',
    })
    assert status == 400


def test_openvpn_issue_forbidden_for_auditor(adminctx, auditor):
    status, body = admin_handlers.openvpn_issue(adminctx, auditor, {
        'cn': 'alice', 'server_endpoint': 'vpn.example.com 1194',
    })
    assert status == 403
