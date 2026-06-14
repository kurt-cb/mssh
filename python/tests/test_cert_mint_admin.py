"""Unit tests for §5 cert minting (cert_mint + openvpn_issue handlers).

Exercises the admin-handler layer directly — no HTTP. Reuses the
`ca_dir` fixture from conftest (a populated bootstrap directory).

Tests: §4.3.6, §4.3.11, §14.1.2
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


# ---- §15.23 per-kind validity policy ---------------------------------------
#
# Verifies that ctx.cert_kinds — when set on the AdminContext — drives
# the default + cap used by cert_mint and openvpn_issue. Without a
# cert_kinds policy, the fallback dict at admin.py:_CERT_DEFAULT_VALIDITY
# / _CERT_MAX_VALIDITY applies (v0.4.x behavior, exercised by the
# above tests).

from mssh.ca.config import CertKindsPolicy


@pytest.fixture
def adminctx_with_policy(adminctx):
    """AdminContext that has an operator-configured cert_kinds policy
    overriding defaults + caps for tls-server."""
    adminctx.cert_kinds = CertKindsPolicy(per_kind={
        'tls-server': {'default_validity_days': 7, 'max_validity_days': 14},
        'code-sign':  {'default_validity_days': 30},   # cap unchanged
        'openvpn':    {'max_validity_days': 30},       # default unchanged
    })
    return adminctx


def test_per_kind_default_used_when_validity_days_omitted(
        adminctx_with_policy, superuser):
    """Verifies §15.23 — operator-set default_validity_days drives the
    default when the request body omits validity_days."""
    status, body = admin_handlers.cert_mint(
        adminctx_with_policy, superuser,
        {'type': 'tls-server', 'cn': 'short-lived.example'})
    assert status == 201
    assert body['cert']['validity_days'] == 7


def test_per_kind_cap_rejects_overlong_request(
        adminctx_with_policy, superuser):
    """Verifies §15.23 — per-kind max_validity_days caps operator
    requests; 15 days for tls-server is over the operator's 14-day cap."""
    status, body = admin_handlers.cert_mint(
        adminctx_with_policy, superuser,
        {'type': 'tls-server', 'cn': 'over.example', 'validity_days': 15})
    assert status == 400
    assert '14' in body['detail']


def test_per_kind_cap_accepts_at_cap(adminctx_with_policy, superuser):
    """Verifies §15.23 — request exactly at the cap is accepted."""
    status, body = admin_handlers.cert_mint(
        adminctx_with_policy, superuser,
        {'type': 'tls-server', 'cn': 'at-cap.example', 'validity_days': 14})
    assert status == 201
    assert body['cert']['validity_days'] == 14


def test_per_kind_partial_override_falls_through_to_baseline(
        adminctx_with_policy, superuser):
    """Verifies §15.23 — code-sign override only sets default; cap
    still uses the baseline (1825) so a 365-day request is fine."""
    status, body = admin_handlers.cert_mint(
        adminctx_with_policy, superuser,
        {'type': 'code-sign', 'cn': 'build-x', 'validity_days': 365})
    assert status == 201
    assert body['cert']['validity_days'] == 365


def test_openvpn_per_kind_cap_applies(adminctx_with_policy, superuser):
    """Verifies §15.23 — openvpn_issue uses ctx.cert_kinds cap;
    operator tightened to 30 days, so 31-day request is rejected."""
    status, body = admin_handlers.openvpn_issue(
        adminctx_with_policy, superuser,
        {'cn': 'bob', 'server_endpoint': 'vpn.example.com 1194',
         'validity_days': 31})
    assert status == 400
    assert '30' in body['detail']


def test_no_policy_falls_back_to_v04_behavior(adminctx, superuser):
    """Verifies §15.23 — when ctx.cert_kinds is None, behavior matches
    v0.4.x: default 90 days, cap 825 days for tls-server."""
    assert adminctx.cert_kinds is None
    status, body = admin_handlers.cert_mint(
        adminctx, superuser,
        {'type': 'tls-server', 'cn': 'fallback.example'})
    assert status == 201
    assert body['cert']['validity_days'] == 90   # v0.4.x default
    # Request right at the v0.4.x cap is accepted.
    status, body = admin_handlers.cert_mint(
        adminctx, superuser,
        {'type': 'tls-server', 'cn': 'at-cap-fb.example',
         'validity_days': 825})
    assert status == 201
    # One day over → rejected.
    status, body = admin_handlers.cert_mint(
        adminctx, superuser,
        {'type': 'tls-server', 'cn': 'over-cap-fb.example',
         'validity_days': 826})
    assert status == 400
