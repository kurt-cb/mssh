"""Tests for §25 cert renewal handler.

The renewal endpoint takes the cert being renewed as the mTLS
client cert (passed as the ``presented_cert`` arg in unit-test
land). These tests use real x509 certs minted via the cert_minter
helpers, then call ``admin_handlers.cert_renew`` directly.
"""

from __future__ import annotations

import datetime as _dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import oid

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca import crl as _crl
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import Enrollment


@pytest.fixture
def adminctx(ca_dir, tmp_path):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    crl_store = _crl.CRLStore(tmp_path / 'crl.jsonl')
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        crl=crl_store,
        crl_url='https://ca.example.com/v1/crl.pem',
    )


def _mint_tls_server(adminctx, *, cn='svc.example.com',
                      sans=None, validity_days=30):
    bundle = cert_minter.issue_server_cert(
        cn, adminctx.tls_ca_key, adminctx.tls_ca_cert,
        validity_days=validity_days,
        key_type='ec',
        sans=sans or ['DNS:svc.example.com'],
        crl_url=adminctx.crl_url)
    cert = x509.load_pem_x509_certificate(bundle.cert_pem.split(b'-----END CERTIFICATE-----\n')[0] + b'-----END CERTIFICATE-----\n')
    return cert, bundle


def _mint_client(adminctx, *, cn='alice', validity_days=30):
    bundle = cert_minter.issue_client_cert(
        cn, adminctx.tls_ca_key, adminctx.tls_ca_cert,
        validity_days=validity_days,
        key_type='ec',
        crl_url=adminctx.crl_url)
    cert = x509.load_pem_x509_certificate(bundle.cert_pem)
    return cert, bundle


# ---- happy paths -----------------------------------------------------

def test_renew_tls_server_within_window(adminctx):
    """A TLS server cert within the renewal window renews to a new
    cert with the same CN + SANs."""
    cert, _ = _mint_tls_server(adminctx, cn='svc.example.com',
                                 sans=['DNS:svc.example.com',
                                       'IP:10.0.0.1'])
    # Default window is 30 days; a 30-day cert is immediately
    # renewable (not_after - now == 30 days, on the boundary).
    # Use a 14-day cert so we're solidly inside.
    cert, _ = _mint_tls_server(adminctx, validity_days=14)
    status, body = admin_handlers.cert_renew(adminctx, cert, {})
    assert status == 200, body
    assert body['cert']['subject_cn'] == 'svc.example.com'
    # New cert is a different cert (different serial) but same CN.
    new_cert = x509.load_pem_x509_certificate(
        body['credentials']['cert_pem'].encode('ascii'))
    assert new_cert.serial_number != cert.serial_number
    new_cn = next(a.value for a in new_cert.subject
                   if a.oid == oid.NameOID.COMMON_NAME)
    assert new_cn == 'svc.example.com'


def test_renew_client_cert_within_window(adminctx):
    cert, _ = _mint_client(adminctx, cn='alice-admin', validity_days=14)
    status, body = admin_handlers.cert_renew(adminctx, cert, {})
    assert status == 200
    new_cert = x509.load_pem_x509_certificate(
        body['credentials']['cert_pem'].encode('ascii'))
    # clientAuth EKU preserved.
    eku = new_cert.extensions.get_extension_for_oid(
        oid.ExtensionOID.EXTENDED_KEY_USAGE).value
    assert oid.ExtendedKeyUsageOID.CLIENT_AUTH in list(eku)


def test_renew_preserves_validity_days(adminctx):
    """Renewed cert's validity == original cert's validity."""
    cert, _ = _mint_tls_server(adminctx, validity_days=14)
    status, body = admin_handlers.cert_renew(adminctx, cert, {})
    assert status == 200
    # Original was 14 days; new should be ~14 days too.
    assert body['cert']['validity_days'] == 14


def test_renew_preserves_sans(adminctx):
    cert, _ = _mint_tls_server(adminctx, cn='multi.example.com',
                                 sans=['DNS:multi.example.com',
                                       'DNS:alias.example.com',
                                       'IP:10.0.0.99'],
                                 validity_days=14)
    status, body = admin_handlers.cert_renew(adminctx, cert, {})
    assert status == 200
    new_cert = x509.load_pem_x509_certificate(
        body['credentials']['cert_pem'].encode('ascii'))
    san_ext = new_cert.extensions.get_extension_for_oid(
        oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    san_names = []
    for entry in san_ext:
        if isinstance(entry, x509.DNSName):
            san_names.append(f'DNS:{entry.value}')
        elif isinstance(entry, x509.IPAddress):
            san_names.append(f'IP:{entry.value}')
    assert set(san_names) == {
        'DNS:multi.example.com',
        'DNS:alias.example.com',
        'IP:10.0.0.99',
    }


# ---- rejection paths -------------------------------------------------

def test_renew_no_cert_401(adminctx):
    status, body = admin_handlers.cert_renew(adminctx, None, {})
    assert status == 401
    assert 'no mTLS client cert' in body['detail']


def test_renew_too_early_returns_304(adminctx):
    """A cert with > 30 days until expiry shouldn't renew yet."""
    cert, _ = _mint_tls_server(adminctx, validity_days=90)
    status, body = admin_handlers.cert_renew(adminctx, cert, {})
    assert status == 304
    assert body['status'] == 'too_early'
    assert body['seconds_to_expiry'] > 30 * 86400


def test_renew_revoked_cert_403(adminctx):
    """A revoked cert can't renew."""
    cert, _ = _mint_tls_server(adminctx, validity_days=14)
    # Revoke it via the CRL.
    serial_hex = format(cert.serial_number, 'x')
    adminctx.crl.append([serial_hex], revoked_by='operator',
                         reason='compromised')
    status, body = admin_handlers.cert_renew(adminctx, cert, {})
    assert status == 403
    assert body['reason'] == 'revoked'


def test_renew_past_grace_period_410(adminctx):
    """A cert expired by more than the grace period is refused."""
    # Mint a cert that's already expired by > 7 days. Easiest:
    # mint with a normal validity, then manufacture an x509 with an
    # in-the-past not_after using cert_minter's lower-level path.
    # Simpler shortcut: mint a 1-day cert, then synthetically construct
    # an x509 with not_after = now - 14 days. But we don't have a
    # cert_minter API that takes explicit dates...
    #
    # Workaround: monkey-patch _DEFAULT_GRACE_PERIOD_DAYS to a tiny
    # value so a cert near-expiry triggers past-grace.
    import mssh.ca.admin as ah
    original = ah._DEFAULT_GRACE_PERIOD_DAYS
    ah._DEFAULT_GRACE_PERIOD_DAYS = -10000  # impossibly negative grace
    try:
        # Now any cert with seconds_to_expiry < (-10000 * 86400) → past_grace.
        # A 14-day cert has +14 days to expiry, so the check
        # `seconds_to_expiry < -(grace_days * 86400)`
        #  = 14d < -(-10000d * 86400) = 14d < +10000d*86400 → True
        cert, _ = _mint_tls_server(adminctx, validity_days=14)
        status, body = admin_handlers.cert_renew(adminctx, cert, {})
        assert status == 410
        assert body['reason'] == 'past_grace'
    finally:
        ah._DEFAULT_GRACE_PERIOD_DAYS = original


# ---- revoke_predecessor flag -----------------------------------------

def test_renew_with_revoke_predecessor(adminctx):
    """When revoke_predecessor=True, the old cert's serial lands
    on the CRL."""
    cert, _ = _mint_tls_server(adminctx, validity_days=14)
    serial_hex = format(cert.serial_number, 'x')

    status, body = admin_handlers.cert_renew(adminctx, cert,
                                               {'revoke_predecessor': True})
    assert status == 200
    assert body['cert']['revoked_predecessor'] is True
    # And the serial is in the CRL.
    entries = adminctx.crl.fetch_after(0)
    revoked_serials = set()
    for entry in entries:
        revoked_serials.update(entry.serials)
    assert serial_hex in revoked_serials


def test_renew_without_revoke_predecessor_default(adminctx):
    cert, _ = _mint_tls_server(adminctx, validity_days=14)
    status, body = admin_handlers.cert_renew(adminctx, cert, {})
    assert status == 200
    assert body['cert']['revoked_predecessor'] is False


# ---- audit log ------------------------------------------------------

def test_renew_audits_success(adminctx, tmp_path):
    cert, _ = _mint_tls_server(adminctx, validity_days=14)
    admin_handlers.cert_renew(adminctx, cert, {})
    # Read the audit log.
    log_path = adminctx.audit.path
    lines = log_path.read_text().splitlines()
    matching = [l for l in lines if 'cert.renew.complete' in l]
    assert len(matching) == 1


def test_renew_audits_refusal_on_revoke(adminctx):
    cert, _ = _mint_tls_server(adminctx, validity_days=14)
    serial_hex = format(cert.serial_number, 'x')
    adminctx.crl.append([serial_hex], revoked_by='operator', reason='x')
    admin_handlers.cert_renew(adminctx, cert, {})
    lines = adminctx.audit.path.read_text().splitlines()
    matching = [l for l in lines if 'cert.renew.refused' in l]
    assert len(matching) == 1
