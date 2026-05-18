"""Unit tests for the CA-bypass cert mint path.

  - admin.bypass_cert_mint enforces superuser role
  - input validation (missing user, malformed pubkey, etc.)
  - happy path: returns a PEM cert with the OID_CA_BYPASS critical
    extension marker
  - cert_minter.mint_authorization_cert(ca_bypass=True) sets the
    extension critical-flag

The actual msshd-side injection (mTLS handshake + header parsing +
cache write) is exercised in the LXC integration suite.
"""
from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography import x509

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import Admin, Enrollment


@pytest.fixture
def adminctx(ca_dir):
    """AdminContext with the authorization signing key wired up."""
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    signing_key = cert_minter.load_private_key(ca_dir / 'signing-key.pem')
    signing_cert = cert_minter.load_certificate(ca_dir / 'signing-cert.pem')
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        signing_key=signing_key, signing_cert=signing_cert,
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


@pytest.fixture
def user_admin():
    return Admin(name='useradm', role='user-admin',
                 mtls_subject='CN=useradm')


def _enroll_user(adminctx, superuser, username='alice'):
    admin_handlers.user_add(adminctx, superuser, {'username': username})


def _dummy_ssh_pubkey_blob(test_key) -> bytes:
    """Take a fresh test SSH key and return its wire-format pubkey blob."""
    return test_key.public_blob


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


def test_bypass_cert_mint_forbidden_for_user_admin(adminctx, user_admin,
                                                    test_key):
    _enroll_user(adminctx, _superuser_helper())
    status, body = admin_handlers.bypass_cert_mint(
        adminctx, user_admin, {
            'username': 'alice',
            'pubkey_b64': base64.b64encode(test_key.public_blob)
                          .decode('ascii'),
        })
    assert status == 403
    assert body['reason'] == 'forbidden'


def _superuser_helper():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def test_bypass_cert_mint_missing_username(adminctx, superuser):
    status, body = admin_handlers.bypass_cert_mint(
        adminctx, superuser, {'pubkey_b64': 'aGVsbG8='})
    assert status == 400
    assert 'username' in body['detail']


def test_bypass_cert_mint_user_not_enrolled(adminctx, superuser, test_key):
    status, body = admin_handlers.bypass_cert_mint(
        adminctx, superuser, {
            'username': 'noone',
            'pubkey_b64': base64.b64encode(test_key.public_blob)
                          .decode('ascii'),
        })
    assert status == 404


def test_bypass_cert_mint_missing_pubkey(adminctx, superuser):
    _enroll_user(adminctx, superuser)
    status, body = admin_handlers.bypass_cert_mint(
        adminctx, superuser, {'username': 'alice'})
    assert status == 400
    assert 'pubkey_b64' in body['detail']


def test_bypass_cert_mint_bad_pubkey_b64(adminctx, superuser):
    _enroll_user(adminctx, superuser)
    status, body = admin_handlers.bypass_cert_mint(
        adminctx, superuser, {
            'username': 'alice',
            'pubkey_b64': '!!! not base64 !!!',
        })
    assert status == 400


def test_bypass_cert_mint_validity_days_out_of_range(adminctx, superuser,
                                                      test_key):
    _enroll_user(adminctx, superuser)
    status, body = admin_handlers.bypass_cert_mint(
        adminctx, superuser, {
            'username': 'alice',
            'pubkey_b64': base64.b64encode(test_key.public_blob)
                          .decode('ascii'),
            'validity_days': 0,
        })
    assert status == 400


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_bypass_cert_mint_happy_path(adminctx, superuser, test_key):
    _enroll_user(adminctx, superuser)
    status, body = admin_handlers.bypass_cert_mint(
        adminctx, superuser, {
            'username': 'alice',
            'pubkey_b64': base64.b64encode(test_key.public_blob)
                          .decode('ascii'),
            'validity_days': 30,
        })
    assert status == 201
    assert body['username'] == 'alice'
    assert body['serial']
    assert '-----BEGIN CERTIFICATE-----' in body['cert_pem']
    assert '-----END CERTIFICATE-----' in body['cert_pem']


def test_minted_cert_carries_bypass_marker(adminctx, superuser, test_key):
    """The OID_CA_BYPASS critical extension must be present on the
    minted cert. msshd uses the marker to identify which certs are
    bypass-injectable."""
    _enroll_user(adminctx, superuser)
    _, body = admin_handlers.bypass_cert_mint(
        adminctx, superuser, {
            'username': 'alice',
            'pubkey_b64': base64.b64encode(test_key.public_blob)
                          .decode('ascii'),
            'validity_days': 30,
        })
    cert = x509.load_pem_x509_certificate(body['cert_pem'].encode('ascii'))
    marker = None
    for ext in cert.extensions:
        if ext.oid.dotted_string == '1.3.6.1.4.1.55555.1.8':
            marker = ext
            break
    assert marker is not None, 'OID_CA_BYPASS marker missing'
    assert marker.critical is True, 'OID_CA_BYPASS must be critical'


def test_minted_cert_carries_normal_authz_extensions(adminctx, superuser,
                                                      test_key):
    """A bypass cert is otherwise a normal authz cert; it must carry
    source_bind, server_bind, channel_policy critical extensions so
    that msshd's policy parse (run on cache-hit) gets a populated
    CertPolicy."""
    _enroll_user(adminctx, superuser)
    _, body = admin_handlers.bypass_cert_mint(
        adminctx, superuser, {
            'username': 'alice',
            'pubkey_b64': base64.b64encode(test_key.public_blob)
                          .decode('ascii'),
            'validity_days': 30,
            'source_bind': '10.0.0.0/24',
            'force_command': '/usr/local/bin/emergency',
        })
    cert = x509.load_pem_x509_certificate(body['cert_pem'].encode('ascii'))
    oids = {ext.oid.dotted_string for ext in cert.extensions}
    assert '1.3.6.1.4.1.55555.1.1' in oids  # OID_SOURCE_BIND
    assert '1.3.6.1.4.1.55555.1.2' in oids  # OID_SERVER_BIND
    assert '1.3.6.1.4.1.55555.1.3' in oids  # OID_CHANNEL_POLICY
    assert '1.3.6.1.4.1.55555.1.8' in oids  # OID_CA_BYPASS


# ---------------------------------------------------------------------------
# cert_minter unit-level
# ---------------------------------------------------------------------------


def test_cert_minter_ca_bypass_flag_off_by_default(ca_dir, test_key):
    """A normal mint (ca_bypass=False) does NOT carry the marker.
    Otherwise every authz cert would look bypass-injectable, defeating
    the marker's purpose."""
    import datetime as _dt
    signing_key = cert_minter.load_private_key(ca_dir / 'signing-key.pem')
    signing_cert = cert_minter.load_certificate(ca_dir / 'signing-cert.pem')
    now = _dt.datetime.now(_dt.timezone.utc)
    cert, _ = cert_minter.mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(minutes=10),
        source_bind='10.0.0.0/24', server_bind='*',
        channels=['session'],
    )
    oids = {ext.oid.dotted_string for ext in cert.extensions}
    assert '1.3.6.1.4.1.55555.1.8' not in oids
