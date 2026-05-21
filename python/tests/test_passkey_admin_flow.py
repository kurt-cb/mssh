"""Tests for the admin-2FA passkey handlers in mssh-ca.

Stubs the broker client (no real HTTP) and uses the `webauthn`
library's stable testing primitives where applicable.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import (Admin, Enrollment, EnrollmentError,
                                  PasskeyCredential, Policy)


@pytest.fixture
def adminctx(ca_dir, tmp_path):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')

    # Stub broker.
    fake_broker = MagicMock()
    fake_broker.create_ceremony.return_value = type('C', (), {
        'ceremony_id': 'ceremony-xyz',
        'url': 'https://passkey.example.com/register/ceremony-xyz',
        'expires_at': '2099-01-01T00:00:00Z',
    })()

    from mssh.ca import passkey as _pk
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        passkey_broker=fake_broker,
        passkey_rp_id='passkey.example.com',
        passkey_rp_name='mssh-ca test',
        passkey_expected_origin='https://passkey.example.com',
        passkey_callback_url='https://mssh-ca.internal:8443/v1/admin/passkey/callback',
        passkey_aaguid_allowlist=_pk.AAGUIDAllowlist(allowed=set(),
                                                      require_allowlist=False),
        passkey_pending_registrations={},
        passkey_pending_authentications={},
        passkey_2fa_cache={},
    )


@pytest.fixture
def superuser(adminctx):
    """An enrolled superuser that's actually in the enrollment DB."""
    adminctx.enrollment.add_admin('boot', 'superuser', 'CN=boot')
    return adminctx.enrollment.admins['boot']


@pytest.fixture
def target_admin(adminctx):
    adminctx.enrollment.add_admin('alice-admin', 'superuser', 'CN=alice-admin')
    return 'alice-admin'


# ---- 503 when broker not configured -----------------------------------

def test_passkey_503_when_unconfigured(ca_dir, tmp_path):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    ctx = AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
    )  # broker left at None
    enroll.add_admin('boot', 'superuser', 'CN=boot')
    su = enroll.admins['boot']
    status, body = admin_handlers.passkey_admin_enroll(
        ctx, su, {'admin_name': 'boot'})
    assert status == 503
    assert 'not configured' in body['detail']


# ---- enroll-begin ------------------------------------------------------

def test_enroll_begin_calls_broker_and_returns_url(adminctx, superuser,
                                                     target_admin):
    status, body = admin_handlers.passkey_admin_enroll(
        adminctx, superuser, {'admin_name': target_admin})
    assert status == 201
    assert body['ceremony_id'] == 'ceremony-xyz'
    assert body['url'].endswith('ceremony-xyz')
    # Pending state cached for callback verification.
    assert 'ceremony-xyz' in adminctx.passkey_pending_registrations
    pending = adminctx.passkey_pending_registrations['ceremony-xyz']
    assert pending['admin_name'] == target_admin
    assert isinstance(pending['challenge'], bytes)
    # Broker was called with type=register.
    args = adminctx.passkey_broker.create_ceremony.call_args
    assert args.kwargs['ceremony_type'] == 'register'


def test_enroll_begin_unknown_admin_404(adminctx, superuser):
    status, body = admin_handlers.passkey_admin_enroll(
        adminctx, superuser, {'admin_name': 'nobody'})
    assert status == 404


def test_enroll_begin_requires_superuser(adminctx, target_admin):
    """Auditor cannot enroll passkeys."""
    adminctx.enrollment.add_admin('audit', 'auditor', 'CN=audit')
    auditor = adminctx.enrollment.admins['audit']
    status, body = admin_handlers.passkey_admin_enroll(
        adminctx, auditor, {'admin_name': target_admin})
    assert status == 403


# ---- list / revoke ------------------------------------------------------

def test_list_returns_empty_for_new_admin(adminctx, superuser, target_admin):
    status, body = admin_handlers.passkey_admin_list(
        adminctx, superuser, target_admin)
    assert status == 200
    assert body['credentials'] == []


def test_list_returns_registered_credentials(adminctx, superuser, target_admin):
    # Manually pre-register a credential.
    adminctx.enrollment.add_admin_passkey(target_admin, PasskeyCredential(
        credential_id='abc123',
        public_key='pubkey-blob',
        aaguid='ee882879-721c-4913-9775-3dfcce97072a',
        sign_count=5, label='alice yubikey'))
    status, body = admin_handlers.passkey_admin_list(
        adminctx, superuser, target_admin)
    assert status == 200
    assert len(body['credentials']) == 1
    assert body['credentials'][0]['label'] == 'alice yubikey'


def test_revoke_invalidates_2fa_cache(adminctx, superuser, target_admin):
    adminctx.enrollment.add_admin_passkey(target_admin, PasskeyCredential(
        credential_id='abc123', public_key='pk', aaguid='', sign_count=0))
    adminctx.passkey_2fa_cache[target_admin] = '2099-01-01T00:00:00Z'

    status, body = admin_handlers.passkey_admin_revoke(
        adminctx, superuser, target_admin, 'abc123')
    assert status == 200
    assert target_admin not in adminctx.passkey_2fa_cache


def test_revoke_unknown_404(adminctx, superuser, target_admin):
    status, body = admin_handlers.passkey_admin_revoke(
        adminctx, superuser, target_admin, 'never-existed')
    assert status == 404


# ---- callback handling --------------------------------------------------

def test_callback_unknown_ceremony_404(adminctx):
    status, body = admin_handlers.passkey_admin_callback(adminctx, {
        'ceremony_id': 'ghost',
        'outcome': 'approved',
        'response_json': '{}',
    })
    assert status == 404


def test_callback_outcome_not_approved_just_logs(adminctx, target_admin):
    """Denied / expired callbacks remove the pending entry + audit-log
    but don't try to verify."""
    adminctx.passkey_pending_registrations['c1'] = {
        'flow': 'admin', 'admin_name': target_admin,
        'challenge': b'x' * 32,
        'label': '', 'allowlist': adminctx.passkey_aaguid_allowlist,
        'rp_id': adminctx.passkey_rp_id,
        'expected_origin': adminctx.passkey_expected_origin,
    }
    status, body = admin_handlers.passkey_admin_callback(adminctx, {
        'ceremony_id': 'c1', 'outcome': 'denied',
        'response_json': None,
    })
    assert status == 200
    assert body['outcome'] == 'denied'
    # Pending entry consumed.
    assert 'c1' not in adminctx.passkey_pending_registrations


def test_callback_bad_outcome_400(adminctx):
    status, body = admin_handlers.passkey_admin_callback(adminctx, {
        'ceremony_id': 'c1', 'outcome': 'unknown',
    })
    assert status == 400


# ---- 2FA enforcement check ---------------------------------------------

def test_check_2fa_skips_when_policy_says_none(adminctx, superuser):
    policy = Policy(id='p1', require_2fa='none')
    out = admin_handlers.passkey_check_2fa(adminctx, superuser, policy)
    assert out is None


def test_check_2fa_returns_challenge_on_miss(adminctx, superuser, target_admin):
    # Need the calling admin to have a credential for the challenge to
    # succeed.
    adminctx.enrollment.add_admin_passkey('boot', PasskeyCredential(
        credential_id='abc', public_key='pk', aaguid='', sign_count=0))
    policy = Policy(id='p1', require_2fa='passkey', twofa_within_seconds=60)
    out = admin_handlers.passkey_check_2fa(adminctx, superuser, policy)
    assert out is not None
    status, body = out
    assert status == 202
    assert body['reason'] == 'passkey_required'
    assert body['ceremony_id']


def test_check_2fa_cache_hit(adminctx, superuser):
    """When the admin has a recent verified 2FA, the check returns
    None (skip the challenge)."""
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    adminctx.passkey_2fa_cache['boot'] = now_iso
    policy = Policy(id='p1', require_2fa='passkey', twofa_within_seconds=60)
    out = admin_handlers.passkey_check_2fa(adminctx, superuser, policy)
    assert out is None


def test_check_2fa_503_when_broker_unconfigured(ca_dir):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    ctx = AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
    )
    enroll.add_admin('boot', 'superuser', 'CN=boot')
    su = enroll.admins['boot']
    policy = Policy(id='p1', require_2fa='passkey')
    out = admin_handlers.passkey_check_2fa(ctx, su, policy)
    assert out is not None
    status, body = out
    assert status == 503


def test_check_2fa_admin_has_no_credentials_403(adminctx, superuser):
    """If the admin needs 2FA but has no enrolled passkey, refuse —
    they can't satisfy it."""
    policy = Policy(id='p1', require_2fa='passkey')
    out = admin_handlers.passkey_check_2fa(adminctx, superuser, policy)
    assert out is not None
    status, body = out
    assert status == 403
    assert 'no active passkey' in body['detail']


# ---- policy DSL extension ---------------------------------------------

def test_policy_add_with_require_2fa(adminctx, superuser):
    adminctx.enrollment.add_user('alice')
    adminctx.enrollment.add_server('srv-foo', 'CN=srv-foo')
    status, body = admin_handlers.policy_add(adminctx, superuser, {
        'username': 'alice',
        'policy': {
            'servers': ['srv-foo'],
            'channels': ['session'],
            'require_2fa': 'passkey',
            'twofa_within_seconds': 120,
        },
    })
    assert status == 201
    # Saved + read back.
    alice = adminctx.enrollment.users['alice']
    assert alice.policies[-1].require_2fa == 'passkey'
    assert alice.policies[-1].twofa_within_seconds == 120


def test_policy_add_rejects_unknown_2fa(adminctx, superuser):
    adminctx.enrollment.add_user('alice')
    adminctx.enrollment.add_server('srv-foo', 'CN=srv-foo')
    status, body = admin_handlers.policy_add(adminctx, superuser, {
        'username': 'alice',
        'policy': {
            'servers': ['srv-foo'],
            'channels': ['session'],
            'require_2fa': 'totp',         # not 'none' or 'passkey'
        },
    })
    assert status == 400
