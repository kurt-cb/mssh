"""Tests for the external-tool RP-service flow in mssh-ca.

Tests: §4.3.9, §13.6
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import Admin, Enrollment


@pytest.fixture
def adminctx(ca_dir, tmp_path):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')

    fake_broker = MagicMock()
    fake_broker.create_ceremony.return_value = type('C', (), {
        'ceremony_id': 'ceremony-tool',
        'url': 'https://passkey.example.com/approve/ceremony-tool',
        'expires_at': '2099-01-01T00:00:00Z',
    })()
    fake_broker.client_cert = 'cb-cert.pem'
    fake_broker.client_key = 'cb-key.pem'
    fake_broker.ca_cert = 'cb-ca.pem'

    from mssh.ca import passkey as _pk
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        passkey_broker=fake_broker,
        passkey_rp_id='passkey.example.com',
        passkey_rp_name='mssh-ca',
        passkey_expected_origin='https://passkey.example.com',
        passkey_callback_url='https://mssh-ca/cb',
        passkey_aaguid_allowlist=_pk.AAGUIDAllowlist(allowed=set(),
                                                      require_allowlist=False),
        passkey_pending_registrations={},
        passkey_pending_authentications={},
        passkey_2fa_cache={},
    )


@pytest.fixture
def superuser(adminctx):
    adminctx.enrollment.add_admin('boot', 'superuser', 'CN=boot')
    return adminctx.enrollment.admins['boot']


# ---- Tool CRUD --------------------------------------------------------

def test_tool_add(adminctx, superuser):
    """Verifies §4.3.9 — external-tool registration mints mTLS credentials."""
    status, body = admin_handlers.external_tool_add(adminctx, superuser, {
        'name': 'payroll',
        'rp_id': 'passkey.example.com',
        'outcome_url_prefix': 'https://payroll.example.com/cb/',
    })
    assert status == 201
    assert body['tool']['name'] == 'payroll'
    assert body['tool']['mtls_subject'].startswith('CN=external-tool:')
    assert '-----BEGIN' in body['credentials']['cert_pem']


def test_tool_add_validates_https_prefix(adminctx, superuser):
    status, body = admin_handlers.external_tool_add(adminctx, superuser, {
        'name': 'bad', 'rp_id': 'p',
        'outcome_url_prefix': 'http://insecure/',
    })
    assert status == 400


def test_tool_add_conflict(adminctx, superuser):
    body = {'name': 'payroll', 'rp_id': 'p',
            'outcome_url_prefix': 'https://payroll/cb/'}
    assert admin_handlers.external_tool_add(adminctx, superuser, body)[0] == 201
    assert admin_handlers.external_tool_add(adminctx, superuser, body)[0] == 409


def test_tool_list_empty(adminctx, superuser):
    status, body = admin_handlers.external_tool_list(adminctx, superuser)
    assert status == 200
    assert body['tools'] == []


def test_tool_remove(adminctx, superuser):
    admin_handlers.external_tool_add(adminctx, superuser, {
        'name': 'payroll', 'rp_id': 'p',
        'outcome_url_prefix': 'https://x/cb/'})
    status, _ = admin_handlers.external_tool_remove(adminctx, superuser, 'payroll')
    assert status == 200
    assert admin_handlers.external_tool_remove(
        adminctx, superuser, 'payroll')[0] == 404


def test_tool_add_forbidden_for_auditor(adminctx):
    """Verifies §4.3.9 — auditors cannot register external tools (superuser-only)."""
    adminctx.enrollment.add_admin('aud', 'auditor', 'CN=aud')
    auditor = adminctx.enrollment.admins['aud']
    status, _ = admin_handlers.external_tool_add(adminctx, auditor, {
        'name': 'payroll', 'rp_id': 'p',
        'outcome_url_prefix': 'https://x/cb/'})
    assert status == 403


# ---- Tool-mTLS endpoints ----------------------------------------------

def _enrol_tool(adminctx, superuser, name='payroll'):
    admin_handlers.external_tool_add(adminctx, superuser, {
        'name': name, 'rp_id': 'passkey.example.com',
        'outcome_url_prefix': 'https://app.example.com/cb/',
    })
    return f'CN=external-tool:{name}'


def test_enroll_begin_rejects_unknown_tool(adminctx):
    status, body = admin_handlers.external_tool_passkey_enroll_begin(
        adminctx, 'CN=unknown-tool',
        {'user_id': 'alice'})
    assert status == 401


def test_enroll_begin_success(adminctx, superuser):
    subj = _enrol_tool(adminctx, superuser)
    status, body = admin_handlers.external_tool_passkey_enroll_begin(
        adminctx, subj,
        {'user_id': 'alice@payroll', 'display_name': 'Alice'})
    assert status == 201
    assert body['url'].endswith('ceremony-tool')
    pending = adminctx.passkey_pending_registrations['ceremony-tool']
    assert pending['flow'] == 'external-tool'
    assert pending['tool_name'] == 'payroll'
    assert pending['user_id'] == 'alice@payroll'


def test_enroll_begin_missing_user_id(adminctx, superuser):
    subj = _enrol_tool(adminctx, superuser)
    status, _ = admin_handlers.external_tool_passkey_enroll_begin(
        adminctx, subj, {})
    assert status == 400


def test_challenge_validates_outcome_url_prefix(adminctx, superuser):
    """Verifies §13.6 — outcome_url must match the tool's registered prefix."""
    subj = _enrol_tool(adminctx, superuser)
    # Pre-register a credential so the challenge has someone to challenge.
    from mssh.ca.enrollment import PasskeyCredential
    adminctx.enrollment.add_external_tool_user_passkey(
        'payroll', 'alice', PasskeyCredential(
            credential_id='c1', public_key='pk', aaguid='', sign_count=0))

    status, body = admin_handlers.external_tool_passkey_challenge(
        adminctx, subj, {
            'user_id': 'alice',
            'description': 'Approve payroll batch #1234',
            'outcome_url': 'https://attacker.example.com/cb/x',
        })
    assert status == 400
    assert 'must start with' in body['detail']


def test_challenge_404_when_user_has_no_creds(adminctx, superuser):
    subj = _enrol_tool(adminctx, superuser)
    status, _ = admin_handlers.external_tool_passkey_challenge(
        adminctx, subj, {
            'user_id': 'alice',
            'description': 'x',
            'outcome_url': 'https://app.example.com/cb/x',
        })
    assert status == 404


def test_challenge_success(adminctx, superuser):
    subj = _enrol_tool(adminctx, superuser)
    from mssh.ca.enrollment import PasskeyCredential
    adminctx.enrollment.add_external_tool_user_passkey(
        'payroll', 'alice', PasskeyCredential(
            credential_id='c1', public_key='pk', aaguid='', sign_count=0))

    status, body = admin_handlers.external_tool_passkey_challenge(
        adminctx, subj, {
            'user_id': 'alice',
            'description': 'Approve batch',
            'outcome_url': 'https://app.example.com/cb/x',
        })
    assert status == 201
    assert body['ceremony_id'] == 'ceremony-tool'
    pending = adminctx.passkey_pending_authentications['ceremony-tool']
    assert pending['flow'] == 'external-tool'
    assert pending['outcome_url'] == 'https://app.example.com/cb/x'


def test_status_cross_tool_isolation(adminctx, superuser):
    """Verifies §13.6 — Tool A cannot poll Tool B's ceremony status (tenant isolation)."""
    _enrol_tool(adminctx, superuser, 'tool-a')
    _enrol_tool(adminctx, superuser, 'tool-b')
    # Tool A creates a ceremony.
    from mssh.ca.enrollment import PasskeyCredential
    adminctx.enrollment.add_external_tool_user_passkey(
        'tool-a', 'alice', PasskeyCredential(
            credential_id='c1', public_key='pk', aaguid='', sign_count=0))
    admin_handlers.external_tool_passkey_challenge(
        adminctx, 'CN=external-tool:tool-a', {
            'user_id': 'alice', 'description': 'x',
            'outcome_url': 'https://app.example.com/cb/x'})
    # Tool B tries to poll it.
    status, body = admin_handlers.external_tool_passkey_status(
        adminctx, 'CN=external-tool:tool-b', 'ceremony-tool')
    assert status == 404


def test_revoke_credential(adminctx, superuser):
    subj = _enrol_tool(adminctx, superuser)
    from mssh.ca.enrollment import PasskeyCredential
    adminctx.enrollment.add_external_tool_user_passkey(
        'payroll', 'alice', PasskeyCredential(
            credential_id='cred-x', public_key='pk', aaguid='', sign_count=0))
    status, body = admin_handlers.external_tool_passkey_revoke(
        adminctx, subj, 'alice', 'cred-x')
    assert status == 200
    # Now no active creds left.
    tool = adminctx.enrollment.external_tools['payroll']
    assert tool.user_credentials['alice'][0].revoked_at != ''


def test_revoke_unknown_404(adminctx, superuser):
    subj = _enrol_tool(adminctx, superuser)
    status, _ = admin_handlers.external_tool_passkey_revoke(
        adminctx, subj, 'alice', 'nope')
    assert status == 404


# R-4: external-tool ceremony cancel route. Tests: §14.1.3, §13.6

def test_r4_cancel_ceremony_own_tool(adminctx, superuser):
    """Verifies §14.1.3 — tool can cancel its own pending ceremony."""
    subj = _enrol_tool(adminctx, superuser)
    from mssh.ca.enrollment import PasskeyCredential
    adminctx.enrollment.add_external_tool_user_passkey(
        'payroll', 'alice', PasskeyCredential(
            credential_id='c1', public_key='pk', aaguid='', sign_count=0))
    admin_handlers.external_tool_passkey_challenge(
        adminctx, subj, {
            'user_id': 'alice', 'description': 'x',
            'outcome_url': 'https://app.example.com/cb/x'})
    status, body = admin_handlers.external_tool_passkey_cancel(
        adminctx, subj, 'ceremony-tool')
    assert status == 200
    assert body['outcome'] == 'cancelled'
    # Pending record is dropped.
    assert 'ceremony-tool' not in adminctx.passkey_pending_authentications


def test_r4_cancel_ceremony_cross_tool_404(adminctx, superuser):
    """Verifies §13.6 — tool cannot cancel another tool's ceremony.

    Cross-tool DELETE returns 404 to keep ceremony existence opaque.
    """
    _enrol_tool(adminctx, superuser, 'tool-a')
    _enrol_tool(adminctx, superuser, 'tool-b')
    from mssh.ca.enrollment import PasskeyCredential
    adminctx.enrollment.add_external_tool_user_passkey(
        'tool-a', 'alice', PasskeyCredential(
            credential_id='c1', public_key='pk', aaguid='', sign_count=0))
    admin_handlers.external_tool_passkey_challenge(
        adminctx, 'CN=external-tool:tool-a', {
            'user_id': 'alice', 'description': 'x',
            'outcome_url': 'https://app.example.com/cb/x'})
    status, _ = admin_handlers.external_tool_passkey_cancel(
        adminctx, 'CN=external-tool:tool-b', 'ceremony-tool')
    assert status == 404
