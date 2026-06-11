"""Tests for admin-2FA gating: the CA-config protected-action list
forces a passkey ceremony before the handler runs.

Companion to test_passkey_admin_flow.py — that file tests the
passkey helper in isolation; this one tests the per-action gating
on actual handlers (cert_revoke, admin_add, admin_remove, user_remove)
and the CLI's poll-and-retry loop.

Tests: §13.5, §4.3.8
"""

from __future__ import annotations

import datetime as _dt
from unittest.mock import MagicMock, patch

import pytest

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.crl import CRLRegistry
from mssh.ca.enrollment import Enrollment, PasskeyCredential


# ---- AdminContext fixture with gating turned on ------------------------

@pytest.fixture
def gated_ctx(ca_dir, tmp_path):
    """Context with gating wired for 4 actions + a stub broker that
    happily mints ceremonies."""
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    signing_key = cert_minter.load_private_key(ca_dir / 'signing-key.pem')
    signing_cert = cert_minter.load_certificate(ca_dir / 'signing-cert.pem')

    fake_broker = MagicMock()
    fake_broker.create_ceremony.return_value = type('C', (), {
        'ceremony_id': 'ceremony-xyz',
        'url': 'https://passkey.example.com/approve/ceremony-xyz',
        'expires_at': '2099-01-01T00:00:00Z',
    })()

    from mssh.ca import passkey as _pk
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        signing_key=signing_key, signing_cert=signing_cert,
        crl=CRLRegistry(ca_dir / 'crl'),
        passkey_broker=fake_broker,
        passkey_rp_id='passkey.example.com',
        passkey_rp_name='mssh-ca test',
        passkey_expected_origin='https://passkey.example.com',
        passkey_callback_url='https://mssh-ca/v1/admin/passkey/callback',
        passkey_aaguid_allowlist=_pk.AAGUIDAllowlist(
            allowed=set(), require_allowlist=False),
        passkey_pending_registrations={},
        passkey_pending_authentications={},
        passkey_2fa_cache={},
        admin_2fa_protected_actions=frozenset({
            'admin.add', 'admin.remove', 'user.remove', 'cert.revoke',
        }),
        admin_2fa_within_seconds=60,
    )


@pytest.fixture
def superuser_with_passkey(gated_ctx):
    gated_ctx.enrollment.add_admin('boot', 'superuser', 'CN=boot')
    gated_ctx.enrollment.add_admin_passkey('boot', PasskeyCredential(
        credential_id='abc', public_key='pk', aaguid='', sign_count=0))
    return gated_ctx.enrollment.admins['boot']


# ---- helper: admin_check_2fa --------------------------------------------

def test_check_skips_action_not_in_list(gated_ctx, superuser_with_passkey):
    """An unprotected action passes through cleanly."""
    out = admin_handlers.admin_check_2fa(
        gated_ctx, superuser_with_passkey, 'server.add')
    assert out is None


def test_check_returns_challenge_for_protected_action(gated_ctx,
                                                       superuser_with_passkey):
    out = admin_handlers.admin_check_2fa(
        gated_ctx, superuser_with_passkey, 'cert.revoke')
    assert out is not None
    status, body = out
    assert status == 202
    assert body['reason'] == 'passkey_required'
    assert body['ceremony_id'] == 'ceremony-xyz'


def test_check_cache_hit_skips_challenge(gated_ctx, superuser_with_passkey):
    now = _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    gated_ctx.passkey_2fa_cache['boot'] = now
    out = admin_handlers.admin_check_2fa(
        gated_ctx, superuser_with_passkey, 'cert.revoke')
    assert out is None


# ---- wired handlers gate on the protected list --------------------------

def test_cert_revoke_returns_202_when_uncached(gated_ctx,
                                                superuser_with_passkey):
    status, body = admin_handlers.cert_revoke(
        gated_ctx, superuser_with_passkey,
        {'serials': ['deadbeef'], 'reason': 'test'})
    assert status == 202
    assert body['reason'] == 'passkey_required'


def test_cert_revoke_proceeds_with_cache_hit(gated_ctx,
                                              superuser_with_passkey):
    now = _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    gated_ctx.passkey_2fa_cache['boot'] = now
    status, body = admin_handlers.cert_revoke(
        gated_ctx, superuser_with_passkey,
        {'serials': ['deadbeef'], 'reason': 'test'})
    assert status == 201
    assert body['status'] == 'ok'


def test_admin_add_gated(gated_ctx, superuser_with_passkey):
    status, body = admin_handlers.admin_add(
        gated_ctx, superuser_with_passkey,
        {'name': 'new-admin', 'role': 'auditor'})
    assert status == 202


def test_user_remove_gated(gated_ctx, superuser_with_passkey):
    gated_ctx.enrollment.add_user('alice')
    status, body = admin_handlers.user_remove(
        gated_ctx, superuser_with_passkey, 'alice')
    assert status == 202


def test_empty_protected_list_passes_through(ca_dir, tmp_path):
    """Default config (empty protected list) is a no-op — handlers run
    even without a broker configured."""
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    ctx = AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        crl=CRLRegistry(ca_dir / 'crl'),
    )  # admin_2fa_protected_actions defaults to empty
    enroll.add_admin('boot', 'superuser', 'CN=boot')
    su = enroll.admins['boot']
    enroll.add_user('alice')
    status, body = admin_handlers.user_remove(ctx, su, 'alice')
    assert status == 200


# ---- CLI poll-retry loop -----------------------------------------------

def _mk_pending_2fa_resp():
    return {
        'status': 'pending_2fa',
        'reason': 'passkey_required',
        'ceremony_id': 'ceremony-xyz',
        'url': 'https://passkey.example.com/approve/ceremony-xyz',
        'expires_at': '2099-01-01T00:00:00Z',
    }


def test_cli_2fa_polls_and_retries_on_approval():
    from mssh.admin.main import _handle_2fa_call

    fake_client = MagicMock()
    fake_op = MagicMock(side_effect=[
        _mk_pending_2fa_resp(),                # first call → challenge
        {'status': 'ok', 'removed': 'alice'},  # retry after approval → success
    ])
    fake_client.passkey_poll = MagicMock(side_effect=[
        {'status': 'pending'},
        {'status': 'ok', 'outcome': 'approved'},
    ])
    with patch('mssh.admin.main.time.sleep'):
        out = _handle_2fa_call(fake_client, fake_op, 'alice')
    assert out == {'status': 'ok', 'removed': 'alice'}
    assert fake_op.call_count == 2
    assert fake_client.passkey_poll.call_count == 2


def test_cli_2fa_exits_on_denial():
    from mssh.admin.main import _handle_2fa_call

    fake_client = MagicMock()
    fake_op = MagicMock(return_value=_mk_pending_2fa_resp())
    fake_client.passkey_poll = MagicMock(return_value={
        'status': 'ok', 'outcome': 'denied'})
    with patch('mssh.admin.main.time.sleep'):
        with pytest.raises(SystemExit) as excinfo:
            _handle_2fa_call(fake_client, fake_op, 'alice')
    assert excinfo.value.code == 2


def test_cli_2fa_passthrough_when_no_challenge():
    from mssh.admin.main import _handle_2fa_call

    fake_client = MagicMock()
    fake_op = MagicMock(return_value={'status': 'ok', 'removed': 'alice'})
    out = _handle_2fa_call(fake_client, fake_op, 'alice')
    assert out == {'status': 'ok', 'removed': 'alice'}
    assert fake_op.call_count == 1
    fake_client.passkey_poll.assert_not_called()


def test_cli_qr_renders_when_stderr_is_tty(capsys):
    """When stderr is a TTY (interactive run), _handle_2fa_call
    renders a QR code below the URL. Operator can scan it with
    a phone instead of typing the URL.

    Verifies: code path doesn't crash + the QR characters appear
    in stderr (unicode half-blocks indicate a rendered QR)."""
    from mssh.admin.main import _handle_2fa_call

    fake_client = MagicMock()
    fake_op = MagicMock(side_effect=[
        _mk_pending_2fa_resp(),
        {'status': 'ok', 'removed': 'alice'},
    ])
    fake_client.passkey_poll = MagicMock(return_value={
        'status': 'ok', 'outcome': 'approved'})

    with patch('mssh.admin.main.sys.stderr.isatty', return_value=True), \
         patch('mssh.admin.main.time.sleep'):
        _handle_2fa_call(fake_client, fake_op, 'alice')

    err = capsys.readouterr().err
    # QR uses unicode half-block chars (▄ ▀ █) when rendered. Look
    # for any of them; presence confirms the QR went out.
    assert any(ch in err for ch in '▄▀█'), (
        f'no QR chars in stderr; output was:\n{err}')


def test_cli_qr_skipped_when_stderr_not_a_tty(capsys):
    """Piped output (e.g. CI, redirected to file) shouldn't pollute
    with QR escape sequences."""
    from mssh.admin.main import _handle_2fa_call

    fake_client = MagicMock()
    fake_op = MagicMock(side_effect=[
        _mk_pending_2fa_resp(),
        {'status': 'ok', 'removed': 'alice'},
    ])
    fake_client.passkey_poll = MagicMock(return_value={
        'status': 'ok', 'outcome': 'approved'})

    # capsys already replaces stderr with a non-tty wrapper; isatty()
    # returns False naturally. Belt-and-suspenders, force it.
    with patch('mssh.admin.main.sys.stderr.isatty', return_value=False), \
         patch('mssh.admin.main.time.sleep'):
        _handle_2fa_call(fake_client, fake_op, 'alice')

    err = capsys.readouterr().err
    # URL still printed; no QR chars.
    assert 'approve' in err
    assert not any(ch in err for ch in '▄▀█'), (
        f'QR rendered into non-tty stderr; output was:\n{err}')
