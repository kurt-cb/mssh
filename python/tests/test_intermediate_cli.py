"""Tests for v0.2.4 (Commit 5): mssh-admin intermediate CLI +
admin-side handlers. Covers:

  - intermediate_list: returns metadata for all 4 intermediates
  - intermediate_rotate: replaces keypair + cert; archives old; keeps
    legacy aliases in sync; new issuer_id reflected
  - RBAC: list is auditor-or-superuser; rotate is superuser only
  - 503 when CA is in legacy single-signer mode (no ca_dir)

Tests: §2.5, §7.3.4
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.crl import CRLRegistry
from mssh.ca.enrollment import Admin, Enrollment


@pytest.fixture
def ca_with_intermediates(tmp_path):
    """Bootstrap a fresh CA with the multi-intermediate layout."""
    d = tmp_path / 'ca'
    cert_minter.bootstrap_ca(d)
    return d


@pytest.fixture
def adminctx(ca_with_intermediates):
    d = ca_with_intermediates
    enroll = Enrollment(d / 'enrollment.yaml')
    audit = AuditLog(d / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(d / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(d / 'tls-ca-cert.pem')
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        crl=CRLRegistry(d / 'crl'),
        ca_dir=str(d),
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


@pytest.fixture
def auditor():
    return Admin(name='aud', role='auditor', mtls_subject='CN=aud')


@pytest.fixture
def user_admin():
    return Admin(name='ua', role='user-admin', mtls_subject='CN=ua')


# ---- intermediate.list -------------------------------------------------

def test_list_returns_all_four_intermediates(adminctx, superuser):
    status, body = admin_handlers.intermediate_list(adminctx, superuser)
    assert status == 200
    roles = {i['role'] for i in body['intermediates']}
    assert roles == {'user-mint', 'bypass-mint', 'host-mint', 'auth'}


def test_list_each_entry_has_issuer_id_and_validity(adminctx, superuser):
    status, body = admin_handlers.intermediate_list(adminctx, superuser)
    for entry in body['intermediates']:
        assert ':' in entry['issuer_id']         # short:fp16
        assert len(entry['pubkey_fp16']) == 16
        assert entry['not_before']
        assert entry['not_after']
        assert entry['subject']


def test_list_auditor_allowed(adminctx, auditor):
    status, _ = admin_handlers.intermediate_list(adminctx, auditor)
    assert status == 200


def test_list_user_admin_allowed(adminctx, user_admin):
    """Verifies §14.1.2 — intermediate.list RBAC allows user-admin.

    R-4 broadened the allow-list to {superuser, server-admin, user-admin,
    auditor} to match the design's published RBAC matrix.
    """
    status, _ = admin_handlers.intermediate_list(adminctx, user_admin)
    assert status == 200


def test_list_503_when_no_ca_dir(adminctx, superuser):
    """Legacy single-signer mode (no ca_dir) → 503."""
    adminctx.ca_dir = ''
    status, body = admin_handlers.intermediate_list(adminctx, superuser)
    assert status == 503
    assert 'legacy' in body['detail']


# ---- intermediate.rotate -----------------------------------------------

def test_rotate_replaces_keypair(adminctx, superuser, ca_with_intermediates):
    d = ca_with_intermediates
    role_dir = d / 'intermediates' / 'user-mint'
    old_cert = (role_dir / 'cert.pem').read_bytes()
    old_key = (role_dir / 'key.pem').read_bytes()

    status, body = admin_handlers.intermediate_rotate(
        adminctx, superuser, {'role': 'user-mint'})
    assert status == 200

    new_cert = (role_dir / 'cert.pem').read_bytes()
    new_key = (role_dir / 'key.pem').read_bytes()
    assert new_cert != old_cert
    assert new_key != old_key
    # Archived under timestamp.
    archives = list(role_dir.glob('cert.pem.archive.*'))
    assert len(archives) == 1
    assert archives[0].read_bytes() == old_cert


def test_rotate_returns_new_issuer_id(adminctx, superuser):
    status, body = admin_handlers.intermediate_rotate(
        adminctx, superuser, {'role': 'bypass-mint'})
    assert status == 200
    assert body['new_issuer_id'].startswith('bypass-mint:')


def test_rotate_includes_redistribution_warning(adminctx, superuser):
    status, body = admin_handlers.intermediate_rotate(
        adminctx, superuser, {'role': 'host-mint'})
    assert status == 200
    assert 'Distribute' in body['warning']
    assert 'bypass_trust_root' in body['warning']


def test_rotate_keeps_legacy_signing_alias_in_sync(adminctx, superuser,
                                                     ca_with_intermediates):
    """Rotating user-mint must update signing-cert.pem / signing-key.pem
    so legacy callers see the new key too."""
    d = ca_with_intermediates
    admin_handlers.intermediate_rotate(
        adminctx, superuser, {'role': 'user-mint'})
    # Aliases match the new intermediate.
    new_user_mint_cert = (d / 'intermediates' / 'user-mint' / 'cert.pem'
                          ).read_bytes()
    assert (d / 'signing-cert.pem').read_bytes() == new_user_mint_cert


def test_rotate_keeps_legacy_tls_ca_alias_in_sync(adminctx, superuser,
                                                    ca_with_intermediates):
    """Rotating auth must update tls-ca-cert.pem (as auth+root bundle)."""
    d = ca_with_intermediates
    admin_handlers.intermediate_rotate(
        adminctx, superuser, {'role': 'auth'})
    new_auth_cert = (d / 'intermediates' / 'auth' / 'cert.pem').read_bytes()
    root = (d / 'root-cert.pem').read_bytes()
    assert (d / 'tls-ca-cert.pem').read_bytes() == new_auth_cert + root


def test_rotate_rejects_unknown_role(adminctx, superuser):
    status, body = admin_handlers.intermediate_rotate(
        adminctx, superuser, {'role': 'imaginary'})
    assert status == 400


def test_rotate_user_admin_forbidden(adminctx, user_admin):
    status, _ = admin_handlers.intermediate_rotate(
        adminctx, user_admin, {'role': 'user-mint'})
    assert status == 403


def test_rotate_auditor_forbidden(adminctx, auditor):
    """Auditor can READ via list but cannot ROTATE."""
    status, _ = admin_handlers.intermediate_rotate(
        adminctx, auditor, {'role': 'user-mint'})
    assert status == 403


def test_rotate_503_when_no_ca_dir(adminctx, superuser):
    adminctx.ca_dir = ''
    status, body = admin_handlers.intermediate_rotate(
        adminctx, superuser, {'role': 'user-mint'})
    assert status == 503


def test_rotate_audited(adminctx, superuser, ca_with_intermediates):
    admin_handlers.intermediate_rotate(
        adminctx, superuser, {'role': 'user-mint'})
    audit_lines = (ca_with_intermediates / 'audit.jsonl').read_text().splitlines()
    rotate_entries = [
        line for line in audit_lines if 'intermediate.rotate' in line]
    assert len(rotate_entries) == 1


# ---- cert.revoke takes issuer ------------------------------------------

def test_cert_revoke_issuer_threads_through_to_registry(adminctx, superuser):
    status, body = admin_handlers.cert_revoke(
        adminctx, superuser,
        {'serials': ['deadbeef'], 'issuer': 'bypass-mint',
         'reason': 'test'})
    assert status == 201
    assert body['issuer'] == 'bypass-mint'
    # And user-mint's log is empty.
    assert adminctx.crl.for_issuer('user-mint').current_seq() == 0
    assert adminctx.crl.for_issuer('bypass-mint').current_seq() == 1
