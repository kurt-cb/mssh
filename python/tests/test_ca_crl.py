"""Unit tests for the CA-side CRL store + admin handlers.

Covers:
  - CRLStore: append, fetch_after, current_seq, restart-safety
  - cert_revoke admin handler: RBAC, input validation, happy path
  - crl_fetch handler: reads current_seq + entries

Tests: §4.3.5, §13.3
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.crl import CRLRegistry, CRLStore
from mssh.ca.enrollment import Admin, Enrollment


@pytest.fixture
def crl_store(tmp_path):
    """Bare CRLStore for unit tests of the store's own API."""
    return CRLStore(tmp_path / 'crl.jsonl')


@pytest.fixture
def crl_registry(tmp_path):
    """Per-issuer registry that handlers expect on ctx.crl."""
    return CRLRegistry(tmp_path / 'crl')


@pytest.fixture
def adminctx(ca_dir, crl_registry):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec', crl=crl_registry,
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


@pytest.fixture
def user_admin():
    return Admin(name='useradm', role='user-admin',
                 mtls_subject='CN=useradm')


# ---------------------------------------------------------------------------
# CRLStore unit tests
# ---------------------------------------------------------------------------


def test_crlstore_empty_current_seq(tmp_path):
    s = CRLStore(tmp_path / 'crl.jsonl')
    assert s.current_seq() == 0


def test_crlstore_append_returns_entry_with_assigned_seq(crl_store):
    e1 = crl_store.append(['abc'], revoked_by='alice')
    assert e1.seq == 1
    assert e1.serials == ['abc']
    assert e1.revoked_by == 'alice'
    assert crl_store.current_seq() == 1

    e2 = crl_store.append(['def', 'ghi'], revoked_by='alice',
                          reason='rotation')
    assert e2.seq == 2
    assert crl_store.current_seq() == 2


def test_crlstore_fetch_after_filters_by_seq(crl_store):
    crl_store.append(['a'], revoked_by='a')   # seq=1
    crl_store.append(['b'], revoked_by='a')   # seq=2
    crl_store.append(['c'], revoked_by='a')   # seq=3

    assert [e.seq for e in crl_store.fetch_after(0)] == [1, 2, 3]
    assert [e.seq for e in crl_store.fetch_after(1)] == [2, 3]
    assert [e.seq for e in crl_store.fetch_after(3)] == []
    assert [e.seq for e in crl_store.fetch_after(100)] == []


def test_crlstore_fetch_after_respects_limit(crl_store):
    for i in range(10):
        crl_store.append([f'cert-{i}'], revoked_by='a')
    out = crl_store.fetch_after(0, limit=3)
    assert [e.seq for e in out] == [1, 2, 3]


def test_crlstore_persistence_round_trip(tmp_path):
    p = tmp_path / 'crl.jsonl'
    s1 = CRLStore(p)
    s1.append(['abc'], revoked_by='a')
    s1.append(['def', 'ghi'], revoked_by='a', reason='rotation')

    s2 = CRLStore(p)
    assert s2.current_seq() == 2
    out = s2.fetch_after(0)
    assert len(out) == 2
    assert out[0].serials == ['abc']
    assert out[1].serials == ['def', 'ghi']


def test_crlstore_serials_normalized_to_lowercase(crl_store):
    e = crl_store.append(['ABCdef', '  XYZ  '], revoked_by='a')
    assert e.serials == ['abcdef', 'xyz']


def test_crlstore_skips_malformed_lines(tmp_path):
    p = tmp_path / 'crl.jsonl'
    # Mix of valid + malformed lines.
    body = [
        '{"seq":1,"revoked_at":"2026-01-01T00:00:00Z","serials":["a"],"revoked_by":"a"}',
        'this is not json',
        '{"seq":2,"revoked_at":"2026-01-01T00:00:00Z","serials":["b"],"revoked_by":"a"}',
        '',
    ]
    p.write_text('\n'.join(body) + '\n')
    s = CRLStore(p)
    assert s.current_seq() == 2
    out = s.fetch_after(0)
    assert len(out) == 2


# ---------------------------------------------------------------------------
# cert_revoke admin handler
# ---------------------------------------------------------------------------


def test_cert_revoke_forbidden_for_user_admin(adminctx, user_admin):
    status, body = admin_handlers.cert_revoke(
        adminctx, user_admin, {'serials': ['abc']})
    assert status == 403


def test_cert_revoke_requires_serials(adminctx, superuser):
    status, body = admin_handlers.cert_revoke(adminctx, superuser, {})
    assert status == 400
    status, body = admin_handlers.cert_revoke(
        adminctx, superuser, {'serials': []})
    assert status == 400
    status, body = admin_handlers.cert_revoke(
        adminctx, superuser, {'serials': 'not-a-list'})
    assert status == 400


def test_cert_revoke_rejects_blank_serial(adminctx, superuser):
    status, _ = admin_handlers.cert_revoke(
        adminctx, superuser, {'serials': ['']})
    assert status == 400


def test_cert_revoke_happy_path(adminctx, superuser, crl_registry):
    status, body = admin_handlers.cert_revoke(
        adminctx, superuser,
        {'serials': ['abc123', 'DEF456'], 'reason': 'rotation'})
    assert status == 201
    assert body['seq'] == 1
    assert body['serials'] == ['abc123', 'def456']
    # Default issuer is user-mint.
    assert body['issuer'] == 'user-mint'
    assert crl_registry.for_issuer('user-mint').current_seq() == 1


def test_cert_revoke_appends_to_existing_log(adminctx, superuser, crl_registry):
    admin_handlers.cert_revoke(
        adminctx, superuser, {'serials': ['a']})
    status, body = admin_handlers.cert_revoke(
        adminctx, superuser, {'serials': ['b']})
    assert status == 201
    assert body['seq'] == 2


def test_cert_revoke_explicit_issuer(adminctx, superuser, crl_registry):
    """Caller can target a specific intermediate's CRL log."""
    status, body = admin_handlers.cert_revoke(
        adminctx, superuser,
        {'serials': ['abc'], 'issuer': 'bypass-mint',
         'reason': 'revoke offline-minted'})
    assert status == 201
    assert body['issuer'] == 'bypass-mint'
    # The revocation lives in bypass-mint's log, NOT user-mint's.
    assert crl_registry.for_issuer('bypass-mint').current_seq() == 1
    assert crl_registry.for_issuer('user-mint').current_seq() == 0


# ---------------------------------------------------------------------------
# crl_fetch admin handler
# ---------------------------------------------------------------------------


def test_crl_fetch_returns_current_seq_and_entries(adminctx, superuser,
                                                     auditor):
    admin_handlers.cert_revoke(adminctx, superuser, {'serials': ['a']})
    admin_handlers.cert_revoke(adminctx, superuser, {'serials': ['b']})
    status, body = admin_handlers.crl_fetch(adminctx, auditor, 0, None)
    assert status == 200
    assert body['current_seq'] == 2
    assert len(body['entries']) == 2


def test_crl_fetch_after_filters(adminctx, superuser, auditor):
    for s in ['a', 'b', 'c', 'd']:
        admin_handlers.cert_revoke(adminctx, superuser, {'serials': [s]})
    status, body = admin_handlers.crl_fetch(adminctx, auditor, 2, None)
    assert status == 200
    assert [e['seq'] for e in body['entries']] == [3, 4]


@pytest.fixture
def auditor():
    return Admin(name='aud', role='auditor', mtls_subject='CN=aud')
