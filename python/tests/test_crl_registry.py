"""Tests for the v0.2.2 per-issuer CRL registry.

The CRLRegistry wraps multiple CRLStores keyed by intermediate
short_name. Per-issuer logs let revocation entries from one
intermediate not interfere with serial lookups in another (serials
are issuer-scoped, not globally unique).

Tests: §4.3.5, §13.3, §2.5
"""
from __future__ import annotations

from pathlib import Path

import pytest

from mssh.ca.crl import (DEFAULT_CRL_ISSUER, CRLRegistry, CRLStore,
                          migrate_legacy_crl)


# ---- CRLRegistry basics ------------------------------------------------

def test_registry_creates_store_per_issuer(tmp_path):
    reg = CRLRegistry(tmp_path / 'crl')
    user_store = reg.for_issuer('user-mint')
    bypass_store = reg.for_issuer('bypass-mint')
    # Different stores, different files.
    assert user_store is not bypass_store
    assert user_store.path != bypass_store.path
    assert user_store.path.name == 'user-mint.jsonl'
    assert bypass_store.path.name == 'bypass-mint.jsonl'


def test_registry_for_issuer_is_idempotent(tmp_path):
    reg = CRLRegistry(tmp_path / 'crl')
    first = reg.for_issuer('user-mint')
    second = reg.for_issuer('user-mint')
    assert first is second


def test_registry_append_routes_to_issuer(tmp_path):
    reg = CRLRegistry(tmp_path / 'crl')
    reg.append('user-mint', ['abc'], revoked_by='alice')
    reg.append('bypass-mint', ['def'], revoked_by='alice')
    # Each entry lives only in its issuer's log.
    user_entries = reg.fetch_after('user-mint', 0)
    bypass_entries = reg.fetch_after('bypass-mint', 0)
    assert [e.serials for e in user_entries] == [['abc']]
    assert [e.serials for e in bypass_entries] == [['def']]


def test_registry_serials_isolated_across_issuers(tmp_path):
    """Same serial in two issuer logs: serial collision doesn't
    cross-contaminate. (Serials are issuer-scoped per X.509.)"""
    reg = CRLRegistry(tmp_path / 'crl')
    reg.append('user-mint', ['collide'], revoked_by='alice',
               reason='user-mint revoke')
    reg.append('bypass-mint', ['collide'], revoked_by='alice',
               reason='bypass-mint revoke')
    user = reg.fetch_after('user-mint', 0)
    bypass = reg.fetch_after('bypass-mint', 0)
    assert user[0].reason == 'user-mint revoke'
    assert bypass[0].reason == 'bypass-mint revoke'


def test_registry_current_seqs_returns_map(tmp_path):
    reg = CRLRegistry(tmp_path / 'crl')
    reg.append('user-mint', ['a'], revoked_by='alice')
    reg.append('user-mint', ['b'], revoked_by='alice')
    reg.append('auth', ['c'], revoked_by='alice')
    seqs = reg.current_seqs()
    assert seqs == {'user-mint': 2, 'auth': 1}


def test_registry_default_issuer_is_user_mint(tmp_path):
    """The convention is user-mint for backward compat with v0.2.0."""
    assert DEFAULT_CRL_ISSUER == 'user-mint'
    reg = CRLRegistry(tmp_path / 'crl')
    # Empty string defaults to user-mint.
    s = reg.for_issuer('')
    assert s.path.name == 'user-mint.jsonl'


def test_registry_known_issuers_discovers_existing_files(tmp_path):
    """On a cold start, existing .jsonl files are discovered, not
    only the ones explicitly opened."""
    crl_dir = tmp_path / 'crl'
    crl_dir.mkdir()
    (crl_dir / 'host-mint.jsonl').write_text('')
    (crl_dir / 'bypass-mint.jsonl').write_text('')
    reg = CRLRegistry(crl_dir)
    assert set(reg.known_issuers()) >= {'host-mint', 'bypass-mint'}


# ---- legacy migration ---------------------------------------------------

def test_migrate_legacy_crl_moves_old_file(tmp_path):
    legacy = tmp_path / 'crl.jsonl'
    legacy.write_text('{"seq":1,"revoked_at":"2026-01-01T00:00:00Z",'
                      '"serials":["abc"],"revoked_by":"alice"}\n')
    crl_dir = tmp_path / 'crl'
    moved = migrate_legacy_crl(crl_dir, legacy)
    assert moved is True
    assert not legacy.exists()
    assert (crl_dir / 'user-mint.jsonl').exists()
    # Content preserved.
    reg = CRLRegistry(crl_dir)
    entries = reg.fetch_after('user-mint', 0)
    assert entries[0].serials == ['abc']


def test_migrate_noop_if_target_exists(tmp_path):
    legacy = tmp_path / 'crl.jsonl'
    legacy.write_text('old\n')
    crl_dir = tmp_path / 'crl'
    crl_dir.mkdir()
    (crl_dir / 'user-mint.jsonl').write_text('new\n')
    moved = migrate_legacy_crl(crl_dir, legacy)
    assert moved is False
    # Both files left as they were.
    assert legacy.exists()
    assert (crl_dir / 'user-mint.jsonl').read_text() == 'new\n'


def test_migrate_noop_if_legacy_missing(tmp_path):
    crl_dir = tmp_path / 'crl'
    moved = migrate_legacy_crl(crl_dir, tmp_path / 'absent.jsonl')
    assert moved is False
