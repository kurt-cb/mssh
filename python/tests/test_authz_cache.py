"""Unit tests for mssh.msshd.authz_cache.

Covers cache operations + on-disk persistence + source-tag policy.
The msshd-side bypass-injection wiring (the bit inside
enforce_listener._handle_bypass_injection) is exercised in the LXC
integration suite where there's a real CA + mTLS handshake; here we
just cover the cache module on its own.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

import pytest

from mssh.msshd.authz_cache import (SOURCE_BYPASS, SOURCE_CA, AuthzCache,
                                     CachedGrant)
from mssh.msshd.ca import AuthorizationGrant


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now():
    return _dt.datetime.now(_dt.timezone.utc)


def _grant(serial: str = 'aaaa', *,
           valid_for=_dt.timedelta(hours=1)) -> AuthorizationGrant:
    return AuthorizationGrant(
        cert_der=f'der-{serial}'.encode('utf-8'),
        serial=serial,
        not_after=_now() + valid_for,
    )


# ---------------------------------------------------------------------------
# Basic put / get / invalidate
# ---------------------------------------------------------------------------


def test_get_miss_returns_none():
    c = AuthzCache()
    assert c.get('alice') is None


def test_put_then_get_hit():
    c = AuthzCache()
    g = _grant()
    e = c.put('alice', g, source=SOURCE_CA)
    assert isinstance(e, CachedGrant)
    hit = c.get('alice')
    assert hit is not None
    assert hit.principal == 'alice'
    assert hit.source == SOURCE_CA
    assert hit.grant.serial == 'aaaa'


def test_put_replaces_existing():
    c = AuthzCache()
    c.put('alice', _grant('first'), source=SOURCE_CA)
    c.put('alice', _grant('second'), source=SOURCE_BYPASS)
    hit = c.get('alice')
    assert hit.grant.serial == 'second'
    assert hit.source == SOURCE_BYPASS


def test_put_invalid_source_raises():
    c = AuthzCache()
    with pytest.raises(ValueError, match='source must be one of'):
        c.put('alice', _grant(), source='unknown')


def test_invalidate_returns_true_when_removed():
    c = AuthzCache()
    c.put('alice', _grant(), source=SOURCE_CA)
    assert c.invalidate('alice') is True
    assert c.get('alice') is None


def test_invalidate_no_op_when_missing():
    c = AuthzCache()
    assert c.invalidate('alice') is False


def test_invalidate_drops_bypass_too():
    """CA deny invalidates ALL entries for the principal, regardless
    of source. CA is the oracle when up."""
    c = AuthzCache()
    c.put('alice', _grant('bypass-cert'), source=SOURCE_BYPASS)
    assert c.invalidate('alice') is True
    assert c.get('alice') is None


# ---------------------------------------------------------------------------
# Lazy expiry on lookup
# ---------------------------------------------------------------------------


def test_expired_entry_evicted_on_get():
    c = AuthzCache()
    expired = _grant(valid_for=_dt.timedelta(seconds=-60))
    c.put('alice', expired, source=SOURCE_CA)
    # Bypass internal state check; get() must evict.
    assert c.get('alice') is None
    # Confirm the entry actually went away.
    assert 'alice' not in c._entries


def test_list_all_filters_and_evicts_expired():
    c = AuthzCache()
    c.put('alice', _grant('A', valid_for=_dt.timedelta(hours=1)),
          source=SOURCE_CA)
    c.put('bob',   _grant('B', valid_for=_dt.timedelta(seconds=-1)),
          source=SOURCE_BYPASS)
    c.put('carol', _grant('C', valid_for=_dt.timedelta(hours=1)),
          source=SOURCE_BYPASS)
    out = c.list_all()
    principals = sorted(e.principal for e in out)
    assert principals == ['alice', 'carol']
    assert 'bob' not in c._entries


# ---------------------------------------------------------------------------
# On-disk persistence
# ---------------------------------------------------------------------------


def test_persist_writes_file_at_mode_600(tmp_path):
    p = tmp_path / 'cache.json'
    c = AuthzCache(persist_path=p)
    c.put('alice', _grant(), source=SOURCE_CA)
    assert p.exists()
    assert (p.stat().st_mode & 0o777) == 0o600


def test_persist_roundtrip(tmp_path):
    p = tmp_path / 'cache.json'
    c = AuthzCache(persist_path=p)
    c.put('alice', _grant('a-serial'), source=SOURCE_CA)
    c.put('bob',   _grant('b-serial'), source=SOURCE_BYPASS)

    c2 = AuthzCache(persist_path=p)
    a = c2.get('alice')
    b = c2.get('bob')
    assert a.grant.serial == 'a-serial' and a.source == SOURCE_CA
    assert b.grant.serial == 'b-serial' and b.source == SOURCE_BYPASS


def test_persist_invalidate_persists_removal(tmp_path):
    p = tmp_path / 'cache.json'
    c = AuthzCache(persist_path=p)
    c.put('alice', _grant(), source=SOURCE_CA)
    c.invalidate('alice')
    c2 = AuthzCache(persist_path=p)
    assert c2.get('alice') is None


def test_persist_skips_expired_on_load(tmp_path):
    p = tmp_path / 'cache.json'
    c = AuthzCache(persist_path=p)
    c.put('alice', _grant('fresh', valid_for=_dt.timedelta(hours=1)),
          source=SOURCE_CA)
    c.put('bob',   _grant('stale', valid_for=_dt.timedelta(seconds=-1)),
          source=SOURCE_BYPASS)

    c2 = AuthzCache(persist_path=p)
    assert c2.get('alice') is not None
    assert c2.get('bob') is None


def test_persist_malformed_file_starts_empty(tmp_path):
    p = tmp_path / 'cache.json'
    p.write_text('not valid json {')
    c = AuthzCache(persist_path=p)
    assert c.get('anything') is None


def test_persist_unknown_source_skipped_on_load(tmp_path):
    p = tmp_path / 'cache.json'
    body = {
        'version': 1,
        'entries': [
            {'principal': 'alice', 'cert_der_b64': '',
             'serial': 'x', 'not_after': '9999-01-01T00:00:00Z',
             'inner_sshd_config': '', 'protocol_version': '',
             'source': 'unknown-source', 'injected_at': '2026-01-01T00:00:00Z'},
        ],
    }
    p.write_text(json.dumps(body))
    p.chmod(0o600)
    c = AuthzCache(persist_path=p)
    assert c.get('alice') is None


def test_persist_disabled_when_no_path():
    """In-memory mode: no disk side effects."""
    c = AuthzCache()
    c.put('alice', _grant(), source=SOURCE_CA)
    # No exception, no disk artifacts. Cache works in memory.
    assert c.get('alice') is not None
    assert c._persist_path is None
