"""Unit tests for mssh.msshd.authz_cache.

Covers cache operations + on-disk persistence + source-tag policy.
The msshd-side bypass-injection wiring (the bit inside
enforce_listener._handle_bypass_injection) is exercised in the LXC
integration suite where there's a real CA + mTLS handshake; here we
just cover the cache module on its own.

Tests: §5.3.5, §5.3.6, §13.1, §13.9.3, §14.6
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


# ---------------------------------------------------------------------------
# Eviction (capacity caps)
# ---------------------------------------------------------------------------


def test_eviction_default_no_caps_active():
    """Default constructor: no caps. Cache grows unbounded."""
    c = AuthzCache()
    for i in range(1000):
        c.put(f'user-{i}', _grant(f'serial-{i}'), source=SOURCE_CA)
    assert len(c._entries) == 1000


def test_global_cap_evicts_oldest_first():
    c = AuthzCache(max_total=3)
    # Insert in order so injected_at is monotonic.
    c.put('alice',   _grant('a1'), source=SOURCE_CA)
    c.put('bob',     _grant('b1'), source=SOURCE_CA)
    c.put('carol',   _grant('c1'), source=SOURCE_CA)
    assert len(c._entries) == 3
    # Fourth entry triggers eviction of oldest (alice).
    c.put('dave',    _grant('d1'), source=SOURCE_CA)
    assert len(c._entries) == 3
    assert c.get('alice') is None
    assert c.get('bob') is not None
    assert c.get('carol') is not None
    assert c.get('dave') is not None


def test_global_cap_treats_bypass_identically():
    """Bypass-tagged entries follow the same eviction rules; no
    source-based exemption (per the agreed 'same policy for any cert'
    resolution)."""
    c = AuthzCache(max_total=2)
    c.put('alice', _grant('a1'), source=SOURCE_BYPASS)   # oldest
    c.put('bob',   _grant('b1'), source=SOURCE_CA)
    c.put('carol', _grant('c1'), source=SOURCE_CA)
    # alice (oldest, bypass) evicted.
    assert c.get('alice') is None
    assert c.get('bob') is not None
    assert c.get('carol') is not None


def test_global_cap_replaces_existing_doesnt_grow():
    """A put() that replaces an existing principal's entry shouldn't
    trip the cap (since count is unchanged)."""
    c = AuthzCache(max_total=2)
    c.put('alice', _grant('a1'), source=SOURCE_CA)
    c.put('bob',   _grant('b1'), source=SOURCE_CA)
    # Replace alice with a fresh grant — total count stays at 2.
    c.put('alice', _grant('a2'), source=SOURCE_CA)
    assert len(c._entries) == 2
    assert c.get('alice').grant.serial == 'a2'
    assert c.get('bob') is not None


def test_global_cap_zero_disables():
    c = AuthzCache(max_total=0)
    for i in range(100):
        c.put(f'user-{i}', _grant(f's-{i}'), source=SOURCE_CA)
    assert len(c._entries) == 100


def test_per_principal_cap_structural_today():
    """Per-principal cap > 0 is forward-compat: today the cache is
    keyed by principal so the cap is structurally enforced at 1.
    The knob doesn't change observable behavior."""
    c = AuthzCache(max_per_principal=10, max_total=0)
    for i in range(5):
        c.put('alice', _grant(f's-{i}'), source=SOURCE_CA)
    # Always exactly one entry per principal today.
    assert len(c._entries) == 1
    assert c.get('alice').grant.serial == 's-4'


def test_global_cap_persists_after_eviction(tmp_path):
    """Eviction triggers persist; reloading from disk shows the
    post-eviction state."""
    p = tmp_path / 'cache.json'
    c = AuthzCache(persist_path=p, max_total=2)
    c.put('alice', _grant('a1'), source=SOURCE_CA)
    c.put('bob',   _grant('b1'), source=SOURCE_CA)
    c.put('carol', _grant('c1'), source=SOURCE_CA)
    # alice was evicted; reload should NOT have alice.
    c2 = AuthzCache(persist_path=p, max_total=2)
    assert c2.get('alice') is None
    assert c2.get('bob') is not None
    assert c2.get('carol') is not None


def test_cap_lowered_on_construction_evicts_immediately(tmp_path):
    """If on-disk has more entries than max_total at load time, the
    NEXT put() trims down. Reloading with a lower cap doesn't
    proactively trim (read is read-only), but the next mutating
    operation enforces the cap."""
    p = tmp_path / 'cache.json'
    c1 = AuthzCache(persist_path=p)
    for i in range(5):
        c1.put(f'user-{i}', _grant(f's-{i}'), source=SOURCE_CA)
    # Reload with a much smaller cap.
    c2 = AuthzCache(persist_path=p, max_total=2)
    assert len(c2._entries) == 5    # not yet trimmed
    # First write trims down to 2.
    c2.put('newcomer', _grant('new'), source=SOURCE_CA)
    assert len(c2._entries) == 2


# R-7 §14.6 tests — last_used_at tracking + persistence

def test_r7_put_sets_last_used_at_to_injected_at(tmp_path):
    """Verifies §14.6 — put() initializes last_used_at to injected_at."""
    c = AuthzCache()
    c.put('alice', _grant('srv1'), source=SOURCE_CA)
    entry = c._entries['alice']
    assert entry.last_used_at is not None
    assert entry.last_used_at == entry.injected_at


def test_r7_get_updates_last_used_at(tmp_path):
    """Verifies §14.6 — get() bumps last_used_at on each successful hit."""
    import time
    c = AuthzCache()
    c.put('alice', _grant('srv1'), source=SOURCE_CA)
    first_use = c._entries['alice'].last_used_at
    time.sleep(0.01)
    c.get('alice')
    second_use = c._entries['alice'].last_used_at
    assert second_use > first_use


def test_r7_last_used_at_round_trips_through_persistence(tmp_path):
    """Verifies §14.6 — last_used_at survives serialize → load.

    Note: on-disk format is second-precision (per §14.6 ISO-8601 'Z'
    format), so the round-trip drops sub-second components.
    """
    p = tmp_path / 'cache.json'
    c1 = AuthzCache(persist_path=p)
    c1.put('alice', _grant('srv1'), source=SOURCE_CA)
    original = c1._entries['alice'].last_used_at.replace(microsecond=0)
    c2 = AuthzCache(persist_path=p)
    assert c2._entries['alice'].last_used_at == original


def test_r7_load_pre_r7_file_falls_back_to_injected_at(tmp_path):
    """Verifies §14.6 — files written before R-7 (no last_used_at field)
    load cleanly with last_used_at defaulted to injected_at.
    """
    import base64, datetime as _dt
    # Hand-craft a pre-R-7 entry (no last_used_at key).
    p = tmp_path / 'cache.json'
    grant = _grant('srv1')
    body = {
        'version': 1,
        'last_crl_seq': 0,
        'last_crl_seqs': {},
        'entries': [{
            'principal': 'alice',
            'cert_der_b64': base64.b64encode(grant.cert_der).decode('ascii'),
            'serial': grant.serial,
            'not_after': grant.not_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'inner_sshd_config': '',
            'protocol_version': '',
            'source': SOURCE_CA,
            'injected_at': '2026-05-22T12:00:00Z',
            # NO last_used_at key (pre-R-7 file).
        }],
    }
    p.write_text(json.dumps(body))
    c = AuthzCache(persist_path=p)
    entry = c._entries['alice']
    assert entry.last_used_at == entry.injected_at
