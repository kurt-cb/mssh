"""Unit tests for the msshd-side CRL sync logic.

Covers:
  - authz_cache.invalidate_by_serial (drops matching entry,
    source-agnostic; persists)
  - authz_cache.last_crl_seq persisted across reload
  - authz_cache.set_last_crl_seq (monotonic, no-op when going backward)
  - CRLSync.sync_now: catch-up loop, applies revocations, advances
    last_crl_seq, stops on error
  - CRLSync handles empty pages / CA giving up
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest

from mssh.msshd.authz_cache import (SOURCE_BYPASS, SOURCE_CA, AuthzCache)
from mssh.msshd.ca import AuthorizationGrant
from mssh.msshd.crl_sync import CRLSync


def _now():
    return _dt.datetime.now(_dt.timezone.utc)


def _grant(serial: str, *,
           valid_for=_dt.timedelta(hours=1)) -> AuthorizationGrant:
    return AuthorizationGrant(
        cert_der=f'der-{serial}'.encode('utf-8'),
        serial=serial,
        not_after=_now() + valid_for,
    )


# ---------------------------------------------------------------------------
# invalidate_by_serial
# ---------------------------------------------------------------------------


def test_invalidate_by_serial_drops_matching_entry():
    c = AuthzCache()
    c.put('alice', _grant('abc123'), source=SOURCE_CA)
    c.put('bob', _grant('def456'), source=SOURCE_CA)
    assert c.invalidate_by_serial('abc123') == 1
    assert c.get('alice') is None
    assert c.get('bob') is not None


def test_invalidate_by_serial_is_source_agnostic():
    """A revoked bypass cert is dropped exactly the same as a revoked
    CA-grant cert. CRL applies don't care about source."""
    c = AuthzCache()
    c.put('alice', _grant('abc123'), source=SOURCE_BYPASS)
    assert c.invalidate_by_serial('abc123') == 1
    assert c.get('alice') is None


def test_invalidate_by_serial_normalizes_case():
    c = AuthzCache()
    c.put('alice', _grant('abc123'), source=SOURCE_CA)
    assert c.invalidate_by_serial('ABC123') == 1
    assert c.get('alice') is None


def test_invalidate_by_serial_no_match_returns_zero():
    c = AuthzCache()
    c.put('alice', _grant('abc'), source=SOURCE_CA)
    assert c.invalidate_by_serial('not-a-serial') == 0
    assert c.get('alice') is not None


def test_invalidate_by_serial_persists_to_disk(tmp_path):
    p = tmp_path / 'cache.json'
    c = AuthzCache(persist_path=p)
    c.put('alice', _grant('abc'), source=SOURCE_CA)
    c.invalidate_by_serial('abc')

    c2 = AuthzCache(persist_path=p)
    assert c2.get('alice') is None


# ---------------------------------------------------------------------------
# last_crl_seq tracking + persistence
# ---------------------------------------------------------------------------


def test_last_crl_seq_starts_at_zero():
    c = AuthzCache()
    assert c.last_crl_seq == 0


def test_set_last_crl_seq_advances():
    c = AuthzCache()
    c.set_last_crl_seq(5)
    assert c.last_crl_seq == 5


def test_set_last_crl_seq_monotonic_no_backward(tmp_path):
    c = AuthzCache(persist_path=tmp_path / 'cache.json')
    c.set_last_crl_seq(10)
    c.set_last_crl_seq(3)        # ignored
    assert c.last_crl_seq == 10


def test_last_crl_seq_persists(tmp_path):
    p = tmp_path / 'cache.json'
    c = AuthzCache(persist_path=p)
    c.set_last_crl_seq(42)

    c2 = AuthzCache(persist_path=p)
    assert c2.last_crl_seq == 42


# ---------------------------------------------------------------------------
# CRLSync.sync_now
# ---------------------------------------------------------------------------


class _FakeCAClient:
    """Drop-in for MsshdCAClient for sync tests. Records call args
    and returns pre-canned CRL pages."""

    def __init__(self, pages: list[dict]):
        # pages[i] is the response to call i.
        self._pages = list(pages)
        self.fetch_calls: list[tuple[int, int]] = []

    async def fetch_crl(self, *, after: int, limit: int,
                        issuer: str = 'user-mint') -> dict:
        self.fetch_calls.append((after, limit))
        if not self._pages:
            return {'status': 'ok', 'current_seq': after, 'entries': []}
        return self._pages.pop(0)


def _make_entry(seq: int, serials: list[str]) -> dict:
    return {
        'seq': seq,
        'revoked_at': '2026-01-01T00:00:00Z',
        'serials': serials,
        'revoked_by': 'admin',
        'reason': '',
    }


@pytest.mark.asyncio
async def test_sync_invalidates_revoked_serial(tmp_path):
    c = AuthzCache()
    c.put('alice', _grant('abc'), source=SOURCE_CA)

    fake = _FakeCAClient([{
        'status': 'ok', 'current_seq': 1,
        'entries': [_make_entry(1, ['abc'])],
    }])
    sync = CRLSync(c, fake, fetch_limit=10)
    new_seqs = await sync.sync_now(1)
    assert new_seqs.get('user-mint') == 1
    assert c.last_crl_seq == 1
    assert c.get('alice') is None


@pytest.mark.asyncio
async def test_sync_pages_through_multiple_fetches(tmp_path):
    """sync_now keeps fetching until last_applied catches up to
    current_crl_seq, in fetch_limit-sized chunks."""
    c = AuthzCache()
    c.put('alice', _grant('abc'), source=SOURCE_CA)
    c.put('bob', _grant('def'), source=SOURCE_CA)
    c.put('carol', _grant('ghi'), source=SOURCE_CA)

    # Two pages, current_seq=3. fetch_limit=2 → first page returns
    # seq 1-2, second page returns seq 3.
    fake = _FakeCAClient([
        {'status': 'ok', 'current_seq': 3,
         'entries': [_make_entry(1, ['abc']), _make_entry(2, ['def'])]},
        {'status': 'ok', 'current_seq': 3,
         'entries': [_make_entry(3, ['ghi'])]},
    ])
    sync = CRLSync(c, fake, fetch_limit=2)
    new_seqs = await sync.sync_now(3)
    assert new_seqs.get('user-mint') == 3
    assert c.last_crl_seq == 3
    assert c.get('alice') is None
    assert c.get('bob') is None
    assert c.get('carol') is None
    assert fake.fetch_calls == [(0, 2), (2, 2)]


@pytest.mark.asyncio
async def test_sync_stops_on_ca_error_and_preserves_partial_progress():
    c = AuthzCache()
    c.put('alice', _grant('abc'), source=SOURCE_CA)
    c.put('bob', _grant('def'), source=SOURCE_CA)

    class _FailingClient:
        def __init__(self):
            self._calls = 0
        async def fetch_crl(self, *, after, limit, issuer='user-mint'):
            self._calls += 1
            if self._calls == 1:
                return {
                    'status': 'ok', 'current_seq': 5,
                    'entries': [_make_entry(1, ['abc'])],
                }
            raise RuntimeError('CA unreachable')

    sync = CRLSync(c, _FailingClient(), fetch_limit=1)
    new_seqs = await sync.sync_now(5)
    # First entry applied; second fetch failed → stops at seq=1.
    assert new_seqs.get('user-mint') == 1
    assert c.last_crl_seq == 1
    assert c.get('alice') is None
    assert c.get('bob') is not None


@pytest.mark.asyncio
async def test_sync_handles_empty_response():
    """CA may return current_seq=N but no entries (e.g., entries were
    pruned for expired certs). Bump last_seq to current and stop."""
    c = AuthzCache()
    fake = _FakeCAClient([{
        'status': 'ok', 'current_seq': 7, 'entries': [],
    }])
    sync = CRLSync(c, fake, fetch_limit=10)
    new_seqs = await sync.sync_now(7)
    assert new_seqs.get('user-mint') == 7
    assert c.last_crl_seq == 7


@pytest.mark.asyncio
async def test_sync_noop_when_already_caught_up():
    c = AuthzCache()
    c.set_last_crl_seq(5)
    fake = _FakeCAClient([])
    sync = CRLSync(c, fake, fetch_limit=10)
    new_seqs = await sync.sync_now(5)
    assert new_seqs.get('user-mint') == 5
    assert fake.fetch_calls == []
