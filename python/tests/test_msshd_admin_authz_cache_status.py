"""Tests for `msshd-admin authz-cache status` — operator diagnostic
for the persisted authz cache.

Reads the on-disk JSON written by AuthzCache._persist(); summarises
total entries, by-source breakdown, soonest expiry, applied CRL
sequences. Useful in incident response when an operator wants to
see what msshd has cached without restarting it or attaching a
debugger.

Tests: §5.3.14
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

import pytest

from mssh.msshd.admin import main as admin_main
from mssh.msshd.authz_cache import AuthzCache, SOURCE_BYPASS, SOURCE_CA
from mssh.msshd.ca import AuthorizationGrant


def _grant(serial: str, *, days: int = 1) -> AuthorizationGrant:
    return AuthorizationGrant(
        cert_der=b'fake',
        serial=serial,
        not_after=_dt.datetime.now(_dt.timezone.utc) +
                  _dt.timedelta(days=days),
    )


@pytest.fixture
def cache_file(tmp_path):
    """Pre-populated cache JSON file via AuthzCache itself."""
    p = tmp_path / 'authz_cache.json'
    c = AuthzCache(persist_path=p)
    c.put('alice', _grant('a1'), source=SOURCE_CA)
    c.put('bob', _grant('b1'), source=SOURCE_CA)
    c.put('carol', _grant('c1'), source=SOURCE_BYPASS)
    c.set_last_crl_seq(7, issuer='user-mint')
    c.set_last_crl_seq(2, issuer='bypass-mint')
    return p


def test_status_no_cache_returns_zero(tmp_path, capsys):
    """When the cache file doesn't exist, the CLI prints a clear
    message and exits 0 (operator probably hasn't started msshd yet,
    or the cache hasn't been written)."""
    rc = admin_main(['authz-cache', 'status',
                      '--cache-path', str(tmp_path / 'nope.json')])
    assert rc == 0
    captured = capsys.readouterr()
    assert 'no authz cache' in captured.err


def test_status_human_summary(cache_file, capsys):
    rc = admin_main(['authz-cache', 'status',
                      '--cache-path', str(cache_file)])
    assert rc == 0
    out = capsys.readouterr().out
    assert 'total entries:   3' in out
    assert 'ca       2' in out
    assert 'bypass   1' in out
    assert 'user-mint' in out
    assert 'seq=7' in out
    assert 'bypass-mint' in out
    assert 'seq=2' in out


def test_status_json_emits_summary(cache_file, capsys):
    rc = admin_main(['authz-cache', 'status',
                      '--cache-path', str(cache_file), '--json'])
    assert rc == 0
    body = json.loads(capsys.readouterr().out)
    assert body['total_entries'] == 3
    assert body['by_source'] == {'ca': 2, 'bypass': 1}
    assert body['last_crl_seqs'] == {'user-mint': 7, 'bypass-mint': 2}
    assert 'soonest_expiry' in body
    # Default JSON output is summary-only.
    assert 'entries' not in body


def test_status_verbose_includes_entries(cache_file, capsys):
    rc = admin_main(['authz-cache', 'status',
                      '--cache-path', str(cache_file),
                      '--json', '--verbose'])
    assert rc == 0
    body = json.loads(capsys.readouterr().out)
    principals = {e['principal'] for e in body['entries']}
    assert principals == {'alice', 'bob', 'carol'}


def test_status_legacy_singular_last_crl_seq(tmp_path, capsys):
    """v0.2.2-era cache files have only `last_crl_seq` (int), not
    the dict. The CLI promotes it to {'user-mint': N}."""
    p = tmp_path / 'authz_cache.json'
    p.write_text(json.dumps({
        'version': 1, 'last_crl_seq': 42, 'entries': []}))
    rc = admin_main(['authz-cache', 'status',
                      '--cache-path', str(p), '--json'])
    assert rc == 0
    body = json.loads(capsys.readouterr().out)
    assert body['last_crl_seqs'] == {'user-mint': 42}
