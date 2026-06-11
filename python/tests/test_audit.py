"""Unit tests for ca/audit.py.

Tests: §4.3.7, §14.6, §13.9.6
"""
from __future__ import annotations

import json

from mssh.ca.audit import AuditLog


def test_write_and_read(tmp_path):
    a = AuditLog(tmp_path / 'audit.jsonl')
    a.write({'type': 'admin', 'action': 'server.add', 'result': 'ok'})
    a.write({'type': 'authorization', 'decision': 'granted'})
    entries = a.read_all()
    assert len(entries) == 2
    assert entries[0]['action'] == 'server.add'
    assert entries[1]['decision'] == 'granted'


def test_read_empty(tmp_path):
    a = AuditLog(tmp_path / 'nope.jsonl')
    assert a.read_all() == []


def test_thread_safe_writes(tmp_path):
    import threading
    a = AuditLog(tmp_path / 'a.jsonl')
    def _run():
        for i in range(50):
            a.write({'i': i})
    threads = [threading.Thread(target=_run) for _ in range(4)]
    for t in threads: t.start()
    for t in threads: t.join()
    entries = a.read_all()
    assert len(entries) == 200


# R-6 reconciliation tests — Verifies §14.6 audit.jsonl canonical schema.

def test_r6_admin_entry_gets_canonical_keys(tmp_path):
    """Verifies §14.6 — admin writes get ts, request_id, actor, action,
    target, result, detail, origin added alongside legacy keys.
    """
    a = AuditLog(tmp_path / 'a.jsonl')
    a.write({
        'timestamp': '2026-05-22T12:00:00Z',
        'type': 'admin',
        'action': 'server.add',
        'admin': {'name': 'bob', 'subject': 'CN=bob'},
        'target': 'srv-acct-01',
        'result': 'ok',
    })
    e = a.read_all()[0]
    # Canonical §14.6 keys (R-6).
    assert e['ts'] == '2026-05-22T12:00:00Z'
    assert e['request_id']  # uuid4 hex; generated if absent
    assert e['actor'] == 'bob'
    assert e['action'] == 'server.add'
    assert e['target'] == 'srv-acct-01'
    assert e['result'] == 'ok'
    assert e['detail'] == {}
    assert e['origin'] == ''
    # Legacy keys still present (additive R-6).
    assert e['timestamp'] == '2026-05-22T12:00:00Z'
    assert e['admin'] == {'name': 'bob', 'subject': 'CN=bob'}


def test_r6_authorize_entry_gets_canonical_keys(tmp_path):
    """Verifies §14.6 — authorize writes are translated from legacy
    `timestamp`/`type`/`decision` to canonical `ts`/`action`/`result`.
    """
    a = AuditLog(tmp_path / 'b.jsonl')
    a.write({
        'timestamp': '2026-05-22T12:00:00Z',
        'type': 'authorization',
        'decision': 'granted',
        'identity': {'username': 'alice'},
        'server': {'canonical_name': 'srv1'},
    })
    e = a.read_all()[0]
    assert e['ts'] == '2026-05-22T12:00:00Z'
    assert e['action'] == 'authorize'             # 'authorization' → 'authorize'
    assert e['result'] == 'granted'                # ← decision
    assert e['actor'] == 'alice'                   # ← identity.username
    assert e['target'] == 'srv1'                   # ← server.canonical_name
    # Legacy keys preserved.
    assert e['decision'] == 'granted'
    assert e['type'] == 'authorization'


def test_r6_request_id_is_unique_per_entry(tmp_path):
    """Verifies §14.6 — auto-generated request_ids don't collide."""
    a = AuditLog(tmp_path / 'c.jsonl')
    for i in range(50):
        a.write({'i': i})
    entries = a.read_all()
    ids = {e['request_id'] for e in entries}
    assert len(ids) == 50  # all distinct


def test_r6_explicit_origin_preserved(tmp_path):
    """Verifies §14.6 — caller-supplied origin (e.g. 'mcp') is preserved."""
    a = AuditLog(tmp_path / 'd.jsonl')
    a.write({'action': 'server.list', 'origin': 'mcp'})
    e = a.read_all()[0]
    assert e['origin'] == 'mcp'


def test_r6_canonicalize_idempotent(tmp_path):
    """Verifies §14.6 — if caller already supplies canonical keys,
    they're preserved (not overwritten).
    """
    a = AuditLog(tmp_path / 'e.jsonl')
    a.write({
        'ts': '2026-05-22T01:02:03Z',
        'request_id': 'fixed-id',
        'actor': 'alice',
        'action': 'authorize',
        'target': 'srv1',
        'result': 'granted',
    })
    e = a.read_all()[0]
    assert e['ts'] == '2026-05-22T01:02:03Z'
    assert e['request_id'] == 'fixed-id'
    assert e['actor'] == 'alice'


# Phase 2 §13.9.6 hash-chain tests.

def test_p2_hash_chain_first_entry_uses_genesis_hash(tmp_path):
    """Verifies §13.9.6 — first entry's prev_hash is the genesis sentinel."""
    from mssh.ca.audit import _ZERO_HASH
    a = AuditLog(tmp_path / 'h.jsonl')
    a.write({'action': 'first.event'})
    e = a.read_all()[0]
    assert e['prev_hash'] == _ZERO_HASH


def test_p2_hash_chain_links_entries(tmp_path):
    """Verifies §13.9.6 — each entry's prev_hash matches hash(previous line)."""
    import hashlib
    a = AuditLog(tmp_path / 'h2.jsonl')
    a.write({'action': 'e1'})
    a.write({'action': 'e2'})
    a.write({'action': 'e3'})
    raw = (tmp_path / 'h2.jsonl').read_text().splitlines()
    e2 = json.loads(raw[1])
    e3 = json.loads(raw[2])
    assert e2['prev_hash'] == hashlib.sha256(raw[0].encode()).hexdigest()
    assert e3['prev_hash'] == hashlib.sha256(raw[1].encode()).hexdigest()


def test_p2_verify_chain_clean(tmp_path):
    """Verifies §13.9.6 — verify_chain() returns [] on an untampered log."""
    a = AuditLog(tmp_path / 'h3.jsonl')
    for i in range(10):
        a.write({'action': f'e{i}'})
    assert a.verify_chain() == []


def test_p2_verify_chain_detects_modification(tmp_path):
    """Verifies §13.9.6 — modifying a middle entry breaks the chain."""
    p = tmp_path / 'h4.jsonl'
    a = AuditLog(p)
    for i in range(5):
        a.write({'action': f'e{i}'})
    # Edit line 3 (1-based) — change action 'e2' → 'e2-tampered'.
    lines = p.read_text().splitlines()
    entry = json.loads(lines[2])
    entry['action'] = 'e2-tampered'
    lines[2] = json.dumps(entry, separators=(',', ':'), sort_keys=True)
    p.write_text('\n'.join(lines) + '\n')
    # Reload via a fresh AuditLog so it doesn't have the cached tail hash.
    a2 = AuditLog(p)
    broken = a2.verify_chain()
    # Line 4 (1-based) is the first line whose prev_hash no longer
    # matches the now-modified line 3. Lines 4 + 5 both break because
    # the chain is now off-by-one from line 3 onward.
    assert 4 in broken


def test_p2_verify_chain_detects_deletion(tmp_path):
    """Verifies §13.9.6 — deleting a middle line breaks the chain."""
    p = tmp_path / 'h5.jsonl'
    a = AuditLog(p)
    for i in range(5):
        a.write({'action': f'e{i}'})
    lines = p.read_text().splitlines()
    # Delete line 3.
    del lines[2]
    p.write_text('\n'.join(lines) + '\n')
    a2 = AuditLog(p)
    broken = a2.verify_chain()
    assert broken                                # at least one break
    # The line that USED to be line 4 is now line 3; its prev_hash
    # still points to the old line 2's hash but line 3's actual
    # predecessor is now the (preserved) line 2 — wait, that means
    # line 3 (new) is fine. The break is line 3 (new) → line 4 (new):
    # the new line 3's hash differs from what the new line 4's
    # prev_hash claims.
    # In any case the verify should flag at least one break.


def test_p2_hash_chain_survives_reopen(tmp_path):
    """Verifies §13.9.6 — closing + reopening preserves the chain.

    The tail hash is recomputed lazily from the file on first write.
    """
    p = tmp_path / 'h6.jsonl'
    a1 = AuditLog(p)
    a1.write({'action': 'a'})
    a1.write({'action': 'b'})
    del a1
    a2 = AuditLog(p)
    a2.write({'action': 'c'})
    assert a2.verify_chain() == []
