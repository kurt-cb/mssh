"""Audit logging in JSON Lines format.

Design: §4.3.7 (see design/mssh_design_v1.md)
Also a §13.9.6 hardening member — the append-only audit log is one of
the mandatory tamper-evidence surfaces.

R-6 reconciliation (2026-05-22): every entry written through `write()`
is canonicalized to carry the §14.6 design schema keys (`ts`,
`request_id`, `actor`, `action`, `target`, `result`, `detail`,
`origin`) alongside any legacy keys the caller supplied. The
canonicalization is additive — legacy `timestamp`, `decision`, `admin`
etc. remain in the entry so existing in-tree consumers (read_all,
audit.read REST endpoint) continue to work. A v1.x cleanup commit
will drop the legacy keys once nothing reads them.

Phase 2 §13.9.6 (2026-05-22): hash-chain integrity. Each entry
carries a `prev_hash` field — SHA-256 over the previous entry's
serialized JSON. The first entry's `prev_hash` is the literal
``"0" * 64``. ``verify_chain()`` walks the file and confirms every
entry's `prev_hash` matches the hash of the preceding entry; any
mismatch is a tamper signal. `mssh-admin audit verify` invokes this.
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from pathlib import Path
from typing import Any


def _canonicalize(entry: dict[str, Any]) -> dict[str, Any]:
    """Add canonical §14.6 keys to an audit entry, derived from
    whatever the caller supplied. Idempotent; canonical keys already
    present are preserved.

    Design: §14.6 audit.jsonl schema.
    """
    out = dict(entry)

    # ts ← timestamp (legacy)
    if 'ts' not in out and 'timestamp' in out:
        out['ts'] = out['timestamp']

    # request_id ← generate (uuid4 hex) if absent
    out.setdefault('request_id', uuid.uuid4().hex)

    # actor ← admin → identity.username → 'ca:internal'
    if 'actor' not in out:
        if 'admin' in out:
            adm = out['admin']
            if isinstance(adm, dict):
                out['actor'] = adm.get('name') or adm.get('subject') or 'admin:unknown'
            else:
                out['actor'] = f'admin:{adm}'
        elif isinstance(out.get('identity'), dict):
            uname = out['identity'].get('username')
            if uname:
                out['actor'] = uname
        if 'actor' not in out:
            out['actor'] = 'ca:internal'

    # action ← existing 'action' or 'type' (e.g. 'authorization' → 'authorize')
    if 'action' not in out:
        t = out.get('type')
        if t == 'authorization':
            out['action'] = 'authorize'
        elif t:
            out['action'] = str(t)

    # target ← existing 'target' or server.canonical_name
    if 'target' not in out:
        srv = out.get('server')
        if isinstance(srv, dict) and srv.get('canonical_name'):
            out['target'] = srv['canonical_name']

    # result ← existing 'result' or 'decision' (granted/denied)
    if 'result' not in out:
        if 'decision' in out:
            out['result'] = out['decision']

    # detail (already a dict in many places; ensure key exists)
    out.setdefault('detail', {})

    # origin defaults to empty (set explicitly by MCP / external-tool / etc.)
    out.setdefault('origin', '')

    return out


_ZERO_HASH = '0' * 64                  # §13.9.6 genesis-entry hash


def _hash_line(line: str) -> str:
    """SHA-256 hex of a serialized JSONL line (without the trailing
    newline). Used as the chain link for the next entry's prev_hash.
    """
    return hashlib.sha256(line.encode('utf-8')).hexdigest()


class AuditLog:
    """Append-only JSONL writer. Thread-safe for in-process writers.

    Phase 2 §13.9.6: each entry carries `prev_hash` linking to the
    previous entry. Tamper-resistance: any mid-file edit/delete
    breaks the chain at and below the modified point;
    ``verify_chain()`` returns the offending line numbers.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # §13.9.6: cached tail hash, primed lazily from the file on
        # first write. None = not yet primed.
        self._last_hash: str | None = None

    def _prime_last_hash(self) -> str:
        """Compute the chain-tail hash by re-reading the file once.
        Called under the lock at first write after construction.
        """
        if not self.path.exists():
            return _ZERO_HASH
        last = _ZERO_HASH
        with self.path.open() as f:
            for line in f:
                stripped = line.rstrip('\n')
                if stripped:
                    last = _hash_line(stripped)
        return last

    def write(self, entry: dict[str, Any]) -> None:
        # §4.3.7 append-only audit; §13.9.6 hash-chain tamper-evidence.
        # R-6: canonicalize to §14.6 schema before writing.
        canonical = _canonicalize(entry)
        with self._lock:
            if self._last_hash is None:
                self._last_hash = self._prime_last_hash()
            # §13.9.6: chain this entry to the previous one. If the
            # caller already set prev_hash (e.g. for a manual replay),
            # leave it alone.
            canonical.setdefault('prev_hash', self._last_hash)
            line = json.dumps(canonical, separators=(',', ':'),
                              sort_keys=True)
            with self.path.open('a') as f:
                f.write(line + '\n')
            # Update tail for the next append.
            self._last_hash = _hash_line(line)

    def read_all(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        with self.path.open() as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify_chain(self) -> list[int]:
        """Verify the §13.9.6 hash chain. Returns a list of 1-based
        line numbers where the chain breaks (empty list = clean).

        For each line N, expects ``entry.prev_hash == hash(line N-1)``.
        Line 1's prev_hash is the genesis sentinel ``"0"*64``.

        Design: §13.9.6 audit log tamper-resistance.
        """
        # §13.9.6 audit integrity verification.
        if not self.path.exists():
            return []
        broken: list[int] = []
        prev_hash = _ZERO_HASH
        with self.path.open() as f:
            for lineno, raw in enumerate(f, start=1):
                stripped = raw.rstrip('\n')
                if not stripped:
                    continue
                try:
                    entry = json.loads(stripped)
                except json.JSONDecodeError:
                    broken.append(lineno)
                    # Can't recover; subsequent lines will all be
                    # marked broken too because we can't compute the
                    # right prev_hash without the parsed entry.
                    prev_hash = _hash_line(stripped)
                    continue
                claimed = entry.get('prev_hash')
                if claimed != prev_hash:
                    broken.append(lineno)
                prev_hash = _hash_line(stripped)
        return broken
