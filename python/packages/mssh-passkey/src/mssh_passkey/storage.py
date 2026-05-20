"""SQLite-backed ceremony store.

One table. Holds in-flight WebAuthn ceremonies until the user
acts or the TTL expires. The broker never inspects ``options_json``
or ``response_json`` — both are opaque from the broker's
perspective and relayed as-is.

Concurrency: SQLite with WAL mode + a coarse Python lock around
mutating operations. Plenty for the broker's load profile
(handfuls of ceremonies per minute).
"""

from __future__ import annotations

import datetime as _dt
import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


_SCHEMA = """
CREATE TABLE IF NOT EXISTS ceremonies (
    ceremony_id     TEXT PRIMARY KEY,
    ceremony_type   TEXT NOT NULL CHECK (ceremony_type IN ('register', 'approve')),
    options_json    TEXT NOT NULL,
    description     TEXT NOT NULL,
    display_name    TEXT,
    callback_url    TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    consumed_at     TEXT,
    outcome         TEXT CHECK (outcome IN ('approved', 'denied', 'expired', 'cancelled')),
    response_json   TEXT,
    callback_status TEXT CHECK (callback_status IN ('pending', 'delivered', 'failed_max_retries'))
);

CREATE INDEX IF NOT EXISTS idx_ceremonies_expires
    ON ceremonies(expires_at, outcome);
CREATE INDEX IF NOT EXISTS idx_ceremonies_callback
    ON ceremonies(callback_status, consumed_at);
"""


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


@dataclass
class Ceremony:
    ceremony_id: str
    ceremony_type: str
    options_json: str
    description: str
    display_name: Optional[str]
    callback_url: str
    created_by: str
    created_at: str
    expires_at: str
    consumed_at: Optional[str] = None
    outcome: Optional[str] = None
    response_json: Optional[str] = None
    callback_status: Optional[str] = None

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> 'Ceremony':
        return cls(
            ceremony_id=row['ceremony_id'],
            ceremony_type=row['ceremony_type'],
            options_json=row['options_json'],
            description=row['description'],
            display_name=row['display_name'],
            callback_url=row['callback_url'],
            created_by=row['created_by'],
            created_at=row['created_at'],
            expires_at=row['expires_at'],
            consumed_at=row['consumed_at'],
            outcome=row['outcome'],
            response_json=row['response_json'],
            callback_status=row['callback_status'],
        )

    def is_expired(self) -> bool:
        return self.expires_at < _now_iso()

    def is_terminal(self) -> bool:
        return self.outcome is not None


class CeremonyStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        # WAL gives readers + a writer without blocking each other.
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA foreign_keys=ON')
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(_SCHEMA)

    # ---- writes ----------------------------------------------------------

    def create(self, *, ceremony_type: str, options_json: str,
               description: str, display_name: Optional[str],
               callback_url: str, created_by: str,
               ttl_seconds: int) -> Ceremony:
        if ceremony_type not in ('register', 'approve'):
            raise ValueError(
                f'ceremony_type must be "register" or "approve", '
                f'got {ceremony_type!r}')
        # Sanity-check options_json is parseable JSON. Don't inspect
        # the contents — the broker isn't supposed to understand
        # WebAuthn options.
        try:
            json.loads(options_json)
        except json.JSONDecodeError as e:
            raise ValueError(f'options_json must be valid JSON: {e}')
        if not description:
            raise ValueError('description must not be empty')
        if not callback_url.startswith(('https://', 'http://')):
            raise ValueError(f'callback_url must be http(s): {callback_url!r}')
        if ttl_seconds < 1 or ttl_seconds > 3600:
            raise ValueError(f'ttl_seconds out of range: {ttl_seconds}')

        cer = Ceremony(
            ceremony_id=str(uuid.uuid4()),
            ceremony_type=ceremony_type,
            options_json=options_json,
            description=description,
            display_name=display_name,
            callback_url=callback_url,
            created_by=created_by,
            created_at=_now_iso(),
            expires_at=_iso_plus(ttl_seconds),
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                'INSERT INTO ceremonies '
                '(ceremony_id, ceremony_type, options_json, description, '
                ' display_name, callback_url, created_by, created_at, '
                ' expires_at) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (cer.ceremony_id, cer.ceremony_type, cer.options_json,
                 cer.description, cer.display_name, cer.callback_url,
                 cer.created_by, cer.created_at, cer.expires_at))
        return cer

    def record_response(self, ceremony_id: str, *,
                        outcome: str, response_json: Optional[str]) -> bool:
        """Set the response + outcome on a ceremony. Idempotent — a
        second call with the same ceremony_id returns False without
        overwriting (so a replayed browser POST can't change the
        recorded outcome).

        Returns True if this call actually updated the row, False if
        it was already consumed."""
        if outcome not in ('approved', 'denied', 'expired', 'cancelled'):
            raise ValueError(f'bad outcome {outcome!r}')
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                'UPDATE ceremonies '
                '   SET outcome = ?, response_json = ?, '
                '       consumed_at = ?, callback_status = ? '
                ' WHERE ceremony_id = ? '
                '   AND outcome IS NULL',
                (outcome, response_json, _now_iso(),
                 'pending' if outcome in ('approved', 'denied') else None,
                 ceremony_id))
            return cur.rowcount == 1

    def mark_callback_delivered(self, ceremony_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                'UPDATE ceremonies SET callback_status = ? '
                'WHERE ceremony_id = ?',
                ('delivered', ceremony_id))

    def mark_callback_failed(self, ceremony_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                'UPDATE ceremonies SET callback_status = ? '
                'WHERE ceremony_id = ?',
                ('failed_max_retries', ceremony_id))

    def sweep_expired(self) -> list[Ceremony]:
        """Mark pending ceremonies past their expiry. Returns the
        ceremonies that were newly expired (callers can use this to
        schedule expiry callbacks)."""
        now = _now_iso()
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                'SELECT * FROM ceremonies '
                'WHERE outcome IS NULL AND expires_at < ?',
                (now,)).fetchall()
            for row in rows:
                conn.execute(
                    'UPDATE ceremonies '
                    '   SET outcome = ?, consumed_at = ?, '
                    '       callback_status = ? '
                    ' WHERE ceremony_id = ?',
                    ('expired', now, 'pending', row['ceremony_id']))
            return [Ceremony.from_row(r) for r in rows]

    # ---- reads -----------------------------------------------------------

    def get(self, ceremony_id: str) -> Optional[Ceremony]:
        with self._connect() as conn:
            row = conn.execute(
                'SELECT * FROM ceremonies WHERE ceremony_id = ?',
                (ceremony_id,)).fetchone()
            return Ceremony.from_row(row) if row else None

    def pending_callbacks(self) -> list[Ceremony]:
        """Ceremonies that have an outcome but no successful callback
        delivery yet. Used by the callback worker to find work."""
        with self._connect() as conn:
            rows = conn.execute(
                'SELECT * FROM ceremonies '
                'WHERE outcome IS NOT NULL AND callback_status = ? '
                'ORDER BY consumed_at',
                ('pending',)).fetchall()
            return [Ceremony.from_row(r) for r in rows]


def _iso_plus(seconds: int) -> str:
    return (_dt.datetime.now(_dt.timezone.utc)
            + _dt.timedelta(seconds=seconds)
            ).strftime('%Y-%m-%dT%H:%M:%SZ')
