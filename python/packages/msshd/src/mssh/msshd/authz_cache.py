"""Authorization cache for msshd.

msshd consults this cache **first** on every connection. On hit, no
CA call. On miss, msshd calls the CA; if the CA grants, the result is
stored here for future hits. If the CA denies, the cache entry for
that principal is invalidated. If the CA is unreachable AND the cache
miss has no entry, the connection is denied.

Two sources of cache entries, tagged on the entry itself:

  - ``'ca'``     — populated by a successful live CA call.
  - ``'bypass'`` — populated by an operator-presented bypass cert
                   (an X.509 authz cert with the mssh-ca-bypass
                   critical extension). The bypass-injection code
                   path in ``enforce_listener`` stores entries with
                   this tag.

Source-tag policy (per design/notes-bypass-cache.md):

  - Lookups don't care about source. Any non-expired entry is a hit.
  - CA deny invalidates ALL entries for the principal regardless of
    source. CA is the oracle when reachable. Admin re-injects bypass
    if they still need it.
  - Persistence: on-disk JSON, mode 0600. Lazy expiry on load.
  - Eviction-on-capacity is NOT implemented (acknowledged design
    hole; TODO outside the scope of bypass-cert work).

This module has no I/O dependencies beyond the filesystem and is
synchronous — all calls are fast in-memory operations plus an
atomic disk write on mutations. Concurrency is single-thread by
construction (msshd is asyncio-on-one-thread).
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .ca import AuthorizationGrant


log = logging.getLogger('msshd.authz_cache')


SOURCE_CA = 'ca'
SOURCE_BYPASS = 'bypass'
_VALID_SOURCES = (SOURCE_CA, SOURCE_BYPASS)


@dataclass
class CachedGrant:
    """A grant in the authz cache, plus its provenance.

    Composes the ``AuthorizationGrant`` dataclass — the wire-level
    grant is unchanged — and adds ``source`` (provenance tag) and
    ``injected_at`` (operator-visible timestamp).
    """
    principal: str
    grant: AuthorizationGrant
    source: str                          # 'ca' or 'bypass'
    injected_at: _dt.datetime

    def is_expired(self, now: _dt.datetime | None = None) -> bool:
        now = now or _now()
        return self.grant.not_after <= now


class AuthzCache:
    """Source-tagged authz cache with optional on-disk persistence.

    Construct once at msshd startup, hand to ``EnforceListener``.
    Thread-safe under the asyncio single-thread assumption.
    """

    def __init__(self, persist_path: str | Path | None = None, *,
                 max_per_principal: int = 0,
                 max_total: int = 0):
        """``persist_path`` enables on-disk persistence. ``None`` =
        in-memory only (useful for tests). The file is created with
        mode 0600 on first write.

        ``max_per_principal`` and ``max_total`` are eviction caps
        (FIFO by injected_at). 0 disables that level entirely. See
        design/notes-bypass-cache.md "Eviction Amendment".

        - max_per_principal: cap on entries with the same principal
          key. Today the cache is principal-keyed (one entry per
          principal); the cap is structurally enforced at 1, so this
          knob is forward-compat for a multi-key cache. Setting it
          > 0 has no observable effect today.
        - max_total: global cap. On put() that would exceed the cap,
          the globally-oldest entry is evicted first.
        """
        self._entries: dict[str, CachedGrant] = {}
        # Last applied CRL sequence number (sequence-based revocation
        # log — see ca/crl.py). 0 = "nothing applied yet". Persisted
        # alongside the cache entries.
        self.last_crl_seq: int = 0
        self.max_per_principal = int(max_per_principal)
        self.max_total = int(max_total)
        self._persist_path: Optional[Path] = (
            Path(persist_path) if persist_path else None)
        if self._persist_path is not None:
            self._load()

    # ----------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------

    def get(self, principal: str) -> Optional[CachedGrant]:
        """Return a non-expired cached grant for ``principal`` or
        ``None``. Expired entries are evicted on access."""
        entry = self._entries.get(principal)
        if entry is None:
            return None
        if entry.is_expired():
            log.info('authz_cache: evicting expired entry for %s '
                     '(source=%s, expired_at=%s)',
                     principal, entry.source, entry.grant.not_after)
            del self._entries[principal]
            self._persist()
            return None
        return entry

    def put(self, principal: str, grant: AuthorizationGrant,
            *, source: str) -> CachedGrant:
        """Insert or replace the entry for ``principal``. ``source``
        must be ``'ca'`` or ``'bypass'``."""
        if source not in _VALID_SOURCES:
            raise ValueError(
                f'source must be one of {_VALID_SOURCES}, got {source!r}')
        entry = CachedGrant(principal=principal, grant=grant,
                            source=source, injected_at=_now())
        prev = self._entries.get(principal)
        self._entries[principal] = entry
        # Eviction caps (no-op if both are 0). Per-principal first,
        # then global. The per-principal cap is structurally enforced
        # at 1 today by the dict-keyed-by-principal layout, so it's a
        # forward-compat knob — meaningful only if/when the cache key
        # broadens. The global cap is the operative control today.
        self._enforce_caps()
        self._persist()
        if prev is None:
            log.info('authz_cache: stored grant for %s '
                     '(source=%s, not_after=%s)',
                     principal, source, grant.not_after)
        else:
            log.info('authz_cache: replaced grant for %s '
                     '(prev source=%s, new source=%s)',
                     principal, prev.source, source)
        return entry

    def _enforce_caps(self) -> None:
        """Apply per-principal then global caps. FIFO by injected_at.
        Called from put(); no-op if both caps are 0."""
        # Per-principal cap. With today's dict-keyed-by-principal
        # layout, every principal has exactly one entry — the loop
        # below is a no-op until the cache key broadens. The shape
        # is in place so that a future multi-key cache doesn't have
        # to re-derive this policy.
        if self.max_per_principal > 0:
            by_p: dict[str, list[CachedGrant]] = {}
            for e in self._entries.values():
                by_p.setdefault(e.principal, []).append(e)
            for principal, group in by_p.items():
                if len(group) > self.max_per_principal:
                    group.sort(key=lambda e: e.injected_at)
                    to_evict = group[:len(group) - self.max_per_principal]
                    for victim in to_evict:
                        log.warning(
                            'authz_cache: per-principal cap '
                            'reached for %s (%d > %d) — evicting '
                            'oldest entry (injected_at=%s, '
                            'source=%s)',
                            principal, len(group),
                            self.max_per_principal,
                            victim.injected_at, victim.source)
                        # In today's dict-keyed-by-principal layout
                        # this code path is unreachable. Future
                        # multi-key cache would index differently.
                        if (cur := self._entries.get(victim.principal)) \
                                is not None and cur is victim:
                            del self._entries[victim.principal]

        # Global cap. Evict globally-oldest until at-or-under the cap.
        if self.max_total > 0:
            while len(self._entries) > self.max_total:
                victim = min(self._entries.values(),
                             key=lambda e: e.injected_at)
                log.warning(
                    'authz_cache: global cap reached (%d > %d) — '
                    'evicting oldest entry (principal=%s, '
                    'injected_at=%s, source=%s)',
                    len(self._entries), self.max_total,
                    victim.principal, victim.injected_at,
                    victim.source)
                del self._entries[victim.principal]

    def invalidate(self, principal: str) -> bool:
        """Drop the entry for ``principal``. Returns True if anything
        was removed.

        CA-deny path calls this regardless of the entry's source —
        when the CA is reachable, it is the oracle of truth and
        revocation overrides any pre-cached grant (including bypass).
        Operator can re-inject afterward if needed."""
        if principal in self._entries:
            prev = self._entries.pop(principal)
            self._persist()
            log.info('authz_cache: invalidated entry for %s (source=%s)',
                     principal, prev.source)
            return True
        return False

    def invalidate_by_serial(self, serial: str) -> int:
        """Drop any cache entry whose grant has the given cert
        ``serial``. Returns the number of entries removed (0 or 1
        in practice; structured as a count for safety).

        Used by CRL apply to remove revoked entries. The CA sends
        ``serials`` in CRL entries; msshd iterates the cache (which
        is small) and drops matches. Source-tag-agnostic: a revoked
        bypass cert is dropped exactly the same as a revoked CA-grant.
        """
        serial = serial.strip().lower()
        if not serial:
            return 0
        dropped: list[str] = []
        for p, e in list(self._entries.items()):
            if e.grant.serial.lower() == serial:
                dropped.append(p)
        for p in dropped:
            del self._entries[p]
        if dropped:
            self._persist()
            log.info('authz_cache: invalidated by serial=%s '
                     '(principals=%s)', serial, dropped)
        return len(dropped)

    def set_last_crl_seq(self, seq: int) -> None:
        """Update the highest-applied CRL sequence and persist."""
        if seq <= self.last_crl_seq:
            return
        self.last_crl_seq = int(seq)
        self._persist()

    def list_all(self) -> list[CachedGrant]:
        """All non-expired entries, for diagnostic / admin tooling.
        Filters out expired entries lazily as a side effect."""
        now = _now()
        keep, drop = [], []
        for p, e in self._entries.items():
            (drop if e.is_expired(now) else keep).append((p, e))
        for p, _ in drop:
            del self._entries[p]
        if drop:
            self._persist()
        return [e for _, e in keep]

    # ----------------------------------------------------------------
    # On-disk persistence
    # ----------------------------------------------------------------

    def _persist(self) -> None:
        if self._persist_path is None:
            return
        body = {
            'version': 1,
            'last_crl_seq': self.last_crl_seq,
            'entries': [
                {
                    'principal':    e.principal,
                    'cert_der_b64': base64.b64encode(e.grant.cert_der).decode('ascii'),
                    'serial':       e.grant.serial,
                    'not_after':    e.grant.not_after.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'inner_sshd_config': e.grant.inner_sshd_config,
                    'protocol_version':  e.grant.protocol_version,
                    'source':       e.source,
                    'injected_at':  e.injected_at.strftime('%Y-%m-%dT%H:%M:%SZ'),
                }
                for e in self._entries.values()
            ],
        }
        # Atomic write: temp file in same dir, then rename. Mode 0600
        # set on the temp file before rename so the cache file is never
        # world-readable even transiently.
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self._persist_path.parent, 0o0700) if not self._persist_path.parent.exists() else None
        with tempfile.NamedTemporaryFile(
                mode='w', dir=self._persist_path.parent,
                prefix='.authz_cache.', suffix='.tmp',
                delete=False) as tmp:
            json.dump(body, tmp, indent=2, sort_keys=True)
            tmp_path = Path(tmp.name)
        os.chmod(tmp_path, 0o0600)
        os.replace(tmp_path, self._persist_path)

    def _load(self) -> None:
        if self._persist_path is None or not self._persist_path.exists():
            return
        try:
            body = json.loads(self._persist_path.read_text())
        except (OSError, json.JSONDecodeError) as e:
            log.warning('authz_cache: failed to load %s, starting empty: %s',
                        self._persist_path, e)
            return
        if not isinstance(body, dict) or body.get('version') != 1:
            log.warning('authz_cache: unexpected on-disk format at %s, '
                        'starting empty', self._persist_path)
            return
        try:
            self.last_crl_seq = int(body.get('last_crl_seq') or 0)
        except (TypeError, ValueError):
            self.last_crl_seq = 0
        loaded, skipped = 0, 0
        now = _now()
        for raw in body.get('entries', []):
            try:
                grant = AuthorizationGrant(
                    cert_der=base64.b64decode(raw['cert_der_b64']),
                    serial=str(raw.get('serial') or ''),
                    not_after=_parse_iso(raw['not_after']),
                    inner_sshd_config=str(raw.get('inner_sshd_config') or ''),
                    protocol_version=str(raw.get('protocol_version') or ''),
                )
                source = str(raw.get('source') or '')
                if source not in _VALID_SOURCES:
                    skipped += 1
                    continue
                entry = CachedGrant(
                    principal=str(raw['principal']),
                    grant=grant,
                    source=source,
                    injected_at=_parse_iso(raw['injected_at']),
                )
                if entry.is_expired(now):
                    skipped += 1
                    continue
                self._entries[entry.principal] = entry
                loaded += 1
            except (KeyError, ValueError, TypeError) as e:
                log.warning('authz_cache: skipping malformed entry: %s', e)
                skipped += 1
        log.info('authz_cache: loaded %d entries from %s (%d skipped)',
                 loaded, self._persist_path, skipped)


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _parse_iso(s: str) -> _dt.datetime:
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    return _dt.datetime.fromisoformat(s)
