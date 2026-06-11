"""CRL sync — fetch new CRL entries and apply them to the authz cache.

Sequence-based revocation channel (see ``ca/crl.py``). The CA's
authorize response carries ``current_crl_seq``; msshd persists the
``last_crl_seq`` it has applied. When ``current > last`` the sync
loop fetches CRLs in pages via ``GET /v1/crl?after=N&limit=K`` and
applies each entry's revoked serials to the authz cache.

Design notes for this module:

  - Sync runs in the background — the connection that triggered it
    does not block on the fetch. (Strict-mode gating is implemented
    one level up in enforce_listener: if the gap exceeds a
    threshold, the listener refuses cache hits until sync catches
    up. The gate itself is a synchronous check, not a wait.)
  - Re-entrancy: a sync task running for a given (cache, ca_client)
    tuple holds an asyncio lock so concurrent triggers coalesce.
  - On any CA failure mid-sync, the loop stops and returns the
    highest seq it applied. Next authorize call will retrigger.

This is the "lenient" half of the dual lenient/strict policy:
the SYNC is best-effort; the GATE (in enforce_listener) is strict.

Design: §5.3.8 + §5.3.9 (see design/mssh_design_v1.md) — CRL sync
(per-issuer page fetch + serial invalidation) and the strict-mode
gate that forces live CA calls when the cache is far behind. See
§13.3 for the cross-cutting revocation story.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from .authz_cache import AuthzCache
from .ca import MsshdCAClient


log = logging.getLogger('msshd.crl_sync')


class CRLSync:
    """Owns the background sync coroutine and its concurrency gate.

    Construct one per msshd process. Call ``maybe_sync(current_seq)``
    from the authorize-response path whenever a fresh CA response
    arrives; this returns immediately and schedules background work
    if a sync is needed.
    """

    def __init__(self, cache: AuthzCache, ca_client: MsshdCAClient, *,
                 fetch_limit: int = 100):
        self._cache = cache
        self._ca = ca_client
        self._fetch_limit = int(fetch_limit)
        # Only one sync task at a time. Concurrent triggers wait
        # on this lock briefly then return — the running task is
        # already going to fetch up to current.
        self._lock = asyncio.Lock()
        self._running: Optional[asyncio.Task] = None

    def maybe_sync(self, current_crl_seqs: dict[str, int] | int) -> None:
        # §5.3.8 background-sync trigger: schedule if any issuer is
        # behind. Non-blocking; safe in the hot authorize path.
        """Schedule a background sync if msshd is behind on ANY
        issuer. Cheap and non-blocking; safe to call from the hot
        authorize path.

        Accepts either the new per-issuer ``current_crl_seqs`` map or
        the legacy singular int (treated as user-mint's value)."""
        seqs = self._coerce_seqs(current_crl_seqs)
        if not self._needs_sync(seqs):
            return
        if self._running is not None and not self._running.done():
            return                              # already syncing
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            log.warning('crl_sync: no running loop, skipping')
            return
        self._running = loop.create_task(
            self._sync(seqs), name='crl-sync')

    async def sync_now(self,
                       current_crl_seqs: dict[str, int] | int) -> dict[str, int]:
        """Synchronous variant — caller awaits completion. Returns the
        new last_crl_seqs map. Used by tests and by enforce_listener's
        strict-mode catch-up. Holds the lock so concurrent calls
        serialize."""
        seqs = self._coerce_seqs(current_crl_seqs)
        async with self._lock:
            return await self._do_sync(seqs)

    @staticmethod
    def _coerce_seqs(v) -> dict[str, int]:
        """Accept either a dict or a singular int (legacy)."""
        if isinstance(v, dict):
            return {str(k): int(s) for k, s in v.items()}
        return {'user-mint': int(v or 0)}

    def _needs_sync(self, current_seqs: dict[str, int]) -> bool:
        for issuer, current in current_seqs.items():
            if current > self._cache.last_crl_seqs.get(issuer, 0):
                return True
        return False

    async def _sync(self, current_seqs: dict[str, int]) -> None:
        async with self._lock:
            try:
                await self._do_sync(current_seqs)
            except Exception:                   # noqa: BLE001
                log.exception('crl_sync: background sync raised')

    async def _do_sync(self,
                       current_seqs: dict[str, int]) -> dict[str, int]:
        # §5.3.8 per-issuer sync loop driver (§13.3 revocation story).
        """Iterate over each stale issuer and apply its missing
        entries to the authz cache. Returns the new last_crl_seqs."""
        for issuer, current in current_seqs.items():
            if current > self._cache.last_crl_seqs.get(issuer, 0):
                await self._do_sync_issuer(issuer, current)
        return dict(self._cache.last_crl_seqs)

    async def _do_sync_issuer(self, issuer: str, current: int) -> int:
        # §5.3.8 per-issuer CRL sync: page-fetch, invalidate-by-serial,
        # persist last_crl_seqs after each page.
        """Fetch + apply loop for ONE issuer. Returns the new
        last-applied seq for that issuer."""
        start = self._cache.last_crl_seqs.get(issuer, 0)
        applied_through = start

        while applied_through < current:
            try:
                resp = await self._ca.fetch_crl(
                    after=applied_through, limit=self._fetch_limit,
                    issuer=issuer)
            except Exception as e:              # noqa: BLE001
                log.warning('crl_sync[%s]: fetch failed at after=%d: %s',
                            issuer, applied_through, e)
                break

            entries = resp.get('entries') or []
            if not entries:
                # CA says current_seq was M but returned nothing —
                # log silently moved or the CA reset. Bump to
                # whatever the CA reports as current to stop looping.
                ca_current = int(resp.get('current_seq') or 0)
                if ca_current > applied_through:
                    self._cache.set_last_crl_seq(ca_current, issuer=issuer)
                    applied_through = ca_current
                break

            for entry in entries:
                seq = int(entry.get('seq') or 0)
                if seq <= applied_through:
                    continue                    # defensive
                serials = entry.get('serials') or []
                total = 0
                for serial in serials:
                    total += self._cache.invalidate_by_serial(serial)
                if total:
                    log.info('crl_sync[%s]: applied seq=%d, invalidated '
                             '%d cache entries (serials=%s)',
                             issuer, seq, total, serials)
                applied_through = seq

            # Persist after each page so a crash mid-loop doesn't
            # re-fetch already-applied entries.
            self._cache.set_last_crl_seq(applied_through, issuer=issuer)

        if applied_through > start:
            log.info('crl_sync[%s]: caught up from seq=%d to seq=%d',
                     issuer, start, applied_through)
        return applied_through

    def is_running(self) -> bool:
        return self._running is not None and not self._running.done()
