"""Callback delivery worker.

Posts ceremony outcomes to the back-end client's callback_url over
mTLS. Uses the configured client cert + CA-trust pair to do full
cert validation in both directions.

Retry schedule (cumulative wall-clock):
   attempt 1 — immediately on outcome
   attempt 2 — +5s
   attempt 3 — +30s
   attempt 4 — +2m
   attempt 5 — +10m
After 5 failed attempts, the ceremony's callback_status is set to
``failed_max_retries`` and the worker stops trying. Operators
investigate via the broker's pending-callback view.

Design: §8.3.4 callback delivery worker (see design/mssh_design_v1.md).
Retry schedule: §8.3.4 / §14.3.4 callback.retry_schedule_seconds
[0, 5, 30, 120, 600] s.
Hardening: §13.9.1 anti-bogus-callback / anti-compromised-broker
defenses are receiver-side; this worker is a relay.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Optional

import requests

from .config import CallbackConfig
from .storage import Ceremony, CeremonyStore

log = logging.getLogger('mssh_passkey.callback')

# §8.3.4 retry schedule [0,5,30,120,600]s
_BACKOFF_SECONDS = (0, 5, 30, 120, 600)


def _payload(cer: Ceremony) -> dict:
    return {
        'ceremony_id': cer.ceremony_id,
        'type': cer.ceremony_type,
        'outcome': cer.outcome,
        'consumed_at': cer.consumed_at,
        'response_json': cer.response_json,
    }


def _deliver(cer: Ceremony, cbk: CallbackConfig) -> bool:
    """Single POST attempt. Returns True on 2xx response."""
    try:
        resp = requests.post(
            cer.callback_url,
            json=_payload(cer),
            cert=((cbk.client_cert, cbk.client_key)
                  if cbk.client_cert and cbk.client_key else None),
            verify=cbk.ca_cert if cbk.ca_cert else True,
            timeout=10.0,
        )
    except requests.RequestException as e:
        log.warning('callback POST %s failed: %s', cer.callback_url, e)
        return False
    if 200 <= resp.status_code < 300:
        return True
    log.warning('callback POST %s returned %d', cer.callback_url,
                resp.status_code)
    return False


def deliver_with_retry(cer: Ceremony, store: CeremonyStore,
                       cbk: CallbackConfig) -> None:
    """Run the retry schedule for one ceremony."""
    # §8.3.4 retry schedule [0,5,30,120,600]s
    for delay in _BACKOFF_SECONDS:
        if delay:
            time.sleep(delay)
        # Re-fetch: maybe an operator cancelled mid-retry. If the
        # ceremony's outcome changed to something the callback
        # consumer wouldn't expect, we still ship the latest state.
        latest = store.get(cer.ceremony_id) or cer
        if _deliver(latest, cbk):
            store.mark_callback_delivered(latest.ceremony_id)
            log.info('callback delivered for ceremony %s',
                     latest.ceremony_id)
            return
    store.mark_callback_failed(cer.ceremony_id)
    log.error('callback delivery FAILED after %d attempts for ceremony %s',
              len(_BACKOFF_SECONDS), cer.ceremony_id)


class CallbackWorker(threading.Thread):
    """Daemon thread that polls the store and dispatches per-ceremony
    delivery threads."""

    def __init__(self, store: CeremonyStore, cbk: CallbackConfig,
                 poll_interval: float = 1.0, name: str = 'mssh-passkey-cb'):
        super().__init__(name=name, daemon=True)
        self.store = store
        self.cbk = cbk
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        # Track which ceremonies have a delivery thread in-flight so
        # we don't dispatch the same one twice.
        self._in_flight: set[str] = set()
        self._lock = threading.Lock()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                pending = self.store.pending_callbacks()
            except Exception as e:
                log.error('callback poll failed: %s', e)
                self._stop.wait(self.poll_interval)
                continue
            for cer in pending:
                with self._lock:
                    if cer.ceremony_id in self._in_flight:
                        continue
                    self._in_flight.add(cer.ceremony_id)
                threading.Thread(
                    target=self._deliver_and_release,
                    args=(cer,),
                    name=f'cb-{cer.ceremony_id[:8]}',
                    daemon=True).start()
            self._stop.wait(self.poll_interval)

    def _deliver_and_release(self, cer: Ceremony) -> None:
        try:
            deliver_with_retry(cer, self.store, self.cbk)
        finally:
            with self._lock:
                self._in_flight.discard(cer.ceremony_id)
