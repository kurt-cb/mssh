"""Expiry sweeper.

Background thread that periodically marks pending ceremonies past
their TTL as ``expired`` and schedules callback delivery so the
back-end client learns about the timeout.
"""

from __future__ import annotations

import logging
import threading

from .storage import CeremonyStore

log = logging.getLogger('mssh_passkey.sweeper')


class ExpirySweeper(threading.Thread):
    def __init__(self, store: CeremonyStore, interval_seconds: int = 30,
                 name: str = 'mssh-passkey-sweep'):
        super().__init__(name=name, daemon=True)
        self.store = store
        self.interval = interval_seconds
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                expired = self.store.sweep_expired()
                if expired:
                    log.info('expired %d pending ceremonies', len(expired))
            except Exception as e:
                log.error('sweep failed: %s', e)
            self._stop.wait(self.interval)
