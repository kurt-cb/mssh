"""Emergency-template support: CA-unreachable recovery for msshd.

When the CA is unreachable AND an emergency cert is configured AND
the operator has opted-in, msshd uses a *local* sshd_config template
(no CA-rendered config available) to spawn the per-session inner
sshd. The emergency cert's principals + extensions serve as the
inner-sshd OpenSSH cert input.

Two locations checked, in order:

1. ``/etc/mssh/sshd_config.emergency.template`` — operator override
2. ``/usr/share/mssh/sshd_config.emergency.template`` — shipped default
3. ``<repo>/config/sshd_config.emergency.template`` — dev fallback

The template uses only ``{LOCAL_*}`` markers — no CA-side
substitution because by definition the CA is unreachable on the
path that loads this file.

Startup validation: msshd renders the template against a synthetic
``{LOCAL_*}`` substitution set and runs ``sshd -t -f rendered`` to
catch syntax errors at boot rather than at break-glass time. If the
operator override fails the sanity check, msshd refuses to start
with a clear error pointing at the override file. (A broken shipped
default would block startup too — but that would be a packaging
bug, not an operator config error.)

Rate limiting: per ``design/security.md`` § emergency cert, the
emergency path is rate-limited at the host. v1 implements a simple
token bucket; full per-cert / fleet-wide rate-limit accounting
lives in a future iteration once we have audit-record correlation.

This module is the scaffolding; the actual integration into
``enforce_listener``'s authorize-deny branch (catch
``AuthorizationError`` → consult emergency mode → mint a local
OpenSSH user cert from the emergency X.509 cert → spawn the
per-session sshd) is the next piece, tracked in
``design/future-ideas.md``.
"""
from __future__ import annotations

import logging
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .inner import _sshd_config_test, _substitute_local_markers


log = logging.getLogger('msshd.emergency')


# Search order for the emergency template at msshd startup.
_OPERATOR_OVERRIDE = Path('/etc/mssh/sshd_config.emergency.template')
_SHIPPED_DEFAULT = Path('/usr/share/mssh/sshd_config.emergency.template')


def _dev_fallback() -> Path:
    """Repo-relative fallback so the path works in dev checkouts where
    the shipped default at /usr/share/mssh isn't installed yet."""
    here = Path(__file__).resolve()
    # python/src/mssh/msshd/emergency.py -> repo root is parents[4]
    return here.parents[4] / 'config' / 'sshd_config.emergency.template'


class EmergencyConfigError(RuntimeError):
    """Raised when the emergency-template config is broken at startup.

    msshd treats this as fatal: it refuses to start so the operator
    finds the bad override at boot, not during a real outage."""


@dataclass
class EmergencyConfig:
    """Resolved emergency-mode configuration.

    Constructed once at msshd startup via ``EmergencyConfig.load()``.
    Holds the validated template text and an inline rate limiter.
    """
    template_path: Path
    template_text: str
    # Token-bucket rate limit. Defaults match security.md
    # "minutes per use" guidance — 1 session / 60s, 5 burst.
    rate_per_minute: float = 1.0
    burst: int = 5
    _tokens: float = field(default=5.0, init=False)
    _last_refill: float = field(default=0.0, init=False)

    @classmethod
    async def load(cls, sshd_binary: str,
                   *,
                   rate_per_minute: float = 1.0,
                   burst: int = 5) -> 'EmergencyConfig':
        """Locate, load, and validate the emergency template.

        Validation runs ``sshd -t`` against a synthetic substitution
        so syntax errors surface at msshd startup, not during a real
        CA outage. Raises ``EmergencyConfigError`` on:

          - no template found anywhere
          - operator override unreadable
          - rendered template fails ``sshd -t``
        """
        path = cls._locate_template()
        if path is None:
            raise EmergencyConfigError(
                'no emergency template found at '
                f'{_OPERATOR_OVERRIDE}, {_SHIPPED_DEFAULT}, '
                f'or {_dev_fallback()}')
        try:
            text = path.read_text()
        except OSError as e:
            raise EmergencyConfigError(
                f'cannot read emergency template {path}: {e}') from e

        await cls._validate(path, text, sshd_binary)

        log.info('emergency template loaded from %s '
                 '(rate=%.2f/min, burst=%d)',
                 path, rate_per_minute, burst)
        cfg = cls(template_path=path, template_text=text,
                  rate_per_minute=rate_per_minute, burst=burst)
        cfg._tokens = float(burst)
        cfg._last_refill = time.monotonic()
        return cfg

    @staticmethod
    def _locate_template() -> Optional[Path]:
        for p in (_OPERATOR_OVERRIDE, _SHIPPED_DEFAULT, _dev_fallback()):
            if p.is_file():
                return p
        return None

    @staticmethod
    async def _validate(path: Path, text: str, sshd_binary: str) -> None:
        """Render against synthetic {LOCAL_*} values and run sshd -t.
        The validation only checks template syntax — the substituted
        paths are dummies that don't need to exist on disk."""
        with tempfile.TemporaryDirectory(prefix='mssh-emerg-validate-') as td:
            tdp = Path(td)
            host_key = tdp / 'host_key'
            user_ca = tdp / 'user_ca.pub'
            banner = tdp / 'banner'
            # Touch dummies — sshd -t will read these.
            host_key.write_text('')
            user_ca.write_text('')
            banner.write_text('')
            os.chmod(host_key, 0o0600)
            rendered = _substitute_local_markers(text, {
                'LOCAL_PORT':           '2222',
                'LOCAL_HOST_KEY':       str(host_key),
                'LOCAL_USER_CA_PUBKEY': str(user_ca),
                'LOCAL_BANNER_FILE':    str(banner),
            })
            cfg_path = tdp / 'sshd_config'
            cfg_path.write_text(rendered)
            os.chmod(cfg_path, 0o0600)
            ok, err = await _sshd_config_test(sshd_binary, cfg_path)
            if not ok:
                raise EmergencyConfigError(
                    f'emergency template {path} failed `sshd -t`: {err}')

    def render_for_session(self, local_paths: dict[str, str]) -> str:
        """Substitute ``{LOCAL_*}`` markers for a real session.

        ``local_paths`` keys are the markers without braces, e.g.
        ``LOCAL_PORT``. Caller is responsible for writing the result
        and re-running ``sshd -t`` if it wants per-session safety
        (already done by ``PerConnectionInnerSshd.acquire_session``).
        """
        return _substitute_local_markers(self.template_text, local_paths)

    def try_acquire(self) -> bool:
        """Token-bucket gate: returns True if the caller may proceed
        with an emergency-mode session, False if rate-limited.

        Caller is expected to deny the session (clean audit story:
        "rate-limited" not "authorized then failed") and log
        prominently."""
        now = time.monotonic()
        elapsed = max(0.0, now - self._last_refill)
        self._tokens = min(
            float(self.burst),
            self._tokens + elapsed * (self.rate_per_minute / 60.0))
        self._last_refill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False
