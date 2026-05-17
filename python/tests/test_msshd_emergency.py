"""Unit tests for the emergency-template machinery.

Covers the parts that don't need a real ``sshd`` binary:

  - template location precedence (operator override > shipped > dev)
  - render_for_session substitution
  - rate-limiter (token bucket) behavior
  - EmergencyConfigError surfaces a useful message when nothing is found

The ``sshd -t`` validation gate is exercised by the LXC integration
suite, which has openssh-server installed.
"""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest import mock

import pytest

from mssh.msshd import emergency as em


# ---------------------------------------------------------------------------
# template location
# ---------------------------------------------------------------------------


def test_locate_template_dev_fallback_exists():
    """The shipped dev fallback at config/sshd_config.emergency.template
    must exist in the repo — that's the file installers ship to
    /usr/share/mssh/."""
    p = em._dev_fallback()
    assert p.is_file(), f'missing shipped dev fallback at {p}'


def test_locate_template_returns_none_when_all_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(em, '_OPERATOR_OVERRIDE', tmp_path / 'a')
    monkeypatch.setattr(em, '_SHIPPED_DEFAULT', tmp_path / 'b')
    monkeypatch.setattr(em, '_dev_fallback', lambda: tmp_path / 'c')
    assert em.EmergencyConfig._locate_template() is None


def test_locate_template_prefers_operator_override(tmp_path, monkeypatch):
    override = tmp_path / 'op.tmpl'
    shipped = tmp_path / 'ship.tmpl'
    override.write_text('op')
    shipped.write_text('ship')
    monkeypatch.setattr(em, '_OPERATOR_OVERRIDE', override)
    monkeypatch.setattr(em, '_SHIPPED_DEFAULT', shipped)
    monkeypatch.setattr(em, '_dev_fallback', lambda: tmp_path / 'nope')
    assert em.EmergencyConfig._locate_template() == override


def test_locate_template_falls_through_to_shipped(tmp_path, monkeypatch):
    shipped = tmp_path / 'ship.tmpl'
    shipped.write_text('ship')
    monkeypatch.setattr(em, '_OPERATOR_OVERRIDE', tmp_path / 'missing')
    monkeypatch.setattr(em, '_SHIPPED_DEFAULT', shipped)
    monkeypatch.setattr(em, '_dev_fallback', lambda: tmp_path / 'nope')
    assert em.EmergencyConfig._locate_template() == shipped


# ---------------------------------------------------------------------------
# load() — error paths (validate() is mocked; the real sshd -t check
# is covered by the LXC suite)
# ---------------------------------------------------------------------------


def _make_cfg(template_text: str = 'Port {LOCAL_PORT}\n') -> em.EmergencyConfig:
    """Build an EmergencyConfig directly, skipping the disk + sshd
    bootstrap — convenient for the unit tests that exercise the
    render / rate-limit surface."""
    return em.EmergencyConfig(
        template_path=Path('/dev/null'),
        template_text=template_text,
        rate_per_minute=60.0,        # 1/sec for fast tests
        burst=3,
    )


def test_load_raises_when_no_template_anywhere(tmp_path, monkeypatch):
    monkeypatch.setattr(em, '_OPERATOR_OVERRIDE', tmp_path / 'a')
    monkeypatch.setattr(em, '_SHIPPED_DEFAULT', tmp_path / 'b')
    monkeypatch.setattr(em, '_dev_fallback', lambda: tmp_path / 'c')
    with pytest.raises(em.EmergencyConfigError, match='no emergency template'):
        asyncio.run(em.EmergencyConfig.load(sshd_binary='/usr/sbin/sshd'))


def test_load_raises_when_validate_fails(tmp_path, monkeypatch):
    override = tmp_path / 'broken.tmpl'
    override.write_text('this is not valid sshd config\n')
    monkeypatch.setattr(em, '_OPERATOR_OVERRIDE', override)
    monkeypatch.setattr(em, '_SHIPPED_DEFAULT', tmp_path / 'nope1')
    monkeypatch.setattr(em, '_dev_fallback', lambda: tmp_path / 'nope2')

    async def fake_test(binary, cfg_path):
        return False, 'fake sshd -t failure'

    monkeypatch.setattr(em, '_sshd_config_test', fake_test)
    with pytest.raises(em.EmergencyConfigError,
                       match='failed `sshd -t`'):
        asyncio.run(em.EmergencyConfig.load(sshd_binary='/usr/sbin/sshd'))


def test_load_succeeds_with_passing_validation(tmp_path, monkeypatch):
    override = tmp_path / 'ok.tmpl'
    override.write_text('Port {LOCAL_PORT}\n')
    monkeypatch.setattr(em, '_OPERATOR_OVERRIDE', override)
    monkeypatch.setattr(em, '_SHIPPED_DEFAULT', tmp_path / 'nope1')
    monkeypatch.setattr(em, '_dev_fallback', lambda: tmp_path / 'nope2')

    async def fake_test(binary, cfg_path):
        return True, ''

    monkeypatch.setattr(em, '_sshd_config_test', fake_test)
    cfg = asyncio.run(em.EmergencyConfig.load(
        sshd_binary='/usr/sbin/sshd', rate_per_minute=2.0, burst=4))
    assert cfg.template_path == override
    assert cfg.rate_per_minute == 2.0
    assert cfg.burst == 4
    assert cfg._tokens == 4.0


# ---------------------------------------------------------------------------
# render_for_session
# ---------------------------------------------------------------------------


def test_render_substitutes_local_markers():
    cfg = _make_cfg('Port {LOCAL_PORT}\nHostKey {LOCAL_HOST_KEY}\n')
    out = cfg.render_for_session({
        'LOCAL_PORT': '49152',
        'LOCAL_HOST_KEY': '/var/lib/mssh/hk',
    })
    assert out == 'Port 49152\nHostKey /var/lib/mssh/hk\n'


def test_render_leaves_unknown_markers_alone():
    # Per _substitute_local_markers: unknown markers pass through.
    # That's a load-time concern, not a per-session one; the startup
    # validator catches it.
    cfg = _make_cfg('Banner {LOCAL_UNRECOGNIZED}\n')
    out = cfg.render_for_session({})
    assert out == 'Banner {LOCAL_UNRECOGNIZED}\n'


# ---------------------------------------------------------------------------
# rate limiter
# ---------------------------------------------------------------------------


def test_rate_limit_burst_then_blocks():
    cfg = _make_cfg()
    # burst=3 — three immediate acquires succeed.
    assert cfg.try_acquire() is True
    assert cfg.try_acquire() is True
    assert cfg.try_acquire() is True
    # Fourth is rate-limited.
    assert cfg.try_acquire() is False


def test_rate_limit_refills_over_time(monkeypatch):
    cfg = _make_cfg()
    # Drain.
    for _ in range(cfg.burst):
        cfg.try_acquire()
    assert cfg.try_acquire() is False

    # Fast-forward time so the bucket refills (1/sec).
    real = time.monotonic()
    monkeypatch.setattr(time, 'monotonic', lambda: real + 2.0)
    assert cfg.try_acquire() is True
    # And again 2 seconds later.
    monkeypatch.setattr(time, 'monotonic', lambda: real + 4.0)
    assert cfg.try_acquire() is True


def test_rate_limit_caps_at_burst(monkeypatch):
    cfg = _make_cfg()
    # Drain, then jump forward a long time. Refill should cap at burst,
    # not accumulate unbounded.
    for _ in range(cfg.burst):
        cfg.try_acquire()
    real = time.monotonic()
    monkeypatch.setattr(time, 'monotonic', lambda: real + 10_000.0)
    succeeded = 0
    for _ in range(20):
        if cfg.try_acquire():
            succeeded += 1
        else:
            break
    assert succeeded == cfg.burst
