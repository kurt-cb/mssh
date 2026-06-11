"""Unit tests for the per-connection inner-sshd machinery.

The full lifecycle (spawn / reap / cleanup) is exercised by the LXC
integration test in tests/lxc/. These tests cover the unit-level
helpers that are independently testable:

  - {LOCAL_*} marker substitution
  - port allocation with an exclude set

Process-spawn and sshd-binary tests live in the LXC suite where
there's a real openssh-server installed.

Tests: §5.3.11, §4.3.12
"""
from __future__ import annotations

import pytest

from mssh.msshd.inner import (
    InnerSshdError,
    _allocate_port_excluding,
    _substitute_local_markers,
)


# ---------------------------------------------------------------------------
# {LOCAL_*} marker substitution
# ---------------------------------------------------------------------------


def test_substitute_basic():
    out = _substitute_local_markers(
        'Port {LOCAL_PORT}\nHostKey {LOCAL_HOST_KEY}\n',
        {'LOCAL_PORT': '49152', 'LOCAL_HOST_KEY': '/var/lib/mssh/hk'})
    assert out == 'Port 49152\nHostKey /var/lib/mssh/hk\n'


def test_substitute_with_default_when_value_missing():
    out = _substitute_local_markers(
        'Banner {LOCAL_BANNER_FILE:/dev/null}\n',
        {})
    assert out == 'Banner /dev/null\n'


def test_substitute_value_wins_over_default():
    out = _substitute_local_markers(
        'Banner {LOCAL_BANNER_FILE:/dev/null}\n',
        {'LOCAL_BANNER_FILE': '/var/lib/mssh/banner'})
    assert out == 'Banner /var/lib/mssh/banner\n'


def test_substitute_leaves_unknown_markers_literal():
    """Marker not in values and no default → leave literal so the
    operator can see it in the per-session sshd_config tempdir."""
    out = _substitute_local_markers(
        'Foo {LOCAL_WHATEVER}\n', {})
    assert out == 'Foo {LOCAL_WHATEVER}\n'


def test_substitute_only_touches_local_namespace():
    """Substitutor must NOT touch {FROMCA_*} markers — those should
    have been resolved by the CA before this function runs. If we see
    one, it's a bug, but we should pass through unmodified rather than
    surprising the operator."""
    out = _substitute_local_markers(
        'Foo {FROMCA_FORCE_COMMAND}\nBar {LOCAL_PORT}\n',
        {'LOCAL_PORT': '49152',
         'FROMCA_FORCE_COMMAND': 'IGNORED'})        # should not apply
    assert '{FROMCA_FORCE_COMMAND}' in out
    assert 'Bar 49152' in out


def test_substitute_handles_multiline_directive_values():
    out = _substitute_local_markers(
        '{LOCAL_BLOCK}\n', {'LOCAL_BLOCK': 'X 1\nY 2'})
    assert out == 'X 1\nY 2\n'


# ---------------------------------------------------------------------------
# Port allocation
# ---------------------------------------------------------------------------


def test_port_allocator_returns_port_in_range():
    port = _allocate_port_excluding(49152, 49200, set())
    assert 49152 <= port <= 49200


def test_port_allocator_skips_excluded():
    """Ports in the exclude set must never be returned."""
    exclude = set(range(49152, 49200))
    port = _allocate_port_excluding(49152, 49250, exclude)
    assert port not in exclude
    assert port > 49199


def test_port_allocator_raises_when_range_exhausted():
    """If every candidate in the range is excluded, raise rather than
    quietly returning an in-use port."""
    exclude = set(range(49152, 49161))           # entire range excluded
    with pytest.raises(InnerSshdError, match='no free port'):
        _allocate_port_excluding(49152, 49160, exclude)
