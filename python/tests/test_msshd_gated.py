"""Tests for the msshd gated-mode listener.

Tests: §1.4.2, §5.3.3, §13.8, §15.7
"""
from __future__ import annotations

import pytest

from mssh.msshd.config import (MODE_ENFORCE, MODE_FALLBACK, MODE_GATED,
                                MsshdConfig, VALID_MODES)


# Config-layer tests.

def test_gated_mode_is_a_valid_mode():
    """Verifies §1.4.2 — 'gated' is one of the three valid msshd modes."""
    assert MODE_GATED == 'gated'
    assert MODE_GATED in VALID_MODES


def test_gated_listener_importable():
    """Verifies §5.3.3 — GatedListener is exported and importable."""
    from mssh.msshd.gated_listener import GatedListener
    assert GatedListener is not None


def test_gated_mode_validate_requires_tls_material(tmp_path):
    """Verifies §5.3.3 + §13.9.7 — gated mode needs same TLS+CA fields as enforce."""
    cfg = MsshdConfig()
    cfg.mode = MODE_GATED
    cfg.fallback.host = '127.0.0.1'
    cfg.fallback.port = 22022
    # No TLS material set → must raise.
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert 'tls' in str(exc.value).lower() or 'server_cert' in str(exc.value)


def test_gated_mode_validate_requires_fallback_port(tmp_path):
    """Verifies §5.3.3 — gated mode requires a valid upstream port."""
    cfg = MsshdConfig()
    cfg.mode = MODE_GATED
    cfg.fallback.port = 0          # invalid
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert 'fallback' in str(exc.value).lower() or 'upstream' in str(exc.value).lower()


def test_gated_mode_validate_does_not_require_inner_sshd_or_users(tmp_path):
    """Verifies §5.3.3 — gated mode skips inner sshd + users.allowed checks
    that enforce mode applies. The operator's existing sshd is the auth
    endpoint, so msshd doesn't run an inner sshd or check users.allowed.
    """
    # Make a valid gated config — needs TLS + CA paths to exist.
    for fname in ('cert.pem', 'key.pem', 'pub.pem'):
        (tmp_path / fname).write_text('-stub-')

    cfg = MsshdConfig()
    cfg.mode = MODE_GATED
    cfg.fallback.host = '127.0.0.1'
    cfg.fallback.port = 22022
    cfg.listen.external_port = 22
    cfg.tls.server_cert = str(tmp_path / 'cert.pem')
    cfg.tls.server_key = str(tmp_path / 'key.pem')
    cfg.tls.user_ca_pubkey = str(tmp_path / 'pub.pem')
    cfg.ca.endpoints = ['https://ca:4443']
    cfg.ca.client_cert = str(tmp_path / 'cert.pem')
    cfg.ca.client_key = str(tmp_path / 'key.pem')
    cfg.ca.ca_pubkey = str(tmp_path / 'pub.pem')
    # users.allowed left empty, inner.port_range left at defaults —
    # neither should cause validate() to fail for gated.
    cfg.validate()           # no raise


def test_gated_mode_load_from_yaml(tmp_path):
    """Verifies §14.3.1 — `mode: gated` in YAML loads correctly."""
    cfg_path = tmp_path / 'msshd.yaml'
    cfg_path.write_text(
        'mode: gated\n'
        'fallback: {host: 127.0.0.1, port: 22022}\n'
        'listen: {external_port: 22}\n'
        'tls: {server_cert: a, server_key: b, user_ca_pubkey: c}\n'
        'ca: {endpoints: [https://ca:4443], '
        'client_cert: a, client_key: b, ca_pubkey: c}\n'
    )
    cfg = MsshdConfig.load(cfg_path)
    assert cfg.mode == MODE_GATED
    assert cfg.fallback.port == 22022


def test_gated_mode_dispatch_path_exists():
    """Verifies §5.3.1 — msshd.py routes gated mode to _run_gated.

    Importing the dispatcher should succeed without running it. The
    presence of `_run_gated` proves the mode is wired in.
    """
    from mssh.msshd import msshd as _entry
    assert hasattr(_entry, '_run_gated'), \
        'msshd.msshd._run_gated must exist for gated dispatch'
