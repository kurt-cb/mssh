"""R-9 default-deny tests for mssh-ca's CAConfig.validate().

Tests: §13.9.7, §14.3.2
"""
from __future__ import annotations

import pytest

from mssh.ca.config import CAConfig


def _good_cfg(tmp_path) -> CAConfig:
    """A CAConfig with all R-9 required fields populated + existing files."""
    sk = tmp_path / 'signing-key.pem'; sk.write_text('-key-')
    sc = tmp_path / 'signing-cert.pem'; sc.write_text('-cert-')
    tc = tmp_path / 'tls-cert.pem'; tc.write_text('-cert-')
    tk = tmp_path / 'tls-key.pem'; tk.write_text('-key-')
    cca = tmp_path / 'client-ca-cert.pem'; cca.write_text('-cert-')
    return CAConfig(
        listen_host='127.0.0.1', listen_port=4443,
        signing_key=str(sk), signing_cert=str(sc),
        tls_cert=str(tc), tls_key=str(tk),
        client_ca_cert=str(cca),
        identity_trust_roots=[str(sc)],
    )


def test_r9_validate_happy_path(tmp_path):
    """Verifies §13.9.7 — a fully-populated config validates."""
    _good_cfg(tmp_path).validate()  # no raise


@pytest.mark.parametrize('field', [
    'signing_key', 'signing_cert', 'tls_cert', 'tls_key', 'client_ca_cert',
])
def test_r9_validate_missing_required_field_raises(tmp_path, field):
    """Verifies §13.9.7 — each security-critical field absent → refuse-to-start.

    Parametrized over every field in the §14.3.2 required-set.
    """
    cfg = _good_cfg(tmp_path)
    setattr(cfg, field, '')
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert field in str(exc.value)
    assert '13.9.7' in str(exc.value)


@pytest.mark.parametrize('field', [
    'signing_key', 'signing_cert', 'tls_cert', 'tls_key', 'client_ca_cert',
])
def test_r9_validate_nonexistent_path_raises(tmp_path, field):
    """Verifies §13.9.7 — pointing at a nonexistent file → refuse-to-start."""
    cfg = _good_cfg(tmp_path)
    setattr(cfg, field, str(tmp_path / 'does-not-exist.pem'))
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert 'does not exist' in str(exc.value)


def test_r9_validate_empty_identity_trust_roots_raises(tmp_path):
    """Verifies §13.9.7 — empty identity_trust_roots → refuse-to-start.

    Without any trust root, the CA cannot validate any client identity.
    """
    cfg = _good_cfg(tmp_path)
    cfg.identity_trust_roots = []
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert 'identity_trust_roots' in str(exc.value)


def test_r9_validate_listen_port_range(tmp_path):
    """Verifies §13.9.7 — invalid listen port → refuse-to-start."""
    cfg = _good_cfg(tmp_path)
    cfg.listen_port = 0
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert 'listen port' in str(exc.value)
