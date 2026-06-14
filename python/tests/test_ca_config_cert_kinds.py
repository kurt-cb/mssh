"""§15.23 cert_kinds policy parser tests.

Verifies that ca-config.yaml's optional `cert_kinds:` section is
parsed into CertKindsPolicy, with the documented fallback ladder:

  1. per_kind[<kind>][default|max]
  2. section-level default_validity_days / default_max_validity_days
  3. _FALLBACK_CERT_DEFAULT_VALIDITY[<kind>] / _FALLBACK_CERT_MAX_VALIDITY[<kind>]
  4. _FALLBACK_BASE_DEFAULT / _FALLBACK_BASE_MAX

Tests: §15.23
"""
from __future__ import annotations

import pytest
import yaml

from mssh.ca.config import (
    CAConfig,
    CertKindsPolicy,
    _FALLBACK_BASE_DEFAULT,
    _FALLBACK_BASE_MAX,
    _FALLBACK_CERT_DEFAULT_VALIDITY,
    _FALLBACK_CERT_MAX_VALIDITY,
)


def _write_yaml(tmp_path, data: dict):
    """Verifies §15.23 — writes a minimal ca-config.yaml + required
    paths so CAConfig.load(...) returns successfully without raising."""
    sk = tmp_path / 'signing-key.pem'; sk.write_text('-key-')
    sc = tmp_path / 'signing-cert.pem'; sc.write_text('-cert-')
    tc = tmp_path / 'tls-cert.pem'; tc.write_text('-cert-')
    tk = tmp_path / 'tls-key.pem'; tk.write_text('-key-')
    cca = tmp_path / 'client-ca-cert.pem'; cca.write_text('-cert-')
    base = {
        'listen': '127.0.0.1:4443',
        'signing_key': str(sk),
        'signing_cert': str(sc),
        'tls_cert': str(tc),
        'tls_key': str(tk),
        'client_ca_cert': str(cca),
        'identity_trust_roots': [str(sc)],
    }
    base.update(data)
    cfg_path = tmp_path / 'ca-config.yaml'
    cfg_path.write_text(yaml.safe_dump(base))
    return cfg_path


# ---- direct CertKindsPolicy unit tests -----------------------------------


def test_empty_section_falls_through_to_builtin_baselines():
    """Verifies §15.23 — when no cert_kinds: section is present,
    per-kind lookups go through the v0.4.x baseline dicts."""
    p = CertKindsPolicy.from_yaml_section(None)
    # Every legacy kind resolves to its built-in baseline.
    for kind, days in _FALLBACK_CERT_DEFAULT_VALIDITY.items():
        assert p.default_for(kind) == days
    for kind, days in _FALLBACK_CERT_MAX_VALIDITY.items():
        assert p.cap_for(kind) == days


def test_unknown_kind_uses_section_level_default():
    """Verifies §15.23 — kind not in fallback dict + not in per_kind:
    falls through to section-level default_validity_days / cap."""
    p = CertKindsPolicy(default_validity_days=42, default_max_validity_days=99)
    assert p.default_for('unknown-kind') == 42
    assert p.cap_for('unknown-kind') == 99


def test_per_kind_override_wins():
    """Verifies §15.23 — per_kind entry takes priority over baseline."""
    p = CertKindsPolicy(per_kind={
        'tls-server': {'default_validity_days': 30, 'max_validity_days': 60},
    })
    assert p.default_for('tls-server') == 30
    assert p.cap_for('tls-server') == 60
    # An untouched kind still falls back.
    assert p.default_for('https-user') == _FALLBACK_CERT_DEFAULT_VALIDITY['https-user']


def test_per_kind_partial_override_falls_through():
    """Verifies §15.23 — operator overrides only default, cap falls
    through to baseline."""
    p = CertKindsPolicy(per_kind={
        'openvpn': {'default_validity_days': 14},
    })
    assert p.default_for('openvpn') == 14
    assert p.cap_for('openvpn') == _FALLBACK_CERT_MAX_VALIDITY['openvpn']


def test_external_use_default_is_twenty_years():
    """Verifies §15.19 — external-use baseline is 20yr default, 25yr cap."""
    p = CertKindsPolicy()
    assert p.default_for('external-use') == 7305   # 20yr
    assert p.cap_for('external-use') == 9125       # 25yr


# ---- ca-config.yaml end-to-end parse -------------------------------------


def test_load_without_cert_kinds_section_uses_builtin(tmp_path):
    """Verifies §15.23 — v0.4.x configs (no cert_kinds: section) still
    work; CertKindsPolicy is constructed with empty per_kind and the
    fallback dicts handle every lookup."""
    cfg_path = _write_yaml(tmp_path, {})
    c = CAConfig.load(cfg_path)
    assert isinstance(c.cert_kinds, CertKindsPolicy)
    assert c.cert_kinds.per_kind == {}
    assert c.cert_kinds.default_for('tls-server') == 90
    assert c.cert_kinds.cap_for('code-sign') == 1825


def test_load_with_per_kind_override(tmp_path):
    """Verifies §15.23 — operator-supplied per_kind entries land in
    CertKindsPolicy and influence default_for / cap_for."""
    cfg_path = _write_yaml(tmp_path, {
        'cert_kinds': {
            'default_validity_days': 90,
            'default_max_validity_days': 825,
            'per_kind': {
                'external-use': {
                    'default_validity_days': 10950,
                    'max_validity_days': 36500,
                },
                'openvpn': {'default_validity_days': 30},
            },
        },
    })
    c = CAConfig.load(cfg_path)
    assert c.cert_kinds.default_for('external-use') == 10950
    assert c.cert_kinds.cap_for('external-use') == 36500
    assert c.cert_kinds.default_for('openvpn') == 30
    # openvpn cap not set in YAML → falls back to baseline (365).
    assert c.cert_kinds.cap_for('openvpn') == 365


def test_load_with_only_section_defaults(tmp_path):
    """Verifies §15.23 — section-level default_validity_days /
    default_max_validity_days apply to unknown kinds (no per_kind entry
    and not in the baseline dicts)."""
    cfg_path = _write_yaml(tmp_path, {
        'cert_kinds': {
            'default_validity_days': 50,
            'default_max_validity_days': 200,
            'per_kind': {},
        },
    })
    c = CAConfig.load(cfg_path)
    # Known kinds STILL use their fallback baselines (cleaner than
    # silently overriding); section defaults are the floor for unknown.
    assert c.cert_kinds.default_for('tls-server') == _FALLBACK_CERT_DEFAULT_VALIDITY['tls-server']
    # Truly unknown kinds use section defaults.
    assert c.cert_kinds.default_for('totally-new-kind') == 50
    assert c.cert_kinds.cap_for('totally-new-kind') == 200


def test_fallback_constants_cover_all_legacy_kinds():
    """Verifies §15.23 — every kind currently accepted by the cert-mint
    handler has a built-in default + cap so it never falls through to
    the section-level base default."""
    legacy = ('tls-server', 'https-user', 'code-sign', 'openvpn')
    for kind in legacy:
        assert kind in _FALLBACK_CERT_DEFAULT_VALIDITY
        assert kind in _FALLBACK_CERT_MAX_VALIDITY
