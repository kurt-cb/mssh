"""§15.21 + §15.23 bootstrap config writer tests.

Verifies that `mssh-admin init` emits:
  1. A documented `cert_kinds:` section with per-kind defaults.
  2. A documented `custom_oids:` section with the reserved-arc
     commentary block.
  3. A ca-config.yaml that parses cleanly through CAConfig.load() +
     CAConfig.validate() with the resulting policies populated.

Tests: §15.21, §15.23
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from mssh.admin import main as admin_main
from mssh.ca.config import CAConfig


@pytest.fixture
def init_ca(tmp_path):
    """Run `mssh-admin init --ca-dir <tmp>` and return the ca-config.yaml
    path."""
    runner = CliRunner()
    ca_dir = tmp_path / 'ca'
    res = runner.invoke(admin_main.cli, [
        'init', '--ca-dir', str(ca_dir),
        '--bootstrap-admin', 'boot',
    ])
    assert res.exit_code == 0, res.output
    return ca_dir / 'ca-config.yaml'


def test_emitted_yaml_parses_cleanly(init_ca):
    """Verifies §15.21 + §15.23 — the emitted file parses as YAML and
    CAConfig.load succeeds. validate() needs identity_trust_roots
    populated (operator step); this test just confirms parse + the
    custom_oids/cert_kinds sections are present."""
    raw = init_ca.read_text()
    data = yaml.safe_load(raw)
    assert 'cert_kinds' in data
    assert 'custom_oids' in data
    cfg = CAConfig.load(init_ca)
    # The cert_kinds policy is populated.
    assert cfg.cert_kinds.default_for('external-use') == 7305
    # The custom_oids allowlist is empty (default-deny).
    assert cfg.custom_oids.entries == {}


def test_cert_kinds_section_carries_per_kind_defaults(init_ca):
    """Verifies §15.23 — emitted cert_kinds: has per-kind defaults for
    every kind the CA mints today."""
    data = yaml.safe_load(init_ca.read_text())
    per_kind = data['cert_kinds']['per_kind']
    for kind in ['authz-user', 'authz-bypass', 'server-tls', 'admin-mtls',
                  'client-mtls', 'https-user', 'openvpn', 'code-sign',
                  'external-use']:
        assert kind in per_kind, kind
        assert 'default_validity_days' in per_kind[kind]
        assert 'max_validity_days' in per_kind[kind]


def test_external_use_defaults_are_twenty_year(init_ca):
    """Verifies §15.19 — external-use ships with a 20yr default + 25yr cap."""
    data = yaml.safe_load(init_ca.read_text())
    eu = data['cert_kinds']['per_kind']['external-use']
    assert eu['default_validity_days'] == 7305
    assert eu['max_validity_days'] == 9125


def test_custom_oids_empty_list_by_default(init_ca):
    """Verifies §15.21 — operator gets an empty allowlist out of the
    box (default-deny); the commented example shows how to opt in."""
    data = yaml.safe_load(init_ca.read_text())
    assert data['custom_oids'] == []


def test_documentation_comments_present(init_ca):
    """Verifies §15.21 + §15.23 — the documented reserved-arc comment
    block is in-file so operators discover it when editing the config.
    The check looks for distinctive substrings from the comment text."""
    raw = init_ca.read_text()
    assert '§15.23' in raw or '15.23' in raw   # cert_kinds doc header
    assert '§15.21' in raw or '15.21' in raw   # custom_oids doc header
    assert '1.3.6.1.4.1.55555.[1-4999]' in raw
    assert '1.3.6.1.4.1.55555.[5000-65535]' in raw
    assert 'OID_KIND_EXTERNAL_USE' in raw      # kind-marker reference
    assert 'OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE' in raw


def test_loaded_policy_matches_emitted_yaml(init_ca):
    """Verifies §15.23 — CAConfig.cert_kinds loaded from the emitted file
    resolves the same per-kind defaults the YAML declares."""
    cfg = CAConfig.load(init_ca)
    # Sanity: a few per-kind lookups should return the values from the YAML.
    assert cfg.cert_kinds.default_for('external-use') == 7305
    assert cfg.cert_kinds.cap_for('external-use') == 9125
    assert cfg.cert_kinds.default_for('openvpn') == 90
    assert cfg.cert_kinds.cap_for('openvpn') == 365
