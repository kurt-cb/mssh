"""Phase 5 — §6.3.1 mssh client config resolution gap closure.

Closes a TESTS-TODO row: the client's resolve_identity() function
had no dedicated unit test for the CLI / env / config / defaults
precedence chain.

Tests: §6.3.1, §14.3.3
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from mssh.client import (DEFAULT_CA, DEFAULT_CERT, DEFAULT_KEY, Identity,
                          load_config, parse_target, resolve_identity,
                          validate_identity)


# ---- precedence chain ----

def test_cli_override_beats_env_and_config(monkeypatch):
    """§6.3.1 — CLI override is highest priority."""
    monkeypatch.setenv('MSSH_CERT', '/env-cert.pem')
    cfg = {'cert': '/cfg-cert.pem'}
    out = resolve_identity(cfg, cert_override='/cli-cert.pem')
    assert str(out.cert) == '/cli-cert.pem'


def test_env_beats_config(monkeypatch):
    """§6.3.1 — env var is next after CLI."""
    monkeypatch.setenv('MSSH_CERT', '/env-cert.pem')
    cfg = {'cert': '/cfg-cert.pem'}
    out = resolve_identity(cfg)
    assert str(out.cert) == '/env-cert.pem'


def test_config_beats_default(monkeypatch):
    """§6.3.1 — file-config is next after env."""
    monkeypatch.delenv('MSSH_CERT', raising=False)
    cfg = {'cert': '/cfg-cert.pem'}
    out = resolve_identity(cfg)
    assert str(out.cert) == '/cfg-cert.pem'


def test_default_used_when_nothing_set(monkeypatch, tmp_path):
    """§6.3.1 — DEFAULT_CERT used when no override / env / config provides one."""
    monkeypatch.delenv('MSSH_CERT', raising=False)
    monkeypatch.setenv('HOME', str(tmp_path))
    out = resolve_identity({})
    assert str(out.cert).endswith('.mssh/cert.pem')


# ---- MSSH_TRUST alias (R-10) ----

def test_mssh_trust_env_var_alias(monkeypatch):
    """§6.3.1 + R-10 — MSSH_TRUST is recognized as an alias for MSSH_CA."""
    monkeypatch.delenv('MSSH_CA', raising=False)
    monkeypatch.setenv('MSSH_TRUST', '/trust-pin.pem')
    out = resolve_identity({})
    assert str(out.ca) == '/trust-pin.pem'


def test_mssh_ca_takes_precedence_over_mssh_trust(monkeypatch):
    """§6.3.1 — both env vars set: MSSH_CA wins (legacy precedence)."""
    monkeypatch.setenv('MSSH_CA', '/ca-set.pem')
    monkeypatch.setenv('MSSH_TRUST', '/trust-set.pem')
    out = resolve_identity({})
    assert str(out.ca) == '/ca-set.pem'


# ---- validate_identity §13.9.7 default-deny ----

def test_validate_identity_refuses_missing_cert(tmp_path):
    """§13.9.7 + §6.3.1 — missing cert file → refuse."""
    ident = Identity(
        cert=tmp_path / 'missing.pem',
        key=tmp_path / 'missing.pem',
        ca=tmp_path / 'missing.pem',
    )
    with pytest.raises(ValueError) as exc:
        validate_identity(ident)
    assert 'cert' in str(exc.value).lower()


def test_validate_identity_refuses_world_readable_key(tmp_path):
    """§13.9.7 + §6.3.1 — key file with bad permissions → refuse."""
    cert = tmp_path / 'cert.pem'; cert.write_text('-')
    key = tmp_path / 'key.pem'; key.write_text('-')
    ca = tmp_path / 'ca.pem'; ca.write_text('-')
    os.chmod(key, 0o644)            # world-readable
    ident = Identity(cert=cert, key=key, ca=ca)
    with pytest.raises(ValueError) as exc:
        validate_identity(ident)
    assert 'mode' in str(exc.value).lower() \
        or 'permissions' in str(exc.value).lower()


def test_validate_identity_accepts_0600_key(tmp_path):
    """§6.3.1 — well-permissioned key → no raise."""
    cert = tmp_path / 'cert.pem'; cert.write_text('-')
    key = tmp_path / 'key.pem'; key.write_text('-')
    ca = tmp_path / 'ca.pem'; ca.write_text('-')
    os.chmod(key, 0o600)
    ident = Identity(cert=cert, key=key, ca=ca)
    validate_identity(ident)         # no raise


# ---- config file parsing ----

def test_load_config_parses_flat_key_value(tmp_path):
    """§14.3.3 — flat `key=value` config parsing."""
    p = tmp_path / 'config'
    p.write_text(
        '# leading comment\n'
        'cert = /home/alice/.mssh/cert.pem\n'
        'key  = /home/alice/.mssh/key.pem\n'
        'ca   = /home/alice/.mssh/ca.pem\n'
    )
    cfg = load_config(p)
    assert cfg['cert'] == '/home/alice/.mssh/cert.pem'
    assert cfg['key'] == '/home/alice/.mssh/key.pem'
    assert cfg['ca'] == '/home/alice/.mssh/ca.pem'


def test_load_config_missing_file_returns_empty(tmp_path):
    """§14.3.3 — absent config file yields empty dict (defaults apply)."""
    assert load_config(tmp_path / 'nope') == {}


def test_load_config_rejects_malformed_line(tmp_path):
    """§14.3.3 — malformed config line → ValueError."""
    p = tmp_path / 'bad'
    p.write_text('garbage line without equals\n')
    with pytest.raises(ValueError):
        load_config(p)


# ---- parse_target ----

def test_parse_target_user_host_port():
    t = parse_target('alice@srv:2200', default_port=22)
    assert t.user == 'alice' and t.host == 'srv' and t.port == 2200


def test_parse_target_default_port():
    t = parse_target('alice@srv', default_port=2200)
    assert t.port == 2200


def test_parse_target_default_user():
    t = parse_target('srv', default_port=22, default_user='bob')
    assert t.user == 'bob'


def test_parse_target_refuses_ipv6_brackets():
    with pytest.raises(ValueError):
        parse_target('[2001:db8::1]:22', default_port=22)
