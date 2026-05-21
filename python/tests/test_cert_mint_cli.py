"""CLI tests for mssh-admin cert mint + openvpn issue.

These cover the client-side formatting bits: SAN normalization, .ovpn
assembly, PEM/PKCS#12 file output layout. The CA-side handlers are
tested separately in test_cert_mint_admin.py.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from mssh.admin import main as admin_main
from mssh.admin.main import _format_ovpn_bundle, _write_pkcs12


# ---- _format_ovpn_bundle ---------------------------------------------------

def test_ovpn_bundle_layout():
    out = _format_ovpn_bundle(
        ca_pem='-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----',
        cert_pem='-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----',
        key_pem='-----BEGIN EC PRIVATE KEY-----\nCCC\n-----END EC PRIVATE KEY-----',
        server_endpoint='vpn.example.com 1194',
        proto='udp', dev='tun',
    )
    # Required OpenVPN client directives.
    assert 'client\n' in out
    assert 'dev tun\n' in out
    assert 'proto udp\n' in out
    assert 'remote vpn.example.com 1194\n' in out
    assert 'remote-cert-tls server\n' in out
    # Inline inline PEM blocks for ca / cert / key.
    assert '<ca>\n-----BEGIN CERTIFICATE-----' in out
    assert '</ca>\n' in out
    assert '<cert>\n-----BEGIN CERTIFICATE-----' in out
    assert '</cert>\n' in out
    assert '<key>\n-----BEGIN EC PRIVATE KEY-----' in out
    assert '</key>\n' in out


def test_ovpn_bundle_tcp_tap():
    out = _format_ovpn_bundle(
        ca_pem='X', cert_pem='Y', key_pem='Z',
        server_endpoint='vpn 443', proto='tcp', dev='tap',
    )
    assert 'proto tcp\n' in out
    assert 'dev tap\n' in out


# ---- _write_pkcs12 ---------------------------------------------------------

def test_pkcs12_writes_password_protected_file(tmp_path, ca_dir):
    # Mint a real client cert via the cert_minter so we have valid PEMs.
    from mssh.ca import cert_minter
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    bundle = cert_minter.issue_client_cert(
        'alice', tls_ca_key, tls_ca_cert, validity_days=30, key_type='ec')

    out_path = tmp_path / 'alice.p12'
    _write_pkcs12(
        cert_pem=bundle.cert_pem.decode('ascii'),
        key_pem=bundle.key_pem.decode('ascii'),
        friendly_name='alice',
        password=b'CHANGEME',
        out_path=out_path,
    )
    assert out_path.exists()
    # File starts with the PKCS#12 SEQUENCE tag (0x30).
    data = out_path.read_bytes()
    assert data[0:1] == b'\x30'
    # Mode 0600.
    assert (out_path.stat().st_mode & 0o777) == 0o600
    # Round-trip: decrypt with the password and recover the cert.
    from cryptography.hazmat.primitives.serialization import pkcs12
    key, cert, extras = pkcs12.load_key_and_certificates(data, b'CHANGEME')
    assert cert is not None
    assert key is not None


# ---- CLI surface — stubbed against a fake CAClient ------------------------

def _stub_client_with(monkeypatch, cert_mint_resp=None,
                      openvpn_resp=None) -> MagicMock:
    """Patch the CLI's _make_client to return a MagicMock with the
    given canned responses for cert_mint / openvpn_issue."""
    fake = MagicMock()
    if cert_mint_resp is not None:
        fake.cert_mint.return_value = cert_mint_resp
    if openvpn_resp is not None:
        fake.openvpn_issue.return_value = openvpn_resp
    monkeypatch.setattr(admin_main, '_make_client', lambda ctx: fake)
    return fake


def _fake_cert_resp(cert_type='tls-server', cn='example'):
    return {
        'status': 'ok',
        'cert': {'type': cert_type, 'subject_cn': cn, 'validity_days': 30},
        'credentials': {
            'cert_pem': '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
            'key_pem':  '-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----',
            'ca_cert_pem': '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----',
        },
    }


def test_cli_cert_mint_tls_server_writes_three_files(tmp_path, monkeypatch):
    _stub_client_with(monkeypatch,
                      cert_mint_resp=_fake_cert_resp('tls-server', 'g.example.com'))
    out_prefix = tmp_path / 'g'
    runner = CliRunner()
    result = runner.invoke(admin_main.cli, [
        'cert', 'mint',
        '--type', 'tls-server',
        '--cn', 'g.example.com',
        '--san', 'DNS:g.example.com',
        '--san', 'IP:10.0.0.42',
        '--out', str(out_prefix),
    ])
    assert result.exit_code == 0, result.output
    for suffix in ('-cert.pem', '-key.pem', '-ca.pem'):
        assert (tmp_path / f'g{suffix}').exists()
    # Key file is 0600.
    assert ((tmp_path / 'g-key.pem').stat().st_mode & 0o777) == 0o600


def test_cli_cert_mint_san_rejected_on_https_user(tmp_path, monkeypatch):
    _stub_client_with(monkeypatch,
                      cert_mint_resp=_fake_cert_resp('https-user', 'alice'))
    runner = CliRunner()
    result = runner.invoke(admin_main.cli, [
        'cert', 'mint',
        '--type', 'https-user',
        '--cn', 'alice',
        '--san', 'DNS:alice.example.com',
        '--out', str(tmp_path / 'alice'),
    ])
    assert result.exit_code != 0
    assert '--san is only valid for --type tls-server' in result.output


def test_cli_cert_mint_p12_password_rejected_on_tls_server(tmp_path, monkeypatch):
    _stub_client_with(monkeypatch,
                      cert_mint_resp=_fake_cert_resp('tls-server', 'x.example.com'))
    runner = CliRunner()
    result = runner.invoke(admin_main.cli, [
        'cert', 'mint',
        '--type', 'tls-server',
        '--cn', 'x.example.com',
        '--p12-password', 'CHANGEME',
        '--out', str(tmp_path / 'x'),
    ])
    assert result.exit_code != 0
    assert '--p12-password is only valid for --type https-user' in result.output


def test_cli_openvpn_issue_writes_ovpn_file(tmp_path, monkeypatch):
    _stub_client_with(monkeypatch, openvpn_resp={
        'status': 'ok',
        'openvpn': {
            'subject_cn': 'alice',
            'server_endpoint': 'vpn.example.com 1194',
            'proto': 'udp', 'dev': 'tun', 'validity_days': 90,
        },
        'credentials': _fake_cert_resp()['credentials'],
    })
    ovpn_path = tmp_path / 'alice.ovpn'
    runner = CliRunner()
    result = runner.invoke(admin_main.cli, [
        'openvpn', 'issue',
        '--cn', 'alice',
        '--server-endpoint', 'vpn.example.com 1194',
        '--out', str(ovpn_path),
    ])
    assert result.exit_code == 0, result.output
    body = ovpn_path.read_text()
    assert 'remote vpn.example.com 1194' in body
    assert '<cert>' in body and '<key>' in body and '<ca>' in body
    assert (ovpn_path.stat().st_mode & 0o777) == 0o600
