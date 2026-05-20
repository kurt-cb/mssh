"""CLI tests for `mssh-admin wireguard ...`. Stubs the CAClient.

Covers the CLI-side behavior: file output paths, mode 0600 on the
client config (which contains a private key), JSON/table emission.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from click.testing import CliRunner

from mssh.admin import main as admin_main


def _stub(monkeypatch, **canned) -> MagicMock:
    fake = MagicMock()
    for method, retval in canned.items():
        getattr(fake, method).return_value = retval
    monkeypatch.setattr(admin_main, '_make_client', lambda ctx: fake)
    return fake


def test_cli_server_init(monkeypatch):
    _stub(monkeypatch, wireguard_server_init={
        'status': 'ok',
        'server': {
            'name': 'wg0', 'network': '10.20.0.0/24',
            'listen_port': 51820, 'endpoint': 'vpn.example.com:51820',
            'public_key_b64': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            'server_address': '10.20.0.1/24',
            'created_at': '2026-05-20T00:00:00Z',
        },
    })
    runner = CliRunner()
    result = runner.invoke(admin_main.cli, [
        'wireguard', 'server-init',
        '--name', 'wg0',
        '--network', '10.20.0.0/24',
        '--endpoint', 'vpn.example.com:51820',
    ])
    assert result.exit_code == 0, result.output
    assert 'wg0' in result.output


def test_cli_peer_issue_writes_secure_config(tmp_path, monkeypatch):
    _stub(monkeypatch, wireguard_peer_issue={
        'status': 'ok',
        'peer': {
            'name': 'alice', 'server': 'wg0',
            'address': '10.20.0.2/32',
            'public_key_b64': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
            'issued_at': '2026-05-20T00:00:00Z',
        },
        'client_config': (
            '[Interface]\n'
            'Address    = 10.20.0.2/32\n'
            'PrivateKey = SECRET\n'
            '\n[Peer]\n'
            'PublicKey  = SRVPUB\n'
            'Endpoint   = vpn.example.com:51820\n'
            'AllowedIPs = 10.20.0.0/24\n'
        ),
    })
    out = tmp_path / 'alice.conf'
    runner = CliRunner()
    result = runner.invoke(admin_main.cli, [
        'wireguard', 'issue',
        '--name', 'alice', '--server', 'wg0',
        '--out', str(out),
    ])
    assert result.exit_code == 0, result.output
    body = out.read_text()
    assert '[Interface]' in body and '[Peer]' in body
    assert 'PrivateKey = SECRET' in body
    # Mode 0600 — contains the private key.
    assert (out.stat().st_mode & 0o777) == 0o600


def test_cli_server_show_writes_to_file(tmp_path, monkeypatch):
    _stub(monkeypatch, wireguard_server_show={
        'status': 'ok',
        'server': {
            'name': 'wg0', 'network': '10.20.0.0/24',
            'listen_port': 51820, 'endpoint': 'vpn.example.com:51820',
            'public_key_b64': 'PUB=',
            'server_address': '10.20.0.1/24',
            'created_at': '2026-05-20T00:00:00Z',
            'created_by': 'boot', 'peer_count': 0,
        },
        'server_config': (
            '[Interface]\nAddress    = 10.20.0.1/24\n'
            'ListenPort = 51820\nPrivateKey = SERVER_SECRET\n'
        ),
    })
    out = tmp_path / 'wg0.conf'
    runner = CliRunner()
    result = runner.invoke(admin_main.cli, [
        'wireguard', 'server-show',
        '--name', 'wg0', '--out', str(out),
    ])
    assert result.exit_code == 0, result.output
    assert 'PrivateKey = SERVER_SECRET' in out.read_text()
    assert (out.stat().st_mode & 0o777) == 0o600


def test_cli_revoke(monkeypatch):
    _stub(monkeypatch, wireguard_peer_revoke={
        'status': 'ok',
        'revoked': {'name': 'alice', 'server': 'wg0'},
    })
    runner = CliRunner()
    result = runner.invoke(admin_main.cli, [
        'wireguard', 'revoke',
        '--name', 'alice', '--server', 'wg0',
    ])
    assert result.exit_code == 0, result.output
