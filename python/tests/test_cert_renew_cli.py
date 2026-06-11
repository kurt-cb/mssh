"""CLI tests for `mssh-admin cert renew`. Stubs the CAClient.

Tests: §7.3.3, §13.4
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from mssh.admin import main as admin_main
from mssh.admin.client import CAClient, CAClientError


def _fake_cert_pem(*, days_to_expiry: int) -> bytes:
    """Mint a self-signed cert with the requested expiry offset.
    Doesn't have to be valid for any real CA path — the CLI just
    reads not_after."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509 import oid

    key = ec.generate_private_key(ec.SECP256R1())
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(oid.NameOID.COMMON_NAME, 'fake.example.com')]))
        .issuer_name(x509.Name([
            x509.NameAttribute(oid.NameOID.COMMON_NAME, 'fake-ca')]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(days=1))
        .not_valid_after(now + _dt.timedelta(days=days_to_expiry))
        .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())


@pytest.fixture
def expiring_cert(tmp_path):
    """Cert that's 7 days from expiry."""
    cert_pem, key_pem = _fake_cert_pem(days_to_expiry=7)
    cert_path = tmp_path / 'tls.crt'
    key_path = tmp_path / 'tls.key'
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return cert_path, key_path


@pytest.fixture
def healthy_cert(tmp_path):
    """Cert that's 60 days from expiry (no-op)."""
    cert_pem, key_pem = _fake_cert_pem(days_to_expiry=60)
    cert_path = tmp_path / 'tls.crt'
    key_path = tmp_path / 'tls.key'
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return cert_path, key_path


def test_cli_noop_when_far_from_expiry(healthy_cert, tmp_path):
    """Cert > threshold days from expiry → exit 0 silently, no
    request made."""
    cert, key = healthy_cert
    out_cert = tmp_path / 'out.crt'
    out_key = tmp_path / 'out.key'
    runner = CliRunner()
    # Patch CAClient.cert_renew to make sure it's NOT called.
    with patch.object(CAClient, 'cert_renew') as mock:
        result = runner.invoke(admin_main.cli, [
            'cert', 'renew',
            '--cert', str(cert), '--key', str(key),
            '--out-cert', str(out_cert), '--out-key', str(out_key),
            '--ca-url', 'https://ca.example/', '--ca-cert', str(cert),
            '--threshold-days', '14',
        ])
        assert result.exit_code == 0, result.output
        mock.assert_not_called()
    # No files should have been written.
    assert not out_cert.exists()


def test_cli_renews_within_threshold(expiring_cert, tmp_path):
    cert, key = expiring_cert
    out_cert = tmp_path / 'out.crt'
    out_key = tmp_path / 'out.key'
    new_pem, new_key_pem = _fake_cert_pem(days_to_expiry=30)
    runner = CliRunner()
    with patch.object(CAClient, 'cert_renew') as mock:
        mock.return_value = {
            'status': 'ok',
            'cert': {'subject_cn': 'fake.example.com',
                     'sans': [], 'validity_days': 30,
                     'old_serial': 'abc123',
                     'revoked_predecessor': False},
            'credentials': {
                'cert_pem': new_pem.decode('ascii'),
                'key_pem': new_key_pem.decode('ascii'),
                'ca_cert_pem': '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----',
            },
        }
        result = runner.invoke(admin_main.cli, [
            'cert', 'renew',
            '--cert', str(cert), '--key', str(key),
            '--out-cert', str(out_cert), '--out-key', str(out_key),
            '--ca-url', 'https://ca.example/', '--ca-cert', str(cert),
            '--threshold-days', '14',
        ])
        assert result.exit_code == 0, result.output
        mock.assert_called_once_with(revoke_predecessor=False)
    # New cert + key written.
    assert out_cert.exists() and out_cert.read_bytes() == new_pem
    assert out_key.exists() and out_key.read_bytes() == new_key_pem
    # Key file is mode 0600.
    assert (out_key.stat().st_mode & 0o777) == 0o600


def test_cli_too_early_response_exits_0(expiring_cert, tmp_path):
    """Server returns status=too_early → CLI exits 0 silently."""
    cert, key = expiring_cert
    out_cert = tmp_path / 'out.crt'
    out_key = tmp_path / 'out.key'
    runner = CliRunner()
    with patch.object(CAClient, 'cert_renew') as mock:
        mock.return_value = {
            'status': 'too_early',
            'detail': 'cert not_after is …; 200 days from now',
            'seconds_to_expiry': 200 * 86400,
        }
        result = runner.invoke(admin_main.cli, [
            'cert', 'renew',
            '--cert', str(cert), '--key', str(key),
            '--out-cert', str(out_cert), '--out-key', str(out_key),
            '--ca-url', 'https://ca.example/', '--ca-cert', str(cert),
        ])
        assert result.exit_code == 0
    assert not out_cert.exists()


def test_cli_server_error_exits_nonzero(expiring_cert, tmp_path):
    cert, key = expiring_cert
    out_cert = tmp_path / 'out.crt'
    out_key = tmp_path / 'out.key'
    runner = CliRunner()
    with patch.object(CAClient, 'cert_renew') as mock:
        mock.side_effect = CAClientError(403, {'reason': 'revoked'})
        result = runner.invoke(admin_main.cli, [
            'cert', 'renew',
            '--cert', str(cert), '--key', str(key),
            '--out-cert', str(out_cert), '--out-key', str(out_key),
            '--ca-url', 'https://ca.example/', '--ca-cert', str(cert),
        ])
        assert result.exit_code == 3
        assert 'HTTP 403' in result.output
    assert not out_cert.exists()


def test_cli_passes_revoke_old_flag(expiring_cert, tmp_path):
    cert, key = expiring_cert
    out_cert = tmp_path / 'out.crt'
    out_key = tmp_path / 'out.key'
    new_pem, new_key_pem = _fake_cert_pem(days_to_expiry=30)
    runner = CliRunner()
    with patch.object(CAClient, 'cert_renew') as mock:
        mock.return_value = {
            'status': 'ok',
            'cert': {'subject_cn': 'fake.example.com',
                     'sans': [], 'validity_days': 30,
                     'old_serial': 'abc',
                     'revoked_predecessor': True},
            'credentials': {
                'cert_pem': new_pem.decode('ascii'),
                'key_pem': new_key_pem.decode('ascii'),
                'ca_cert_pem': 'X',
            },
        }
        result = runner.invoke(admin_main.cli, [
            'cert', 'renew',
            '--cert', str(cert), '--key', str(key),
            '--out-cert', str(out_cert), '--out-key', str(out_key),
            '--ca-url', 'https://ca.example/', '--ca-cert', str(cert),
            '--revoke-old',
        ])
        assert result.exit_code == 0, result.output
        mock.assert_called_once_with(revoke_predecessor=True)


def test_cli_missing_cert_exits_2(tmp_path):
    runner = CliRunner()
    result = runner.invoke(admin_main.cli, [
        'cert', 'renew',
        '--cert', str(tmp_path / 'nope.crt'),
        '--key', str(tmp_path / 'nope.key'),
        '--out-cert', str(tmp_path / 'out.crt'),
        '--out-key', str(tmp_path / 'out.key'),
        '--ca-url', 'https://x/', '--ca-cert', str(tmp_path / 'x'),
    ])
    assert result.exit_code == 2
    assert 'not found' in result.output


def test_cli_on_renew_runs(expiring_cert, tmp_path):
    cert, key = expiring_cert
    out_cert = tmp_path / 'out.crt'
    out_key = tmp_path / 'out.key'
    sentinel = tmp_path / 'on-renew-ran'
    new_pem, new_key_pem = _fake_cert_pem(days_to_expiry=30)
    runner = CliRunner()
    with patch.object(CAClient, 'cert_renew') as mock:
        mock.return_value = {
            'status': 'ok',
            'cert': {'subject_cn': 'x', 'sans': [], 'validity_days': 30,
                     'old_serial': 'a', 'revoked_predecessor': False},
            'credentials': {
                'cert_pem': new_pem.decode('ascii'),
                'key_pem': new_key_pem.decode('ascii'),
                'ca_cert_pem': 'X',
            },
        }
        result = runner.invoke(admin_main.cli, [
            'cert', 'renew',
            '--cert', str(cert), '--key', str(key),
            '--out-cert', str(out_cert), '--out-key', str(out_key),
            '--ca-url', 'https://x/', '--ca-cert', str(cert),
            '--on-renew', f'touch {sentinel}',
        ])
        assert result.exit_code == 0, result.output
    assert sentinel.exists()
