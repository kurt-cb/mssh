"""v0.5.6 — Root CN configurability + CN/SAN DNS validation tests.

Two features that shipped together:

1. **Root CN configurable at init**. Pre-v0.5.6 every mssh CA got the
   same hard-coded Root CN "mssh-root". Now it defaults to
   "<hostname> Root CA" and can be overridden via `--root-cn` on
   `mssh-admin init` or `root_cn=` on `bootstrap_ca`.

2. **CN + SAN validation**. cert_mint validates the CN and each SAN
   against RFC 1035 hostname rules. Hard errors on invalid characters
   or oversize; warnings on browser-hostile shapes (single-label
   hostname, missing DNS SAN on tls-server).

Tests: §14.8, §14.2.2, §2.2
"""
from __future__ import annotations

import socket
from pathlib import Path

import pytest
from cryptography import x509

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import (
    AdminContext,
    _validate_cn,
    _validate_dns_label,
    _validate_dns_name,
    _validate_san,
)
from mssh.ca.audit import AuditLog
from mssh.ca.config import CertKindsPolicy, CustomOIDAllowlist
from mssh.ca.enrollment import Admin, Enrollment


# ---- Root CN configurability -------------------------------------------


def _root_cn_of(cert: x509.Certificate) -> str:
    """Helper: extract the CN attribute from a cert's subject."""
    from cryptography.x509.oid import NameOID
    return cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME)[0].value


def test_bootstrap_ca_default_root_cn_is_placeholder(tmp_path):
    """Verifies §2.2 v0.5.7 — programmatic bootstrap_ca() without
    root_cn produces an obviously-placeholder CN so an operator
    seeing it in a trust store knows the required config step was
    skipped."""
    ca_dir = tmp_path / 'ca'
    cert_minter.bootstrap_ca(ca_dir)
    root_cert = cert_minter.load_certificate(ca_dir / 'root-cert.pem')
    assert _root_cn_of(root_cert) == \
        f'Unspecified cert from host {socket.gethostname()}'


def test_bootstrap_ca_custom_root_cn_honored(tmp_path):
    """Verifies §2.2 v0.5.6 — operator-supplied root_cn is what lands
    on the Root cert."""
    ca_dir = tmp_path / 'ca'
    cert_minter.bootstrap_ca(ca_dir, root_cn='ACME Root CA')
    root_cert = cert_minter.load_certificate(ca_dir / 'root-cert.pem')
    assert _root_cn_of(root_cert) == 'ACME Root CA'


def test_bootstrap_ca_empty_root_cn_rejected(tmp_path):
    """Verifies §2.2 v0.5.6 — empty / whitespace-only root_cn raises."""
    ca_dir = tmp_path / 'ca'
    with pytest.raises(ValueError):
        cert_minter.bootstrap_ca(ca_dir, root_cn='   ')


def test_default_root_cn_helper():
    """Verifies §2.2 v0.5.7 — _default_root_cn returns the obvious
    placeholder 'Unspecified cert from host <hostname>'."""
    assert cert_minter._default_root_cn() == \
        f'Unspecified cert from host {socket.gethostname()}'


def test_cli_init_requires_root_cn(tmp_path):
    """Verifies §7.3.1 / v0.5.7 — `mssh-admin init` refuses to run
    without --root-cn (click surfaces 'Missing option'), so operators
    can't accidentally ship a CA with a generic default CN."""
    from click.testing import CliRunner
    from mssh.admin import main as admin_main
    runner = CliRunner()
    res = runner.invoke(admin_main.cli, [
        'init', '--ca-dir', str(tmp_path / 'ca'),
        '--bootstrap-admin', 'boot',
    ])
    assert res.exit_code != 0
    assert '--root-cn' in res.output or 'root-cn' in res.output


def test_cli_init_accepts_root_cn(tmp_path):
    """Verifies §7.3.1 / v0.5.7 — with --root-cn, init succeeds and
    the operator's CN lands on the Root cert."""
    from click.testing import CliRunner
    from mssh.admin import main as admin_main
    runner = CliRunner()
    ca_dir = tmp_path / 'ca'
    res = runner.invoke(admin_main.cli, [
        'init', '--ca-dir', str(ca_dir),
        '--bootstrap-admin', 'boot',
        '--root-cn', 'ACME Widgets Root CA',
    ])
    assert res.exit_code == 0, res.output
    root_cert = cert_minter.load_certificate(ca_dir / 'root-cert.pem')
    assert _root_cn_of(root_cert) == 'ACME Widgets Root CA'


# ---- DNS label validation ----------------------------------------------


@pytest.mark.parametrize('label', [
    'web',
    'kg-di-dev',
    'a1',
    'x' * 63,           # right at RFC 1035 label max
    '*',                # wildcard label — allowed for TLS SAN leftmost
])
def test_valid_dns_labels(label):
    assert _validate_dns_label(label) is None


@pytest.mark.parametrize('label,fragment', [
    ('',            'empty'),
    ('x' * 64,      'too long'),
    ('-leading',    'must start'),
    ('trailing-',   'may not end'),
    ('bad char',    'invalid character'),
    ('bad.dot',     'invalid character'),
])
def test_invalid_dns_labels(label, fragment):
    err = _validate_dns_label(label)
    assert err is not None
    assert fragment in err


# ---- DNS name validation ------------------------------------------------


def test_valid_fqdn_no_warning():
    err, warnings = _validate_dns_name('web.example.com')
    assert err is None
    assert warnings == []


def test_single_label_warns_but_valid():
    """Verifies §14.8 v0.5.6 — bare hostname is valid DNS but browsers
    reject it. Return valid + warning."""
    err, warnings = _validate_dns_name('kg-di-dev')
    assert err is None
    assert warnings
    assert 'ERR_CERT_COMMON_NAME_INVALID' in warnings[0]


def test_wildcard_leftmost_ok():
    err, warnings = _validate_dns_name('*.example.com')
    assert err is None


def test_wildcard_non_leftmost_rejected():
    err, _ = _validate_dns_name('foo.*.example.com')
    assert err is not None
    assert 'leftmost' in err


def test_over_length_dns_name_rejected():
    # 4 × 63 + 3 dots = 255 chars > 253 RFC limit.
    long_name = '.'.join(['a' * 63, 'b' * 63, 'c' * 63, 'd' * 63])
    err, _ = _validate_dns_name(long_name)
    assert err is not None
    assert 'too long' in err


# ---- SAN validation returns (normalized, warnings) tuple ---------------


def test_san_validation_fqdn():
    normalized, warnings = _validate_san('DNS:web.example.com')
    assert normalized == 'DNS:web.example.com'
    assert warnings == []


def test_san_validation_bare_becomes_dns_prefixed():
    normalized, warnings = _validate_san('web.example.com')
    assert normalized == 'DNS:web.example.com'


def test_san_validation_ip_ok():
    normalized, warnings = _validate_san('IP:192.168.1.1')
    assert normalized == 'IP:192.168.1.1'
    assert warnings == []


def test_san_validation_single_label_warns():
    normalized, warnings = _validate_san('DNS:kg-di-dev')
    assert normalized == 'DNS:kg-di-dev'
    assert any('ERR_CERT_COMMON_NAME_INVALID' in w for w in warnings)


def test_san_validation_bad_char_rejected():
    with pytest.raises(ValueError):
        _validate_san('DNS:invalid chars')


# ---- CN validation ------------------------------------------------------


def test_cn_validation_empty_rejected():
    with pytest.raises(ValueError):
        _validate_cn('', 'tls-server')


def test_cn_validation_control_char_rejected():
    with pytest.raises(ValueError):
        _validate_cn('web\x00example', 'tls-server')


def test_cn_validation_oversize_rejected():
    with pytest.raises(ValueError):
        _validate_cn('x' * 100, 'tls-server')


def test_cn_validation_tls_server_bare_warns():
    warnings = _validate_cn('kg-di-dev', 'tls-server')
    assert warnings
    assert any('DNS SAN' in w or 'browsers' in w for w in warnings)


def test_cn_validation_tls_server_fqdn_ok():
    warnings = _validate_cn('web.example.com', 'tls-server')
    assert warnings == []


def test_cn_validation_non_tls_free_form():
    """Verifies §14.8 v0.5.6 — for code-sign / openvpn / etc., CN can
    be any free-form label (not required to be DNS-shaped)."""
    warnings = _validate_cn('Build agent 03', 'code-sign')
    assert warnings == []   # no complaint about the spaces


# ---- End-to-end cert_mint surfaces warnings in response ---------------


@pytest.fixture
def adminctx(ca_dir):
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        ca_dir=str(ca_dir),
        cert_kinds=CertKindsPolicy(),
        custom_oids=CustomOIDAllowlist(),
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


def test_cert_mint_warns_on_tls_server_no_dns_san(adminctx, superuser):
    """Verifies §14.8 v0.5.6 — tls-server mint without any DNS SAN
    surfaces a warning explaining why browsers will reject it."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
    })
    assert status == 201
    assert 'warnings' in body
    assert any('DNS SAN' in w for w in body['warnings'])


def test_cert_mint_warns_on_single_label_san(adminctx, superuser):
    """Verifies §14.8 v0.5.6 — single-label SAN triggers the
    ERR_CERT_COMMON_NAME_INVALID warning explaining what browsers
    will do."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'kg-di-dev',
        'sans': ['DNS:kg-di-dev'],
    })
    assert status == 201
    assert any('ERR_CERT_COMMON_NAME_INVALID' in w for w in body['warnings'])


def test_cert_mint_no_warnings_on_valid_fqdn_with_dns_san(
        adminctx, superuser):
    """Verifies §14.8 v0.5.6 — the happy path (FQDN CN + matching DNS
    SAN) produces no warnings."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'sans': ['DNS:web.example.com'],
    })
    assert status == 201
    assert body['warnings'] == []


def test_cert_mint_rejects_control_char_cn(adminctx, superuser):
    """Verifies §14.8 v0.5.6 — control chars in CN → 400 bad_request."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web\x01example.com',
    })
    assert status == 400
    assert 'control' in body['detail']
