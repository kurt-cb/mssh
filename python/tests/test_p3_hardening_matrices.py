"""Phase 3 — §13.9.7 default-deny matrix + §13.9.8 cert-OID enforcement
matrix. Parametrized cross-validator + cross-config tests that
exercise every security-relevant field absence + every cert marker
enforcement site, so a future regression surfaces against the
hardening bar.

Tests: §13.9.7, §13.9.8
"""
from __future__ import annotations

import datetime as _dt

import pytest
from cryptography import x509

from mssh.ca.audit import AuditLog
from mssh.ca.cert_minter import (OID_CA_BYPASS, OID_FORCE_COMMAND,
                                  OID_ENVIRONMENT, OID_SOURCE_BIND,
                                  bootstrap_ca, load_certificate,
                                  load_private_key, mint_authorization_cert)
from mssh.ca.config import CAConfig
from mssh.msshd.config import (MODE_ENFORCE, MODE_GATED, MsshdConfig)


# ---------------------------------------------------------------------------
# §13.9.7 default-deny matrix
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('field', [
    'signing_key', 'signing_cert', 'tls_cert', 'tls_key', 'client_ca_cert',
])
def test_p3_caconfig_required_field_absent_refuses(tmp_path, field):
    """§13.9.7 default-deny: every security-critical CAConfig field
    individually causes refuse-to-start when absent.
    """
    sk = tmp_path / 'k1.pem'; sk.write_text('-')
    sc = tmp_path / 'c1.pem'; sc.write_text('-')
    tc = tmp_path / 'c2.pem'; tc.write_text('-')
    tk = tmp_path / 'k2.pem'; tk.write_text('-')
    cca = tmp_path / 'c3.pem'; cca.write_text('-')
    cfg = CAConfig(
        listen_host='127.0.0.1', listen_port=4443,
        signing_key=str(sk), signing_cert=str(sc),
        tls_cert=str(tc), tls_key=str(tk), client_ca_cert=str(cca),
        identity_trust_roots=[str(sc)],
    )
    setattr(cfg, field, '')
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert field in str(exc.value)


@pytest.mark.parametrize('field', [
    'signing_key', 'signing_cert', 'tls_cert', 'tls_key', 'client_ca_cert',
])
def test_p3_caconfig_required_field_path_missing_refuses(tmp_path, field):
    """§13.9.7 default-deny: each path that doesn't exist on disk → refuse."""
    sk = tmp_path / 'k1.pem'; sk.write_text('-')
    sc = tmp_path / 'c1.pem'; sc.write_text('-')
    tc = tmp_path / 'c2.pem'; tc.write_text('-')
    tk = tmp_path / 'k2.pem'; tk.write_text('-')
    cca = tmp_path / 'c3.pem'; cca.write_text('-')
    cfg = CAConfig(
        listen_host='127.0.0.1', listen_port=4443,
        signing_key=str(sk), signing_cert=str(sc),
        tls_cert=str(tc), tls_key=str(tk), client_ca_cert=str(cca),
        identity_trust_roots=[str(sc)],
    )
    setattr(cfg, field, str(tmp_path / 'missing.pem'))
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert 'does not exist' in str(exc.value)


def test_p3_msshd_enforce_refuses_missing_tls_field(tmp_path):
    """§13.9.7 default-deny for msshd enforce-mode: missing tls.server_cert."""
    cfg = MsshdConfig()
    cfg.mode = MODE_ENFORCE
    cfg.listen.external_port = 22
    # No TLS material set.
    with pytest.raises(ValueError):
        cfg.validate()


def test_p3_msshd_gated_refuses_missing_tls_field(tmp_path):
    """§13.9.7 default-deny for msshd gated-mode: missing tls.server_cert.
    Gated mode shares enforce's mTLS requirement (§5.3.3).
    """
    cfg = MsshdConfig()
    cfg.mode = MODE_GATED
    cfg.listen.external_port = 22
    cfg.fallback.port = 22022
    with pytest.raises(ValueError):
        cfg.validate()


def test_p3_msshd_enforce_refuses_bad_auth_trust_root_path(tmp_path):
    """§13.9.7 default-deny: auth_trust_root pointing at nonexistent
    path → refuse to start, even though the field is technically optional.
    """
    # Provide valid TLS + CA paths first.
    for fname in ('cert.pem', 'key.pem', 'pub.pem'):
        (tmp_path / fname).write_text('-')
    cfg = MsshdConfig()
    cfg.mode = MODE_ENFORCE
    cfg.listen.external_port = 22
    cfg.tls.server_cert = str(tmp_path / 'cert.pem')
    cfg.tls.server_key = str(tmp_path / 'key.pem')
    cfg.tls.user_ca_pubkey = str(tmp_path / 'pub.pem')
    cfg.ca.endpoints = ['https://ca:4443']
    cfg.ca.client_cert = str(tmp_path / 'cert.pem')
    cfg.ca.client_key = str(tmp_path / 'key.pem')
    cfg.ca.ca_pubkey = str(tmp_path / 'pub.pem')
    cfg.users.allowed = ['*']
    cfg.ca.auth_trust_root = str(tmp_path / 'does-not-exist.pem')
    with pytest.raises(ValueError) as exc:
        cfg.validate()
    assert 'auth_trust_root' in str(exc.value)


# ---------------------------------------------------------------------------
# §13.9.8 cert OID + marker enforcement matrix
# ---------------------------------------------------------------------------

@pytest.fixture
def ca_dir(tmp_path):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    return d


def _mint_authz(ca_dir, test_key, **kw):
    sk = load_private_key(ca_dir / 'signing-key.pem')
    sc = load_certificate(ca_dir / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    return mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=sk, signing_cert=sc,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
        **kw)


def test_p3_oid_authz_cert_carries_source_bind_critical(ca_dir, test_key):
    """§13.9.8 — every authz cert MUST carry OID_SOURCE_BIND critical."""
    cert, _ = _mint_authz(ca_dir, test_key)
    ext = cert.extensions.get_extension_for_oid(OID_SOURCE_BIND)
    assert ext.critical


def test_p3_oid_force_command_is_critical_when_present(ca_dir, test_key):
    """§13.9.8 + R-1 — OID_FORCE_COMMAND critical-when-present."""
    cert, _ = _mint_authz(ca_dir, test_key, force_command='/bin/echo')
    ext = cert.extensions.get_extension_for_oid(OID_FORCE_COMMAND)
    assert ext.critical


def test_p3_oid_environment_is_critical_when_present(ca_dir, test_key):
    """§13.9.8 + R-1 — OID_ENVIRONMENT critical-when-present."""
    cert, _ = _mint_authz(ca_dir, test_key, environment={'K': 'V'})
    ext = cert.extensions.get_extension_for_oid(OID_ENVIRONMENT)
    assert ext.critical


def test_p3_oid_ca_bypass_only_on_bypass_certs(ca_dir, test_key):
    """§13.9.8 — OID_CA_BYPASS marker MUST be absent on normal authz certs
    and MUST be critical on bypass certs."""
    plain_cert, _ = _mint_authz(ca_dir, test_key, ca_bypass=False)
    with pytest.raises(x509.ExtensionNotFound):
        plain_cert.extensions.get_extension_for_oid(OID_CA_BYPASS)

    bypass_cert, _ = _mint_authz(ca_dir, test_key, ca_bypass=True)
    ext = bypass_cert.extensions.get_extension_for_oid(OID_CA_BYPASS)
    assert ext.critical


def test_p3_authz_cert_has_required_x509_hardening_extensions(ca_dir, test_key):
    """§13.9.8 + R-2 — every authz cert MUST carry the R-2 hardening
    extension set (KeyUsage critical, EKU critical, BasicConstraints
    critical, SKI, SAN).
    """
    cert, _ = _mint_authz(ca_dir, test_key)
    required = [
        x509.OID_BASIC_CONSTRAINTS,
        x509.OID_KEY_USAGE,
        x509.OID_EXTENDED_KEY_USAGE,
        x509.OID_SUBJECT_KEY_IDENTIFIER,
        x509.OID_SUBJECT_ALTERNATIVE_NAME,
    ]
    for oid in required:
        ext = cert.extensions.get_extension_for_oid(oid)
        assert ext is not None


def test_p3_known_critical_includes_every_authz_marker():
    """§13.9.8 — KNOWN_CRITICAL on the consumer side must list every
    critical marker the CA can emit. msshd + shim must agree.
    """
    from mssh.msshd.policy import KNOWN_CRITICAL
    from mssh.shim.shim import _KNOWN_CRITICAL as SHIM_CRITICAL
    required = {
        OID_SOURCE_BIND.dotted_string,
        '1.3.6.1.4.1.55555.1.2',                # OID_SERVER_BIND
        '1.3.6.1.4.1.55555.1.3',                # OID_CHANNEL_POLICY
        OID_FORCE_COMMAND.dotted_string,        # R-1
        OID_ENVIRONMENT.dotted_string,           # R-1
        OID_CA_BYPASS.dotted_string,
        '2.5.29.19',                            # BasicConstraints
        '2.5.29.15',                            # KeyUsage (R-2)
        '2.5.29.37',                            # ExtendedKeyUsage (R-2)
    }
    assert required.issubset(KNOWN_CRITICAL)
    assert required.issubset(SHIM_CRITICAL)


def test_p3_audit_chain_starts_with_genesis_hash(tmp_path):
    """§13.9.8 + §13.9.6 — first audit entry MUST carry the genesis
    sentinel prev_hash, so a verifier can detect a truncated log.
    """
    from mssh.ca.audit import _ZERO_HASH
    a = AuditLog(tmp_path / 'audit.jsonl')
    a.write({'action': 'authorize', 'result': 'granted'})
    e = a.read_all()[0]
    assert e['prev_hash'] == _ZERO_HASH


def test_p3_audit_chain_breaks_detectable(tmp_path):
    """§13.9.6 — verify_chain() detects any post-write modification."""
    import json
    p = tmp_path / 'audit.jsonl'
    a = AuditLog(p)
    a.write({'action': 'e1'})
    a.write({'action': 'e2'})
    a.write({'action': 'e3'})
    # Modify line 2.
    lines = p.read_text().splitlines()
    entry = json.loads(lines[1])
    entry['action'] = 'TAMPERED'
    lines[1] = json.dumps(entry, separators=(',', ':'), sort_keys=True)
    p.write_text('\n'.join(lines) + '\n')
    a2 = AuditLog(p)
    broken = a2.verify_chain()
    assert broken, '§13.9.6: tamper must be detectable'
