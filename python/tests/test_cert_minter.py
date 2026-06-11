"""Unit tests for ca/cert_minter.py — bootstrap and authorization-cert minting.

Tests: §4.3.4, §2.2, §2.4, §14.5, §14.8
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mssh.ca.cert_minter import (OID_CHANNEL_POLICY, OID_SERVER_BIND,
                            OID_SOURCE_BIND, bootstrap_ca, issue_client_cert,
                            load_certificate, load_private_key,
                            mint_authorization_cert)


def test_bootstrap_produces_files(tmp_path):
    d = tmp_path / 'ca'
    artifacts = bootstrap_ca(d)
    for f in [
        'signing-key.pem', 'signing-cert.pem',
        'tls-ca-cert.pem', 'tls-ca-key.pem',
        'tls-server-cert.pem', 'tls-server-key.pem',
        'bootstrap-admin-cert.pem', 'bootstrap-admin-key.pem',
    ]:
        assert (d / f).exists(), f
    # Bootstrap admin cert subject CN matches what we expect.
    assert artifacts.bootstrap_admin_subject == 'CN=bootstrap-admin'


def test_issue_client_cert_chain(tmp_path):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    tls_ca_key = load_private_key(d / 'tls-ca-key.pem')
    tls_ca_cert = load_certificate(d / 'tls-ca-cert.pem')
    issued = issue_client_cert('srv1', tls_ca_key, tls_ca_cert)
    cert = x509.load_pem_x509_certificate(issued.cert_pem)
    assert cert.subject.rfc4514_string() == 'CN=srv1'
    assert cert.issuer == tls_ca_cert.subject


def test_mint_authorization_cert_extensions(tmp_path, test_key):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, serial = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session', 'direct-tcpip'],
        force_command='/bin/echo',
    )
    assert serial
    # Inspect extensions.
    oids = {ext.oid.dotted_string: ext for ext in cert.extensions}
    assert OID_SOURCE_BIND.dotted_string in oids
    assert OID_SERVER_BIND.dotted_string in oids
    assert OID_CHANNEL_POLICY.dotted_string in oids
    # Source-bind extension is critical.
    assert oids[OID_SOURCE_BIND.dotted_string].critical


def test_mint_authorization_cert_signature_verifies(tmp_path, test_key):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
    )
    # Use the shim's verifier (defense in depth path).
    from mssh.shim.shim import _verify_cert_signed_by
    assert _verify_cert_signed_by(cert, signing_cert)


# R-1 reconciliation tests — Verifies §14.5 OID format + §14.8 criticality.
# Tests: §14.5, §14.8

def test_r1_force_command_extension_is_critical(tmp_path, test_key):
    """Verifies §14.5 — OID_FORCE_COMMAND is critical-when-present.

    R-1 flipped this from non-critical so a validator that ignores
    the marker can't silently bypass the force-command restriction.
    """
    from mssh.ca.cert_minter import OID_FORCE_COMMAND
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
        force_command='/usr/bin/safe-shell',
    )
    oids = {ext.oid.dotted_string: ext for ext in cert.extensions}
    assert OID_FORCE_COMMAND.dotted_string in oids
    assert oids[OID_FORCE_COMMAND.dotted_string].critical, \
        'OID_FORCE_COMMAND must be critical (R-1)'


def test_r1_environment_extension_is_critical(tmp_path, test_key):
    """Verifies §14.5 — OID_ENVIRONMENT is critical-when-present.

    R-1 flipped this from non-critical so a validator that ignores
    the marker can't silently bypass the env-injection restriction.
    """
    from mssh.ca.cert_minter import OID_ENVIRONMENT
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
        environment={'PATH': '/usr/local/bin'},
    )
    oids = {ext.oid.dotted_string: ext for ext in cert.extensions}
    assert OID_ENVIRONMENT.dotted_string in oids
    assert oids[OID_ENVIRONMENT.dotted_string].critical, \
        'OID_ENVIRONMENT must be critical (R-1)'


def test_r1_ca_bypass_marker_is_null_encoded(tmp_path, test_key):
    """Verifies §14.5 — OID_CA_BYPASS format is ASN.1 NULL.

    R-1 changed this from UTF8String 'true' to ASN.1 NULL (0x05 0x00).
    The presence of the marker is the signal; no value is meaningful.
    """
    from mssh.ca.cert_minter import OID_CA_BYPASS
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='0.0.0.0/0', server_bind='*',
        channels=['session'],
        ca_bypass=True,
    )
    oids = {ext.oid.dotted_string: ext for ext in cert.extensions}
    assert OID_CA_BYPASS.dotted_string in oids
    marker = oids[OID_CA_BYPASS.dotted_string]
    assert marker.critical, 'OID_CA_BYPASS must be critical'
    # UnrecognizedExtension's .value attribute holds the raw extension bytes.
    raw = marker.value.value
    assert raw == b'\x05\x00', \
        f'OID_CA_BYPASS must be DER NULL (0x05 0x00), got {raw!r}'


def test_r1_msshd_known_critical_accepts_new_critical_extensions(tmp_path, test_key):
    """Verifies §14.5 — msshd's KNOWN_CRITICAL lists FORCE_COMMAND + ENVIRONMENT
    so flipped-critical extensions don't trigger defense-in-depth rejection.

    R-1 added these to KNOWN_CRITICAL alongside the criticality flip in
    the CA so the wire continues to validate end-to-end.
    """
    from mssh.msshd.policy import (KNOWN_CRITICAL, OID_FORCE_COMMAND,
                                   OID_ENVIRONMENT, OID_CA_BYPASS)
    assert OID_FORCE_COMMAND in KNOWN_CRITICAL
    assert OID_ENVIRONMENT in KNOWN_CRITICAL
    assert OID_CA_BYPASS in KNOWN_CRITICAL  # already present pre-R-1

    from mssh.shim.shim import _KNOWN_CRITICAL as SHIM_KNOWN_CRITICAL
    assert OID_FORCE_COMMAND in SHIM_KNOWN_CRITICAL
    assert OID_ENVIRONMENT in SHIM_KNOWN_CRITICAL
    assert OID_CA_BYPASS in SHIM_KNOWN_CRITICAL  # added in R-1


# R-2 reconciliation tests — Verifies §14.8 authz/bypass cert profile.
# Tests: §14.8, §13.3 (CRLDP-for-CRL-discovery)

def test_r2_authz_cert_has_key_usage_critical(tmp_path, test_key):
    """Verifies §14.8 — authz cert carries KeyUsage(digital_signature, critical).

    R-2 added KeyUsage so the cert cannot be misused as e.g. a key-cert-sign
    cert. KeyUsage is in KNOWN_CRITICAL via the OID '2.5.29.15'.
    """
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
    )
    ku_ext = cert.extensions.get_extension_for_oid(x509.OID_KEY_USAGE)
    assert ku_ext.critical
    assert ku_ext.value.digital_signature is True
    assert ku_ext.value.key_cert_sign is False


def test_r2_authz_cert_has_eku_client_auth_critical(tmp_path, test_key):
    """Verifies §14.8 — authz cert carries ExtendedKeyUsage(clientAuth, critical).

    R-2 added EKU so the cert cannot be presented as a TLS server cert.
    """
    from cryptography.x509 import oid as _oid
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
    )
    eku_ext = cert.extensions.get_extension_for_oid(x509.OID_EXTENDED_KEY_USAGE)
    assert eku_ext.critical
    assert _oid.ExtendedKeyUsageOID.CLIENT_AUTH in eku_ext.value
    assert _oid.ExtendedKeyUsageOID.SERVER_AUTH not in eku_ext.value


def test_r2_authz_cert_has_san_rfc822(tmp_path, test_key):
    """Verifies §14.8 — authz cert carries SubjectAlternativeName with rfc822 binding."""
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
    )
    san_ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
    rfc822 = san_ext.value.get_values_for_type(x509.RFC822Name)
    assert rfc822 == ['alice@mssh']


def test_r2_authz_cert_has_subject_key_identifier(tmp_path, test_key):
    """Verifies §14.8 — authz cert carries SubjectKeyIdentifier."""
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
    )
    cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_KEY_IDENTIFIER)


def test_r2_authz_cert_includes_crldp_when_url_provided(tmp_path, test_key):
    """Verifies §14.8 + §13.3 — CRLDP is embedded when crl_url is set.

    External X.509 validators (non-mssh) use CRLDP to discover the
    revocation list. The mssh native CRL-sync path doesn't use this;
    the cert is for cross-validator interop.
    """
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
        crl_url='https://ca.example.com/v1/crl.pem?issuer=user-mint:abc123',
    )
    crldp = cert.extensions.get_extension_for_oid(
        x509.OID_CRL_DISTRIBUTION_POINTS)
    assert not crldp.critical
    urls = []
    for dp in crldp.value:
        for name in dp.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    assert 'https://ca.example.com/v1/crl.pem?issuer=user-mint:abc123' in urls


def test_r2_authz_cert_no_crldp_when_url_unset(tmp_path, test_key):
    """Verifies §14.8 — CRLDP is OPTIONAL; absent when crl_url=None."""
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.42', server_bind='srv1',
        channels=['session'],
    )
    import pytest as _pytest
    with _pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_oid(
            x509.OID_CRL_DISTRIBUTION_POINTS)


def test_r2_bypass_cert_has_all_r2_extensions(tmp_path, test_key):
    """Verifies §14.8 — bypass cert carries the same R-2 hardening
    extensions as authz cert PLUS the CA_BYPASS marker.
    """
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    signing_key = load_private_key(d / 'signing-key.pem')
    signing_cert = load_certificate(d / 'signing-cert.pem')
    now = _dt.datetime.now(tz=_dt.timezone.utc)
    cert, _ = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='0.0.0.0/0', server_bind='*',
        channels=['session'],
        ca_bypass=True,
        crl_url='https://ca.example.com/v1/crl.pem?issuer=bypass-mint:def456',
    )
    # All R-2 extensions present.
    for required_oid in [
        x509.OID_KEY_USAGE, x509.OID_EXTENDED_KEY_USAGE,
        x509.OID_SUBJECT_ALTERNATIVE_NAME, x509.OID_SUBJECT_KEY_IDENTIFIER,
        x509.OID_CRL_DISTRIBUTION_POINTS,
    ]:
        cert.extensions.get_extension_for_oid(required_oid)
    # Plus the bypass marker.
    from mssh.ca.cert_minter import OID_CA_BYPASS
    cert.extensions.get_extension_for_class
    found_bypass = any(ext.oid.dotted_string == OID_CA_BYPASS.dotted_string
                        for ext in cert.extensions)
    assert found_bypass
