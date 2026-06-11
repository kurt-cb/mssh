"""Tests for v0.2.5 (Commit 5b): External Intermediate CA tier.

Validates:
  - Mint shape: cert markers (Organization=name, OU=external),
    BasicConstraints.path_length set, signed by root
  - Key NOT retained on the CA side; only the public cert
  - Trust-store-exclusion property: validators that pin to an
    internal intermediate refuse leaves signed by external-X
  - RBAC + audit + 503 in legacy single-signer mode

Tests: §2.6, §15.3
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.crl import CRLRegistry
from mssh.ca.enrollment import Admin, Enrollment


@pytest.fixture
def ca_dir(tmp_path):
    d = tmp_path / 'ca'
    cert_minter.bootstrap_ca(d)
    return d


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
        crl=CRLRegistry(ca_dir / 'crl'),
        ca_dir=str(ca_dir),
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


@pytest.fixture
def user_admin():
    return Admin(name='ua', role='user-admin', mtls_subject='CN=ua')


# ---- Mint shape --------------------------------------------------------

def test_mint_external_returns_cert_and_key(adminctx, superuser):
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'partner-x'})
    assert status == 201
    assert body['name'] == 'partner-x'
    assert body['cert_pem'].startswith('-----BEGIN CERTIFICATE-----')
    assert body['key_pem'].startswith('-----BEGIN PRIVATE KEY-----')
    assert body['issuer_id'].startswith('external-partner-x:')
    assert 'retain' in body['warning'].lower()


def test_mint_external_cert_carries_required_markers(adminctx, superuser):
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'partner-x', 'path_length': 1})
    cert = x509.load_pem_x509_certificate(body['cert_pem'].encode('ascii'))
    # Organization = name, OrganizationalUnit = "external".
    org = next(a.value for a in cert.subject
                if a.oid.dotted_string == '2.5.4.10')
    ou = next(a.value for a in cert.subject
               if a.oid.dotted_string == '2.5.4.11')
    assert org == 'partner-x'
    assert ou == 'external'
    # path_length plumbs through.
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 1


def test_mint_external_signed_by_root(adminctx, superuser, ca_dir):
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'partner-x'})
    cert = x509.load_pem_x509_certificate(body['cert_pem'].encode('ascii'))
    root = cert_minter.load_root_cert(ca_dir)
    # Issuer subject == root's subject.
    assert cert.issuer == root.subject


def test_mint_external_persists_cert_only_not_key(adminctx, superuser, ca_dir):
    """The CA stores the cert for audit/revocation but does NOT
    retain the private key — that's the whole point of delegation."""
    admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'partner-x'})
    target = ca_dir / 'external' / 'partner-x'
    assert (target / 'cert.pem').exists()
    assert not (target / 'key.pem').exists()


def test_mint_external_default_path_length_zero(adminctx, superuser):
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'leaf-only'})
    assert body['path_length'] == 0


# ---- Validation: input checks ------------------------------------------

def test_mint_external_requires_name(adminctx, superuser):
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {})
    assert status == 400
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': ''})
    assert status == 400


def test_mint_external_rejects_path_traversal_in_name(adminctx, superuser):
    """Names go straight to filesystem paths — reject ../ traversal."""
    status, _ = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': '../oops'})
    assert status == 400
    status, _ = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': '.hidden'})
    assert status == 400


def test_mint_external_rejects_negative_path_length(adminctx, superuser):
    status, _ = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'x', 'path_length': -1})
    assert status == 400


def test_mint_external_duplicate_name_conflicts(adminctx, superuser):
    admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'twice'})
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'twice'})
    assert status == 409


# ---- RBAC -------------------------------------------------------------

def test_mint_external_forbidden_for_non_superuser(adminctx, user_admin):
    status, _ = admin_handlers.external_intermediate_mint(
        adminctx, user_admin, {'name': 'partner-x'})
    assert status == 403


def test_mint_external_503_when_no_ca_dir(adminctx, superuser):
    adminctx.ca_dir = ''
    status, _ = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'partner-x'})
    assert status == 503


def test_mint_external_audited(adminctx, superuser, ca_dir):
    admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'partner-x'})
    audit_lines = (ca_dir / 'audit.jsonl').read_text().splitlines()
    rotate_entries = [
        line for line in audit_lines if 'intermediate.external.mint' in line]
    assert len(rotate_entries) == 1


# ---- list-external ----------------------------------------------------

def test_list_external_empty_initially(adminctx, superuser):
    status, body = admin_handlers.external_intermediate_list(
        adminctx, superuser)
    assert status == 200
    assert body['external_intermediates'] == []


def test_list_external_includes_minted(adminctx, superuser):
    admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'a', 'path_length': 0})
    admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'b', 'path_length': 1})
    status, body = admin_handlers.external_intermediate_list(
        adminctx, superuser)
    names = {e['name'] for e in body['external_intermediates']}
    assert names == {'a', 'b'}
    path_lengths = {e['name']: e['path_length']
                     for e in body['external_intermediates']}
    assert path_lengths == {'a': 0, 'b': 1}


# ---- Trust-store-exclusion property ------------------------------------

def test_external_cert_not_in_internal_intermediates(adminctx, superuser,
                                                       ca_dir):
    """External intermediates live under <ca_dir>/external/, NOT
    under <ca_dir>/intermediates/. The 4-role list returned by
    load_intermediates() must NOT include external-X."""
    admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'partner-x'})
    internal = cert_minter.load_intermediates(ca_dir)
    assert 'external-partner-x' not in internal
    assert 'partner-x' not in internal


def test_msshd_bypass_pinning_refuses_external_signed_leaf(adminctx,
                                                             superuser,
                                                             ca_dir):
    """Load-bearing rule from the trust-model amendment: msshd's
    bypass_trust_root pins to bypass-mint. A bypass-marker cert signed
    by an external-X (chains-to-root through external-X, never
    through bypass-mint) must FAIL signature verification, because
    msshd never has external-X's public key in its trust store."""
    import base64
    import struct
    from mssh.ca.cert_minter import mint_authorization_cert
    from mssh.msshd.authz_cache import AuthzCache
    from mssh.msshd.enforce_listener import EnforceListener
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PublicFormat)

    # Mint external-X.
    _, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'attacker', 'path_length': 1})
    ext_key = serialization.load_pem_private_key(
        body['key_pem'].encode('ascii'), password=None)
    ext_cert = x509.load_pem_x509_certificate(
        body['cert_pem'].encode('ascii'))

    # External-X mints a leaf carrying the bypass marker. Attacker's
    # whole gambit: "if msshd doesn't pin to bypass-mint specifically,
    # it might just chain → root and accept this."
    test_key = cert_minter.generate_signing_key('ed25519')
    name = b'ssh-ed25519'
    raw = test_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ssh_blob = (struct.pack('>I', len(name)) + name +
                struct.pack('>I', len(raw)) + raw)
    now = _dt.datetime.now(_dt.timezone.utc)
    cert, _serial = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=ssh_blob,
        signing_key=ext_key, signing_cert=ext_cert,
        not_before=now,
        not_after=now + _dt.timedelta(days=30),
        source_bind='0.0.0.0/0',
        server_bind='*', channels=['session'],
        ca_bypass=True,
    )
    cert_b64 = base64.b64encode(
        cert.public_bytes(Encoding.DER)).decode('ascii')

    # Set up a listener that pins bypass to bypass-mint (the correct
    # pinning per Commit 4b). The attacker's cert chains to root via
    # external-X, NOT via bypass-mint, so signature verification should
    # fail.
    bypass_mint = cert_minter.load_intermediates(ca_dir)['bypass-mint']
    listener = object.__new__(EnforceListener)
    listener.authz_cache = AuthzCache()
    listener.cfg = None
    listener.user_ca = None
    listener.ca_client = None
    listener.inner_sshd = None
    listener.crl_sync = None
    listener._last_known_ca_crl_seqs = {}
    listener.inner_sshd_kind = 'openssh'
    listener.inner_sshd_version = ''
    listener.msshd_version = '0.2.5'
    listener.protocol_version = '1.1'
    listener._auth_trust_root_pubkey = None
    listener._bypass_trust_root_pubkey = bypass_mint.cert.public_key()

    import asyncio
    # Python 3.10+: get_event_loop() no longer auto-creates one in
    # threads that don't already have a running loop. Use asyncio.run()
    # to spin up a fresh loop for the coroutine call.
    ok, reason = asyncio.run(
        listener._handle_bypass_injection(
            conn_id='t', mtls_principal='alice', peer_der=b'',
            bypass_cert_b64=cert_b64))
    assert ok is False
    assert reason == 'bypass_signature_invalid'
