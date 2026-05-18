"""Tests for the PKI hierarchy foundation (Commit 1 of N).

Covers the additive helpers introduced for the multi-intermediate
hierarchy migration: Intermediate dataclass, compute_pubkey_fp16,
make_issuer_id, _self_signed_root, _issue_intermediate,
load_intermediates, load_root_cert.

These helpers aren't wired into the bootstrap or production code
paths yet (that's Phase 2). Tests here exercise them directly so
the foundation has coverage before the bootstrap refactor lands.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509

from mssh.ca import cert_minter
from mssh.ca.cert_minter import (
    INTERMEDIATE_ROLES, Intermediate,
    _issue_intermediate, _self_signed_root,
    compute_pubkey_fp16, generate_signing_key,
    issue_client_cert, issue_server_cert,
    load_intermediates, load_root_cert,
    make_issuer_id, mint_authorization_cert,
    serialize_certificate, serialize_private_key,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def root_pair():
    key = generate_signing_key('ec')
    cert = _self_signed_root('mssh-test-root', key)
    return key, cert


def _make_intermediate(short_name: str, root_key, root_cert) -> Intermediate:
    ikey = generate_signing_key('ec')
    icert = _issue_intermediate(short_name, ikey, root_key, root_cert)
    return Intermediate(
        short_name=short_name, key=ikey, cert=icert,
        pubkey_fp16=compute_pubkey_fp16(ikey.public_key()),
    )


# ---------------------------------------------------------------------------
# Constants + identifier helpers
# ---------------------------------------------------------------------------


def test_intermediate_roles_present_and_unique():
    """The 4 named intermediate roles are present, in a stable order
    that downstream code can iterate."""
    assert set(INTERMEDIATE_ROLES) == {
        'user-mint', 'bypass-mint', 'host-mint', 'auth',
    }
    assert len(INTERMEDIATE_ROLES) == 4
    assert len(set(INTERMEDIATE_ROLES)) == 4   # unique


def test_compute_pubkey_fp16_length_and_hex():
    """fp16 is 16 lowercase-hex chars (first 16 of SHA256 hex)."""
    key = generate_signing_key('ec')
    fp = compute_pubkey_fp16(key.public_key())
    assert len(fp) == 16
    assert all(c in '0123456789abcdef' for c in fp)


def test_compute_pubkey_fp16_stable():
    """Same key → same fingerprint, every call."""
    key = generate_signing_key('ec')
    a = compute_pubkey_fp16(key.public_key())
    b = compute_pubkey_fp16(key.public_key())
    assert a == b


def test_compute_pubkey_fp16_distinct_per_key():
    """Different keys → different fingerprints (almost certainly)."""
    k1 = generate_signing_key('ec')
    k2 = generate_signing_key('ec')
    assert compute_pubkey_fp16(k1.public_key()) != \
        compute_pubkey_fp16(k2.public_key())


def test_make_issuer_id_format():
    """issuer_id is '<short-name>:<fp16>'."""
    key = generate_signing_key('ec')
    iid = make_issuer_id('user-mint', key.public_key())
    assert iid.startswith('user-mint:')
    assert len(iid.split(':')[1]) == 16


def test_intermediate_issuer_id_property():
    """The dataclass property matches the make_issuer_id() output."""
    key = generate_signing_key('ec')
    cert = _self_signed_root('test', key)
    fp = compute_pubkey_fp16(key.public_key())
    it = Intermediate(short_name='user-mint', key=key, cert=cert,
                      pubkey_fp16=fp)
    assert it.issuer_id == f'user-mint:{fp}'


# ---------------------------------------------------------------------------
# Root + intermediate creation
# ---------------------------------------------------------------------------


def test_self_signed_root_basic_constraints(root_pair):
    _, cert = root_pair
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True
    # Root explicitly allows one level of intermediates underneath.
    assert bc.value.path_length == 1
    assert bc.critical is True


def test_self_signed_root_self_signed(root_pair):
    """Issuer == subject for a root."""
    _, cert = root_pair
    assert cert.issuer == cert.subject


def test_self_signed_root_key_usage(root_pair):
    _, cert = root_pair
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.value.key_cert_sign is True
    assert ku.value.crl_sign is True
    assert ku.value.digital_signature is True


def test_issue_intermediate_is_a_ca_cert(root_pair):
    root_key, root_cert = root_pair
    ikey = generate_signing_key('ec')
    icert = _issue_intermediate('user-mint', ikey, root_key, root_cert)
    bc = icert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.value.ca is True
    # Intermediates can only sign leaves, not further intermediates.
    assert bc.value.path_length == 0


def test_issue_intermediate_signed_by_root(root_pair):
    """The intermediate's issuer field == root's subject."""
    root_key, root_cert = root_pair
    ikey = generate_signing_key('ec')
    icert = _issue_intermediate('user-mint', ikey, root_key, root_cert)
    assert icert.issuer == root_cert.subject


def test_issue_intermediate_subject_carries_short_name(root_pair):
    """The subject includes the short-name in OU so cert dumps are
    readable."""
    root_key, root_cert = root_pair
    ikey = generate_signing_key('ec')
    icert = _issue_intermediate('bypass-mint', ikey, root_key, root_cert)
    ou_attrs = icert.subject.get_attributes_for_oid(
        x509.NameOID.ORGANIZATIONAL_UNIT_NAME)
    assert any(a.value == 'bypass-mint' for a in ou_attrs)


# ---------------------------------------------------------------------------
# load_intermediates + load_root_cert
# ---------------------------------------------------------------------------


def test_load_intermediates_round_trip(tmp_path, root_pair):
    """Persist all 4 intermediates to the standard layout, load them
    back, fingerprints match."""
    root_key, root_cert = root_pair
    # Write the root + 4 intermediates to disk in the canonical layout.
    (tmp_path / 'root-cert.pem').write_bytes(serialize_certificate(root_cert))
    (tmp_path / 'root-key.pem').write_bytes(serialize_private_key(root_key))
    int_dir = tmp_path / 'intermediates'
    int_dir.mkdir()
    expected_fps: dict[str, str] = {}
    for role in INTERMEDIATE_ROLES:
        ikey = generate_signing_key('ec')
        icert = _issue_intermediate(role, ikey, root_key, root_cert)
        rd = int_dir / role
        rd.mkdir()
        (rd / 'cert.pem').write_bytes(serialize_certificate(icert))
        (rd / 'key.pem').write_bytes(serialize_private_key(ikey))
        expected_fps[role] = compute_pubkey_fp16(ikey.public_key())

    intermediates = load_intermediates(tmp_path)
    assert set(intermediates.keys()) == set(INTERMEDIATE_ROLES)
    for role in INTERMEDIATE_ROLES:
        assert intermediates[role].short_name == role
        assert intermediates[role].pubkey_fp16 == expected_fps[role]


def test_load_intermediates_missing_role_raises(tmp_path, root_pair):
    """Missing a single role's files → FileNotFoundError, so the
    operator sees a clear error if their CA dir is partially
    bootstrapped."""
    root_key, root_cert = root_pair
    int_dir = tmp_path / 'intermediates'
    int_dir.mkdir()
    # Write only 3 of the 4 (skip 'auth').
    for role in ('user-mint', 'bypass-mint', 'host-mint'):
        ikey = generate_signing_key('ec')
        icert = _issue_intermediate(role, ikey, root_key, root_cert)
        rd = int_dir / role
        rd.mkdir()
        (rd / 'cert.pem').write_bytes(serialize_certificate(icert))
        (rd / 'key.pem').write_bytes(serialize_private_key(ikey))

    with pytest.raises(FileNotFoundError, match='auth'):
        load_intermediates(tmp_path)


def test_load_root_cert(tmp_path, root_pair):
    _, root_cert = root_pair
    (tmp_path / 'root-cert.pem').write_bytes(serialize_certificate(root_cert))
    loaded = load_root_cert(tmp_path)
    assert loaded.subject == root_cert.subject


# ---------------------------------------------------------------------------
# Backward compat: legacy callers still work
# ---------------------------------------------------------------------------


def test_mint_authorization_cert_legacy_kwargs(test_key, root_pair):
    """mint_authorization_cert with the v1 signing_key+signing_cert
    kwargs still works (the call path used by existing CA code
    that hasn't been migrated to Intermediate yet)."""
    root_key, root_cert = root_pair
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    cert, serial = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing_key=root_key, signing_cert=root_cert,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.0/24', server_bind='*',
        channels=['session'],
    )
    assert serial
    # The leaf names the legacy signer in its issuer field.
    assert cert.issuer == root_cert.subject


def test_mint_authorization_cert_intermediate_kwarg(test_key, root_pair):
    """mint_authorization_cert with signing=Intermediate (new path)
    produces a cert signed by the intermediate, with issuer field
    matching the intermediate's subject."""
    root_key, root_cert = root_pair
    user_mint = _make_intermediate('user-mint', root_key, root_cert)
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    cert, serial = mint_authorization_cert(
        subject_username='alice',
        subject_pubkey_blob=test_key.public_blob,
        signing=user_mint,
        not_before=now, not_after=now + _dt.timedelta(hours=1),
        source_bind='10.0.0.0/24', server_bind='*',
        channels=['session'],
    )
    assert serial
    assert cert.issuer == user_mint.cert.subject


def test_mint_authorization_cert_neither_signing_arg_raises(test_key):
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    with pytest.raises(TypeError, match='signing'):
        mint_authorization_cert(
            subject_username='alice',
            subject_pubkey_blob=test_key.public_blob,
            not_before=now, not_after=now + _dt.timedelta(hours=1),
            source_bind='*', server_bind='*', channels=['session'])


def test_issue_client_cert_legacy_kwargs(root_pair):
    """issue_client_cert with (tls_ca_key, tls_ca_cert) positional
    args works as it did in v1."""
    root_key, root_cert = root_pair
    bundle = issue_client_cert('alice', root_key, root_cert,
                                validity_days=30, key_type='ec')
    # Legacy path: no chain bundle, just the leaf in cert_pem.
    assert b'-----BEGIN CERTIFICATE-----' in bundle.cert_pem
    # ca_cert_pem defaults to the signing cert in legacy mode.
    assert b'-----BEGIN CERTIFICATE-----' in bundle.ca_cert_pem


def test_issue_client_cert_intermediate_path(root_pair):
    """issue_client_cert with signing=Intermediate produces a chain
    bundle (leaf + intermediate) in cert_pem."""
    root_key, root_cert = root_pair
    auth = _make_intermediate('auth', root_key, root_cert)
    bundle = issue_client_cert(
        'admin-alice', signing=auth, validity_days=30,
        root_cert=root_cert, key_type='ec')
    # cert_pem should contain TWO certs (leaf + auth intermediate).
    n = bundle.cert_pem.count(b'-----BEGIN CERTIFICATE-----')
    assert n == 2
    # ca_cert_pem is the root.
    assert b'-----BEGIN CERTIFICATE-----' in bundle.ca_cert_pem


def test_issue_server_cert_includes_san(root_pair):
    """issue_server_cert sets EKU=serverAuth and respects SANs."""
    root_key, root_cert = root_pair
    host_mint = _make_intermediate('host-mint', root_key, root_cert)
    bundle = issue_server_cert(
        'srv-acct', signing=host_mint, validity_days=30,
        sans=['DNS:srv-acct.internal', 'IP:10.0.0.10'],
        root_cert=root_cert)
    # Parse the leaf out of the bundle and check SAN + EKU.
    leaf = x509.load_pem_x509_certificate(
        bundle.cert_pem.split(b'-----END CERTIFICATE-----', 1)[0]
        + b'-----END CERTIFICATE-----\n')
    san = leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    dns_names = san.get_values_for_type(x509.DNSName)
    assert 'srv-acct.internal' in dns_names
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    from cryptography.x509.oid import ExtendedKeyUsageOID
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
