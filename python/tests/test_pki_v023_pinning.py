"""Tests for v0.2.3 PKI hierarchy work: bypass-cert intermediate
pinning + per-issuer authz cache state.

Two main pieces:
  1. EnforceListener prefers `bypass_trust_root` (= bypass-mint) over
     the legacy `auth_trust_root` (= user-mint) when verifying inline
     bypass-cert signatures. This is the load-bearing pinning rule:
     a §5 user-mint-signed leaf must NOT be accepted as a bypass cert.
  2. AuthzCache.last_crl_seqs is per-issuer; the legacy singular
     `last_crl_seq` is an alias for the user-mint entry.
"""
from __future__ import annotations

import base64
import datetime as _dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mssh.ca import cert_minter
from mssh.msshd.authz_cache import AuthzCache, SOURCE_BYPASS
from mssh.msshd.enforce_listener import EnforceListener


# ---- AuthzCache per-issuer state ----------------------------------------

def test_last_crl_seqs_empty_dict_by_default():
    c = AuthzCache()
    assert c.last_crl_seqs == {}
    # Legacy property: user-mint value or 0.
    assert c.last_crl_seq == 0


def test_set_last_crl_seq_advances_user_mint_default():
    c = AuthzCache()
    c.set_last_crl_seq(5)              # default issuer = user-mint
    assert c.last_crl_seqs == {'user-mint': 5}
    assert c.last_crl_seq == 5


def test_set_last_crl_seq_explicit_issuer():
    c = AuthzCache()
    c.set_last_crl_seq(3, issuer='bypass-mint')
    c.set_last_crl_seq(7, issuer='user-mint')
    assert c.last_crl_seqs == {'bypass-mint': 3, 'user-mint': 7}


def test_set_last_crl_seq_monotonic_per_issuer():
    c = AuthzCache()
    c.set_last_crl_seq(10, issuer='auth')
    c.set_last_crl_seq(3, issuer='auth')           # ignored
    c.set_last_crl_seq(10, issuer='auth')          # ignored (==)
    assert c.last_crl_seqs == {'auth': 10}


def test_persist_round_trip_with_per_issuer_seqs(tmp_path):
    p = tmp_path / 'authz_cache.json'
    c1 = AuthzCache(persist_path=p)
    c1.set_last_crl_seq(7, issuer='user-mint')
    c1.set_last_crl_seq(3, issuer='bypass-mint')
    c2 = AuthzCache(persist_path=p)
    assert c2.last_crl_seqs == {'user-mint': 7, 'bypass-mint': 3}


def test_persist_legacy_single_int_is_migrated(tmp_path):
    """A v0.2.2-era persisted cache has only `last_crl_seq: N`.
    On load, this becomes `{'user-mint': N}` in the new dict."""
    p = tmp_path / 'authz_cache.json'
    p.write_text(
        '{"version": 1, "last_crl_seq": 42, "entries": []}')
    c = AuthzCache(persist_path=p)
    assert c.last_crl_seqs == {'user-mint': 42}
    assert c.last_crl_seq == 42


# ---- Bypass-cert pinning to bypass-mint --------------------------------

def _mk_signer(short_name='test-signer'):
    sk = cert_minter.generate_signing_key('ed25519')
    sc = cert_minter._self_signed(short_name, sk)
    return sk, sc


def _mint_bypass_cert(*, signing_key, signing_cert, principal='alice',
                      valid_for=_dt.timedelta(days=30)):
    from mssh.ca.cert_minter import mint_authorization_cert
    test_key = cert_minter.generate_signing_key('ed25519')
    from cryptography.hazmat.primitives.serialization import (
        PublicFormat, Encoding)
    pubkey_blob = test_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    # mssh-ca authz cert minter expects an SSH wire-format pubkey;
    # use a minimal stub by passing the Ed25519 raw blob in the right
    # envelope. Easier path: use cert_minter._self_signed for a fake
    # subject key and build a minimal authz cert by hand.
    # Actually mint_authorization_cert needs an SSH-format blob.
    # For pinning tests we just need a cert signed by a specific key
    # and carrying OID_CA_BYPASS — let's mint via the helper anyway.
    now = _dt.datetime.now(_dt.timezone.utc)
    import struct
    # SSH ssh-ed25519 wire format: u32-len "ssh-ed25519" + u32-len key
    name = b'ssh-ed25519'
    raw = test_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ssh_blob = (struct.pack('>I', len(name)) + name +
                struct.pack('>I', len(raw)) + raw)
    cert, _serial = mint_authorization_cert(
        subject_username=principal,
        subject_pubkey_blob=ssh_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=now,
        not_after=now + valid_for,
        source_bind='10.0.0.0/8',
        server_bind='*',
        channels=['session'],
        ca_bypass=True,
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode('ascii')


def _make_listener(*, bypass_trust_root_pubkey=None,
                   auth_trust_root_pubkey=None):
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
    listener.msshd_version = '0.2.3'
    listener.protocol_version = '1.1'
    listener._auth_trust_root_pubkey = auth_trust_root_pubkey
    listener._bypass_trust_root_pubkey = bypass_trust_root_pubkey
    return listener


@pytest.mark.asyncio
async def test_pinning_accepts_bypass_signed_cert():
    """Cert signed by bypass-mint AND listener pins bypass-mint → ok."""
    bypass_sk, bypass_sc = _mk_signer('bypass-mint')
    listener = _make_listener(bypass_trust_root_pubkey=bypass_sc.public_key())
    cert_b64 = _mint_bypass_cert(
        signing_key=bypass_sk, signing_cert=bypass_sc, principal='alice')

    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64=cert_b64)
    assert ok is True, reason
    assert listener.authz_cache.get('alice') is not None
    assert listener.authz_cache.get('alice').source == SOURCE_BYPASS


@pytest.mark.asyncio
async def test_pinning_rejects_user_mint_signed_cert_when_bypass_pinned():
    """Load-bearing rule: a cert signed by user-mint (or any non-bypass
    signer) must NOT be accepted as a bypass cert when the listener
    has bypass_trust_root configured. Otherwise a §5 user-mint-signed
    leaf could impersonate a bypass cert."""
    user_mint_sk, user_mint_sc = _mk_signer('user-mint')
    bypass_sk, bypass_sc = _mk_signer('bypass-mint')   # separate key
    listener = _make_listener(bypass_trust_root_pubkey=bypass_sc.public_key())
    # Mint with user-mint's key — wrong signer for the pinned bypass root.
    cert_b64 = _mint_bypass_cert(
        signing_key=user_mint_sk, signing_cert=user_mint_sc,
        principal='alice')

    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64=cert_b64)
    assert ok is False
    assert reason == 'bypass_signature_invalid'
    assert listener.authz_cache.get('alice') is None


@pytest.mark.asyncio
async def test_legacy_fallback_uses_auth_trust_root_when_bypass_unset():
    """Backward compat: when only auth_trust_root is configured (the
    v0.2.0 single-signer layout), bypass injection still verifies."""
    sk, sc = _mk_signer('legacy-single-signer')
    listener = _make_listener(auth_trust_root_pubkey=sc.public_key())
    # No bypass_trust_root set; falls back to auth_trust_root.
    cert_b64 = _mint_bypass_cert(
        signing_key=sk, signing_cert=sc, principal='alice')

    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64=cert_b64)
    assert ok is True, reason


@pytest.mark.asyncio
async def test_pinning_refuses_when_no_trust_roots_at_all():
    """Both bypass_trust_root and auth_trust_root unset → fail closed."""
    sk, sc = _mk_signer()
    listener = _make_listener()         # both None
    cert_b64 = _mint_bypass_cert(
        signing_key=sk, signing_cert=sc, principal='alice')

    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64=cert_b64)
    assert ok is False
    assert reason == 'bypass_trust_root_not_configured'


# ---- msshd config loads bypass_trust_root -------------------------------

def test_msshd_config_loads_bypass_trust_root(tmp_path):
    from mssh.msshd.config import MsshdConfig
    cfg_path = tmp_path / 'msshd.yaml'
    cfg_path.write_text(f"""
mode: enforce
fallback:
  host: 127.0.0.1
  port: 22
listen:
  external_address: 127.0.0.1
  external_port: 2200
tls:
  server_cert: {tmp_path}/server.crt
  server_key:  {tmp_path}/server.key
  user_ca_pubkey: {tmp_path}/user-ca.pub
ca:
  endpoints:
    - https://ca-1.internal:8443
  client_cert: {tmp_path}/mtls.crt
  client_key:  {tmp_path}/mtls.key
  ca_pubkey:   {tmp_path}/ca.pub
  auth_trust_root: {tmp_path}/user-mint.pem
  bypass_trust_root: {tmp_path}/bypass-mint.pem
inner:
  sshd_binary: /usr/sbin/sshd
  port_range: [49152, 65535]
users:
  allowed: [alice]
""")
    cfg = MsshdConfig.load(cfg_path)
    assert cfg.ca.bypass_trust_root.endswith('bypass-mint.pem')
    assert cfg.ca.auth_trust_root.endswith('user-mint.pem')
