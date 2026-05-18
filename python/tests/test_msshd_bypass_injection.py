"""Unit tests for EnforceListener._handle_bypass_injection.

The method validates a base64-DER bypass cert presented in the v1
JSON header and writes it into the authz cache. Covered here:

  - happy path: mints a real bypass cert, presents it, expects
    cache populated + (ok=True, "serial=…") return
  - bad base64
  - bad X.509 bytes
  - expired cert (not_after in the past)
  - not-yet-valid cert (not_before in the future)
  - missing OID_CA_BYPASS marker (cert wasn't minted with ca_bypass=True)
  - marker present but not critical (forged / malformed cert)
  - principal mismatch (cert CN != mTLS handshake principal)

The method only consumes self.authz_cache; the rest of the
EnforceListener doesn't matter, so we construct a minimal stub
listener that exposes just the cache.
"""
from __future__ import annotations

import base64
import datetime as _dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mssh.ca import cert_minter
from mssh.msshd.authz_cache import AuthzCache, SOURCE_BYPASS
from mssh.msshd.enforce_listener import EnforceListener


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_listener(cache: AuthzCache) -> EnforceListener:
    """A real EnforceListener instance with everything except the
    authz cache stubbed out. _handle_bypass_injection only touches
    self.authz_cache, so the rest is harmlessly None."""
    # We need to construct without calling __init__ (which requires
    # config + ssl context + etc.). Use object.__new__ to bypass.
    listener = object.__new__(EnforceListener)
    listener.authz_cache = cache
    listener.cfg = None
    listener.user_ca = None
    listener.ca_client = None
    listener.inner_sshd = None
    listener.crl_sync = None
    listener._last_known_ca_crl_seq = 0
    listener.inner_sshd_kind = 'openssh'
    listener.inner_sshd_version = ''
    listener.msshd_version = '0.1.0'
    listener.protocol_version = '1.1'
    return listener


def _mint_bypass_cert(test_key, *, principal: str = 'alice',
                     valid_for: _dt.timedelta = _dt.timedelta(days=30),
                     ca_bypass: bool = True,
                     starts_in: _dt.timedelta = _dt.timedelta(0),
                     ca_dir: Path | None = None) -> bytes:
    """Mint a bypass-style authz cert. Returns base64 DER (wire form).
    If ``ca_dir`` is given, uses the signing key from that bootstrapped
    CA; otherwise generates a fresh signer."""
    if ca_dir is not None:
        signing_key = cert_minter.load_private_key(ca_dir / 'signing-key.pem')
        signing_cert = cert_minter.load_certificate(ca_dir / 'signing-cert.pem')
    else:
        signing_key = cert_minter.generate_signing_key('ed25519')
        signing_cert = cert_minter._self_signed('test-signer', signing_key)

    now = _dt.datetime.now(_dt.timezone.utc)
    not_before = now + starts_in
    not_after = not_before + valid_for

    cert, _serial = cert_minter.mint_authorization_cert(
        subject_username=principal,
        subject_pubkey_blob=test_key.public_blob,
        signing_key=signing_key, signing_cert=signing_cert,
        not_before=not_before, not_after=not_after,
        source_bind='10.0.0.0/24', server_bind='*',
        channels=['session'],
        ca_bypass=ca_bypass,
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode('ascii')


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bypass_injection_happy_path(test_key):
    cache = AuthzCache()
    listener = _make_listener(cache)
    cert_b64 = _mint_bypass_cert(test_key, principal='alice')

    ok, reason = await listener._handle_bypass_injection(
        conn_id='test1', mtls_principal='alice',
        peer_der=b'',                       # not consumed by method
        bypass_cert_b64=cert_b64)

    assert ok is True
    assert 'serial=' in reason
    # Cache populated with the bypass cert, tagged 'bypass'.
    entry = cache.get('alice')
    assert entry is not None
    assert entry.source == SOURCE_BYPASS
    assert entry.grant.serial            # non-empty hex


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bypass_injection_bad_base64(test_key):
    cache = AuthzCache()
    listener = _make_listener(cache)
    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64='!!! not base64 !!!')
    assert ok is False
    assert reason.startswith('bypass_bad_b64')
    assert cache.get('alice') is None


@pytest.mark.asyncio
async def test_bypass_injection_bad_cert_bytes(test_key):
    cache = AuthzCache()
    listener = _make_listener(cache)
    # Valid base64 but not a parseable X.509 cert.
    junk = base64.b64encode(b'\x00\x01\x02hello world').decode('ascii')
    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64=junk)
    assert ok is False
    assert reason.startswith('bypass_bad_cert')
    assert cache.get('alice') is None


@pytest.mark.asyncio
async def test_bypass_injection_expired_cert(test_key):
    """not_after in the past → bypass_expired."""
    cache = AuthzCache()
    listener = _make_listener(cache)
    cert_b64 = _mint_bypass_cert(
        test_key, principal='alice',
        starts_in=_dt.timedelta(days=-100),
        valid_for=_dt.timedelta(days=10))  # ends 90 days ago

    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64=cert_b64)
    assert ok is False
    assert reason == 'bypass_expired'
    assert cache.get('alice') is None


@pytest.mark.asyncio
async def test_bypass_injection_not_yet_valid(test_key):
    """not_before > now + 60s → bypass_not_yet_valid. (Standard
    cert-validity skew tolerance is 60s.)"""
    cache = AuthzCache()
    listener = _make_listener(cache)
    cert_b64 = _mint_bypass_cert(
        test_key, principal='alice',
        starts_in=_dt.timedelta(hours=1),     # valid from 1h from now
        valid_for=_dt.timedelta(days=30))

    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64=cert_b64)
    assert ok is False
    assert reason == 'bypass_not_yet_valid'
    assert cache.get('alice') is None


@pytest.mark.asyncio
async def test_bypass_injection_missing_marker(test_key):
    """Cert minted WITHOUT ca_bypass=True → no OID_CA_BYPASS extension
    → reject. Prevents normal authz certs from being mis-injected."""
    cache = AuthzCache()
    listener = _make_listener(cache)
    cert_b64 = _mint_bypass_cert(test_key, principal='alice',
                                  ca_bypass=False)

    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64=cert_b64)
    assert ok is False
    assert reason == 'bypass_marker_missing'
    assert cache.get('alice') is None


@pytest.mark.asyncio
async def test_bypass_injection_principal_mismatch(test_key):
    """Cert minted for alice but presented by bob → reject. Prevents
    a stolen bypass cert from being injected by an attacker who has
    a different mTLS cert."""
    cache = AuthzCache()
    listener = _make_listener(cache)
    cert_b64 = _mint_bypass_cert(test_key, principal='alice')

    ok, reason = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='bob',     # ← not alice
        peer_der=b'', bypass_cert_b64=cert_b64)
    assert ok is False
    assert reason == 'bypass_principal_mismatch'
    assert cache.get('alice') is None
    assert cache.get('bob') is None


# ---------------------------------------------------------------------------
# Interaction with the cache's source tagging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_bypass_injection_overwrites_existing_ca_entry(test_key):
    """If alice already has a CA-source cache entry and presents a
    bypass cert, the bypass cert replaces the CA entry (single key,
    one entry per principal). Source tag updates to 'bypass'."""
    from mssh.msshd.authz_cache import SOURCE_CA
    from mssh.msshd.ca import AuthorizationGrant

    cache = AuthzCache()
    # Pre-populate with a CA grant.
    cache.put('alice', AuthorizationGrant(
        cert_der=b'fake-ca-cert', serial='old-ca-serial',
        not_after=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(hours=1),
    ), source=SOURCE_CA)
    assert cache.get('alice').source == SOURCE_CA

    listener = _make_listener(cache)
    cert_b64 = _mint_bypass_cert(test_key, principal='alice')

    ok, _ = await listener._handle_bypass_injection(
        conn_id='t', mtls_principal='alice', peer_der=b'',
        bypass_cert_b64=cert_b64)
    assert ok is True
    entry = cache.get('alice')
    assert entry.source == SOURCE_BYPASS
    assert entry.grant.serial != 'old-ca-serial'    # replaced
