"""CSR loading + verification tests for §15.18 / §15.19.

Covers parser robustness, signature verification, extension rejection,
and the multi-algorithm path (RSA, EC, Ed25519).

Tests: §15.18, §15.19
"""
from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from mssh.ca.csr import (
    CSRValidationError,
    extract_public_key,
    load_and_verify_csr,
    public_key_pem,
)


def _csr_from(key, cn='test-device-001', extensions=()) -> bytes:
    """Verifies §15.18 — helper that builds a PEM CSR signed with the
    supplied key. Default no extensions; tests opt in to add some to
    exercise the reject path."""
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    for ext, critical in extensions:
        builder = builder.add_extension(ext, critical=critical)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        csr = builder.sign(key, None)
    else:
        csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


# ---- happy-path: each key type round-trips ---------------------------------


def test_rsa_csr_round_trips():
    """Verifies §15.18 — RSA-2048 CSR loads + signature verifies."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = load_and_verify_csr(_csr_from(key))
    assert isinstance(csr, x509.CertificateSigningRequest)
    assert csr.subject.rfc4514_string() == 'CN=test-device-001'


def test_ec_csr_round_trips():
    """Verifies §15.18 — EC P-256 CSR loads + signature verifies."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = load_and_verify_csr(_csr_from(key))
    assert isinstance(csr, x509.CertificateSigningRequest)


def test_ed25519_csr_round_trips():
    """Verifies §15.18 — Ed25519 CSR loads + signature verifies."""
    key = ed25519.Ed25519PrivateKey.generate()
    csr = load_and_verify_csr(_csr_from(key))
    assert isinstance(csr, x509.CertificateSigningRequest)


# ---- public-key extraction -------------------------------------------------


def test_extract_public_key_matches_signing_key():
    """Verifies §15.18 — extract_public_key returns the same public
    bytes as the originating private key's public_key()."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = load_and_verify_csr(_csr_from(key))
    extracted = extract_public_key(csr)
    expected_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    actual_pem = extracted.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert actual_pem == expected_pem


def test_public_key_pem_helper():
    """Verifies §15.18 — public_key_pem returns PEM-encoded SPKI."""
    key = ed25519.Ed25519PrivateKey.generate()
    csr = load_and_verify_csr(_csr_from(key))
    pem = public_key_pem(csr)
    assert pem.startswith(b'-----BEGIN PUBLIC KEY-----')


# ---- error paths -----------------------------------------------------------


def test_malformed_pem_rejected():
    """Verifies §15.18 — junk PEM raises CSRValidationError, not a
    raw cryptography exception."""
    with pytest.raises(CSRValidationError) as exc:
        load_and_verify_csr(b'-----BEGIN CERTIFICATE REQUEST-----\nnot-pem\n-----END CERTIFICATE REQUEST-----')
    assert 'PKCS#10' in str(exc.value)


def test_string_input_also_accepted():
    """Verifies §15.18 — load_and_verify_csr accepts both bytes + str
    so callers can pass either."""
    key = ec.generate_private_key(ec.SECP256R1())
    pem = _csr_from(key).decode('ascii')
    csr = load_and_verify_csr(pem)
    assert isinstance(csr, x509.CertificateSigningRequest)


def test_csr_with_extension_rejected():
    """Verifies §15.18 — a CSR that smuggles in a SAN extension is
    rejected; the CA owns extensions."""
    key = ec.generate_private_key(ec.SECP256R1())
    san = x509.SubjectAlternativeName([x509.DNSName('attacker.example')])
    pem = _csr_from(key, extensions=[(san, False)])
    with pytest.raises(CSRValidationError) as exc:
        load_and_verify_csr(pem)
    assert 'disallowed extensions' in str(exc.value)
    assert '2.5.29.17' in str(exc.value)  # SAN OID surfaced


def test_csr_with_keyusage_extension_rejected():
    """Verifies §15.18 — a CSR claiming KeyUsage is rejected (the
    CA decides KU per the cert kind / profile)."""
    key = ec.generate_private_key(ec.SECP256R1())
    ku = x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=True,    # <-- escalation attempt
        crl_sign=False, encipher_only=False, decipher_only=False,
    )
    pem = _csr_from(key, extensions=[(ku, True)])
    with pytest.raises(CSRValidationError) as exc:
        load_and_verify_csr(pem)
    assert 'disallowed extensions' in str(exc.value)


def test_tampered_csr_signature_rejected():
    """Verifies §15.18 — a CSR whose signature bytes have been
    mangled fails verification.

    The check goes through cryptography's is_signature_valid, which
    walks the DER and recomputes the hash. Flip a byte in the
    middle of the signature region and re-encode."""
    key = ec.generate_private_key(ec.SECP256R1())
    der = x509.load_pem_x509_csr(_csr_from(key)).public_bytes(
        serialization.Encoding.DER)
    # Flip a byte in the trailing third (signature region).
    bad = bytearray(der)
    bad[-20] ^= 0x42
    bad_pem = (
        b'-----BEGIN CERTIFICATE REQUEST-----\n'
        + __import__('base64').encodebytes(bytes(bad))
        + b'-----END CERTIFICATE REQUEST-----\n'
    )
    with pytest.raises(CSRValidationError):
        load_and_verify_csr(bad_pem)
