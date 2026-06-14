"""CSR loading + verification for the §15.18 / §15.19 CSR-based paths.

Used by the external-use cert mint (§15.19) where the device's
private key lives in a TPM / secure element and never leaves the
device. The operator submits a PKCS#10 CSR; the CA verifies its
self-signature, extracts the public key, and issues a cert.

The CA owns KeyUsage / EKU / SAN / validity / custom OIDs. The CSR
is treated as carrying only the public key + the subject CN. Any
extensions present in the CSR are rejected to prevent the operator
from smuggling KeyUsage/EKU/critical extensions through the mint
path.

Design: §15.18, §15.19
"""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization


class CSRValidationError(ValueError):
    """Raised when a submitted CSR fails verification."""


def load_and_verify_csr(pem_bytes: bytes | str) -> x509.CertificateSigningRequest:
    """Parse a PEM-encoded CSR and verify its self-signature.

    Rejects any CSR that:
      - is not parseable as PEM PKCS#10
      - has an invalid self-signature
      - carries any X.509 extensions (the CA owns those)

    Returns the validated CSR object.

    Design: §15.18.
    """
    if isinstance(pem_bytes, str):
        pem_bytes = pem_bytes.encode('ascii')
    try:
        csr = x509.load_pem_x509_csr(pem_bytes)
    except (ValueError, TypeError) as e:
        raise CSRValidationError(f'CSR is not parseable PEM PKCS#10: {e}')

    # cryptography>=41 surfaces signature validity as a property; the
    # property short-circuits on unsupported signature schemes.
    if not csr.is_signature_valid:
        raise CSRValidationError('CSR self-signature is invalid')

    # Reject any extensions in the CSR — the operator must not dictate
    # KeyUsage/EKU/critical extensions through the CSR. The CA decides
    # those at mint time per the cert kind / profile.
    if list(csr.extensions):
        oids = ', '.join(ext.oid.dotted_string for ext in csr.extensions)
        raise CSRValidationError(
            f'CSR carries disallowed extensions (CA owns these): {oids}')

    return csr


def extract_public_key(csr: x509.CertificateSigningRequest):
    """Return the CSR's public key in the form the cert-mint pipeline
    consumes — same object type returned by ``key.public_key()`` for
    locally-generated keypairs.

    Design: §15.18.
    """
    return csr.public_key()


def public_key_pem(csr: x509.CertificateSigningRequest) -> bytes:
    """Convenience: return the CSR's public key as PEM. Useful for
    audit + diagnostics.

    Design: §15.18.
    """
    return csr.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
