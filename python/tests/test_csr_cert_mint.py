"""§15.18 v0.5.3 CSR-based cert-mint tests.

The `cert_mint` admin handler now accepts an optional `csr` body
field. When set, the CA uses the CSR's public key + merges its SANs
with body SANs instead of generating a keypair. Response's key_pem
is empty — operator's private key never touches the CA.

Also covers the intermediate.external.mint key-retention behavior
(§15.20 v0.5.3) — `--profile != generic` retains a copy of the key
on the CA so external-use leaves can be signed without an operator
key-placement step.

Tests: §15.18, §15.20
"""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.config import CertKindsPolicy, CustomOIDAllowlist
from mssh.ca.enrollment import Admin, Enrollment


def _make_csr(cn: str, sans: list[str] | None = None) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    """Verifies §15.18 — build a PEM CSR + return the private key."""
    key = ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    if sans:
        entries: list[x509.GeneralName] = []
        for s in sans:
            if s.startswith('DNS:'):
                entries.append(x509.DNSName(s[4:]))
            elif s.startswith('IP:'):
                import ipaddress
                entries.append(x509.IPAddress(ipaddress.ip_address(s[3:])))
            else:
                entries.append(x509.DNSName(s))
        builder = builder.add_extension(
            x509.SubjectAlternativeName(entries), critical=False)
    csr = builder.sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM), key


@pytest.fixture
def adminctx(ca_dir):
    """Standard AdminContext + populated cert_kinds so tls-server has
    real defaults."""
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


# ---- CSR-based tls-server mint --------------------------------------------


def test_csr_based_tls_server_mint_returns_no_key(adminctx, superuser):
    """Verifies §15.18 / v0.5.3 — CSR-based tls-server mint produces a
    valid cert and returns key_pem == '' (private key stays with
    operator)."""
    csr_pem, priv_key = _make_csr('web.example.com',
                                    sans=['DNS:web.example.com'])
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'csr': csr_pem.decode('ascii'),
    })
    assert status == 201, body
    assert body['cert']['csr_based'] is True
    assert body['credentials']['key_pem'] == ''

    # Cert uses the CSR's public key.
    cert_pem = body['credentials']['cert_pem']
    cert = x509.load_pem_x509_certificates(cert_pem.encode('ascii'))[0]
    cert_spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    csr_spki = priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    assert cert_spki == csr_spki


def test_csr_sans_merged_into_leaf(adminctx, superuser):
    """Verifies §15.18 / v0.5.3 — SANs in the CSR are merged with
    body-supplied SANs (de-duped, body first)."""
    csr_pem, _ = _make_csr('web.example.com',
                             sans=['DNS:web.example.com',
                                   'DNS:www.example.com'])
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'csr': csr_pem.decode('ascii'),
        'sans': ['DNS:api.example.com'],  # extra body-supplied SAN
    })
    assert status == 201, body
    cert_pem = body['credentials']['cert_pem']
    cert = x509.load_pem_x509_certificates(cert_pem.encode('ascii'))[0]
    san_ext = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    got = sorted(str(n.value) for n in san_ext)
    assert got == sorted(['api.example.com', 'web.example.com',
                          'www.example.com'])


def test_csr_dedup_of_matching_sans(adminctx, superuser):
    """Verifies §15.18 / v0.5.3 — a SAN present in BOTH body and CSR
    appears once, not twice."""
    csr_pem, _ = _make_csr('web.example.com',
                             sans=['DNS:web.example.com'])
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'csr': csr_pem.decode('ascii'),
        'sans': ['DNS:web.example.com'],
    })
    assert status == 201, body
    cert = x509.load_pem_x509_certificates(
        body['credentials']['cert_pem'].encode('ascii'))[0]
    san_ext = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert len([str(n.value) for n in san_ext]) == 1


def test_csr_based_mint_preserves_kind_marker(adminctx, superuser):
    """Verifies §15.18 + §15.23 — CSR-based tls-server cert still gets
    the §15.23 server-tls kind marker (.3.3)."""
    csr_pem, _ = _make_csr('web.example.com')
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'csr': csr_pem.decode('ascii'),
    })
    assert status == 201
    cert = x509.load_pem_x509_certificates(
        body['credentials']['cert_pem'].encode('ascii'))[0]
    cert.extensions.get_extension_for_oid(
        cert_minter.OID_KIND_SERVER_TLS)


def test_csr_based_https_user(adminctx, superuser):
    """Verifies §15.18 / v0.5.3 — CSR path also works for https-user."""
    csr_pem, _ = _make_csr('alice')
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'https-user',
        'cn': 'alice',
        'csr': csr_pem.decode('ascii'),
    })
    assert status == 201, body
    assert body['credentials']['key_pem'] == ''


def test_csr_based_code_sign(adminctx, superuser):
    """Verifies §15.18 / v0.5.3 — CSR path also works for code-sign
    (satisfies the §15.18 pre-existing TODO)."""
    csr_pem, _ = _make_csr('Build agent 07')
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'code-sign',
        'cn': 'Build agent 07',
        'csr': csr_pem.decode('ascii'),
    })
    assert status == 201, body
    assert body['credentials']['key_pem'] == ''


def test_ca_generates_key_when_no_csr(adminctx, superuser):
    """Verifies §15.18 / v0.5.3 — omitting csr preserves v0.4.x
    CA-generates-key behavior (regression guard)."""
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
    })
    assert status == 201
    assert body['cert']['csr_based'] is False
    assert body['credentials']['key_pem'].startswith(
        '-----BEGIN PRIVATE KEY-----')


def test_csr_with_bad_signature_rejected(adminctx, superuser):
    """Verifies §15.18 / v0.5.3 — a corrupted CSR self-signature
    surfaces as a 400 bad_request."""
    csr_pem, _ = _make_csr('web.example.com')
    # Corrupt bytes near the end (signature region).
    corrupted = csr_pem[:-100] + b'X' * 100
    status, body = admin_handlers.cert_mint(adminctx, superuser, {
        'type': 'tls-server',
        'cn': 'web.example.com',
        'csr': corrupted.decode('ascii', errors='replace'),
    })
    assert status == 400
    assert 'CSR rejected' in body['detail']


# ---- Intermediate key retention (v0.5.3) ---------------------------------


def _mint_intermediate(adminctx, superuser, name: str, profile: str,
                       retain_key: bool | None = None):
    body = {'name': name, 'profile': profile}
    if retain_key is not None:
        body['retain_key'] = retain_key
    return admin_handlers.external_intermediate_mint(
        adminctx, superuser, body)


def test_generic_profile_does_not_retain_key(adminctx, superuser):
    """Verifies §2.6 — v0.4.x semantics: `--profile generic` does NOT
    persist the intermediate key on the CA."""
    status, body = _mint_intermediate(adminctx, superuser,
                                       'plain-int', 'generic')
    assert status == 201
    assert body['key_retained_by_ca'] is False
    key_path = Path(adminctx.ca_dir) / 'external' / 'plain-int' / 'key.pem'
    assert not key_path.exists()


def test_device_identity_profile_retains_key(adminctx, superuser):
    """Verifies §15.20 v0.5.3 — non-generic profile retains a copy of
    the intermediate key at <ca_dir>/external/<name>/key.pem so the CA
    can sign external-use leaves under it without an operator
    key-placement step."""
    status, body = _mint_intermediate(adminctx, superuser,
                                       'device-mfg', 'device-identity')
    assert status == 201
    assert body['key_retained_by_ca'] is True
    key_path = Path(adminctx.ca_dir) / 'external' / 'device-mfg' / 'key.pem'
    assert key_path.exists()
    # Mode 0600.
    assert key_path.stat().st_mode & 0o777 == 0o600
    # The persisted key matches the returned one.
    assert key_path.read_text() == body['key_pem']


def test_operator_can_opt_out_of_retention(adminctx, superuser):
    """Verifies §15.20 v0.5.3 — operator can force delegate-to-external
    semantics even on a device-identity profile by passing
    retain_key=False."""
    status, body = _mint_intermediate(adminctx, superuser,
                                       'delegated-mfg', 'device-identity',
                                       retain_key=False)
    assert status == 201
    assert body['key_retained_by_ca'] is False
    key_path = Path(adminctx.ca_dir) / 'external' / 'delegated-mfg' / 'key.pem'
    assert not key_path.exists()


def test_end_to_end_intermediate_then_external_use_leaf(
        adminctx, superuser):
    """Verifies §15.20 v0.5.3 — mint a device-identity intermediate
    (CA retains key), immediately sign an external-use leaf under it
    WITHOUT any operator key-placement step."""
    # 1. Mint the intermediate. With profile=device-identity the CA
    # retains the key automatically.
    status, body = _mint_intermediate(adminctx, superuser,
                                       'e2e-mfg', 'device-identity')
    assert status == 201
    assert body['key_retained_by_ca'] is True

    # 2. Sign a CSR-based external-use leaf. This would have required a
    # manual `install -m 600 device-mfg.key <ca_dir>/external/...`
    # step in v0.5.2; in v0.5.3 it Just Works.
    csr_pem, _ = _make_csr('device-0001')
    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'device-0001',
            'csr': csr_pem.decode('ascii'),
            'issuer_intermediate': 'e2e-mfg',
            'validity_days': 7305,
        })
    assert status == 201, body
    assert body['cert']['type'] == 'external-use'
