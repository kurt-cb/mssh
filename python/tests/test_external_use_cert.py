"""§15.19 external-use cert kind tests.

Covers:

- CSR-based mint path (no key returned).
- Indefinite-expiry sentinel (notAfter = 9999-12-31).
- Issuer-intermediate pin check (§15.20 marker required).
- Custom OID injection (§15.21).
- Kind marker (§15.23 OID_KIND_EXTERNAL_USE = .3.9).

Tests: §15.19, §15.20, §15.21, §15.23
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.config import CertKindsPolicy, CustomOIDAllowlist, CustomOIDEntry
from mssh.ca.enrollment import Admin, Enrollment


def _make_csr(cn: str = 'device-001') -> bytes:
    """Verifies §15.18 — helper: build a PEM CSR signed by a fresh EC key."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    ).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)


def _mint_intermediate(ca_dir: Path, *, name: str, profile: str = 'generic'):
    """Verifies §15.20 — helper: mint an external intermediate with the
    given profile and persist its key.pem so external-use leaf mints
    can find it."""
    root_cert = cert_minter.load_root_cert(ca_dir)
    root_key = cert_minter.load_private_key(ca_dir / 'root-key.pem')
    key, cert = cert_minter.issue_external_intermediate(
        name, root_key=root_key, root_cert=root_cert,
        path_length=0, validity_days=10950, profile=profile)
    target = ca_dir / 'external' / name
    target.mkdir(parents=True, exist_ok=True)
    (target / 'cert.pem').write_bytes(cert_minter.serialize_certificate(cert))
    # Test fixture persists the key here so the leaf mint can sign.
    # In production, the operator places the key here after deciding to
    # let mssh-ca sign leaves under it.
    (target / 'key.pem').write_bytes(cert_minter.serialize_private_key(key))
    (target / 'profile.json').write_text(json.dumps({'profile': profile}))


@pytest.fixture
def adminctx(ca_dir):
    """Standard AdminContext with ctx.custom_oids populated for §15.21
    custom-OID tests."""
    enroll = Enrollment(ca_dir / 'enrollment.yaml')
    audit = AuditLog(ca_dir / 'audit.jsonl')
    tls_ca_key = cert_minter.load_private_key(ca_dir / 'tls-ca-key.pem')
    tls_ca_cert = cert_minter.load_certificate(ca_dir / 'tls-ca-cert.pem')
    allowlist = CustomOIDAllowlist(
        entries={
            '1.3.6.1.4.1.55555.5001.1': CustomOIDEntry(
                oid='1.3.6.1.4.1.55555.5001.1', name='device_oem',
                encoding='utf8', max_length=64),
        },
        by_name={'device_oem': '1.3.6.1.4.1.55555.5001.1'},
    )
    return AdminContext(
        enrollment=enroll, audit=audit,
        tls_ca_key=tls_ca_key, tls_ca_cert=tls_ca_cert,
        server_cert_validity_days=30, admin_cert_validity_days=30,
        mtls_key_type='ec',
        ca_dir=str(ca_dir),
        cert_kinds=CertKindsPolicy(),   # picks up 'external-use' fallback (20yr default, 25yr cap)
        custom_oids=allowlist,
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


@pytest.fixture
def auditor():
    return Admin(name='audit-bob', role='auditor', mtls_subject='CN=audit-bob')


# ---- happy-path: device-identity profile + CSR → leaf round-trip ---------


def test_external_use_mint_happy_path(adminctx, superuser, ca_dir):
    """Verifies §15.19 — CSR + device-identity intermediate → leaf
    chains correctly, carries the .3.9 kind marker."""
    _mint_intermediate(Path(adminctx.ca_dir), name='device-mfg',
                        profile='device-identity')
    csr_pem = _make_csr('device-0001').decode('ascii')

    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'device-0001',
            'csr': csr_pem,
            'issuer_intermediate': 'device-mfg',
            'validity_days': 7305,
        })
    assert status == 201, body
    assert body['cert']['type'] == 'external-use'
    assert body['cert']['subject_cn'] == 'device-0001'
    assert body['cert']['validity_days'] == 7305

    # The CA does not return the private key — operator's CSR-supplied
    # key stays on-device.
    assert 'key_pem' not in body['credentials']

    leaf = x509.load_pem_x509_certificate(
        body['credentials']['leaf_only_pem'].encode('ascii'))
    # §15.23 kind marker .3.9
    leaf.extensions.get_extension_for_oid(
        x509.ObjectIdentifier('1.3.6.1.4.1.55555.3.9'))


def test_external_use_never_expires_sets_sentinel(
        adminctx, superuser, ca_dir):
    """Verifies §15.19 — never_expires=true → notAfter = 9999-12-31."""
    _mint_intermediate(Path(adminctx.ca_dir), name='rom-burn',
                        profile='device-identity')
    csr_pem = _make_csr('rom-device-1').decode('ascii')

    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'rom-device-1',
            'csr': csr_pem,
            'issuer_intermediate': 'rom-burn',
            'never_expires': True,
        })
    assert status == 201
    assert body['cert']['never_expires'] is True
    assert body['cert']['validity_days'] is None
    assert body['cert']['not_valid_after'].startswith('9999-12-31')

    leaf = x509.load_pem_x509_certificate(
        body['credentials']['leaf_only_pem'].encode('ascii'))
    assert leaf.not_valid_after_utc.year == 9999


# ---- intermediate pin check (§15.20) ------------------------------------


def test_generic_intermediate_rejected_for_external_use(
        adminctx, superuser, ca_dir):
    """Verifies §15.19/§15.20 — a generic-profile intermediate (no
    .2.1 marker) cannot sign external-use leaves."""
    _mint_intermediate(Path(adminctx.ca_dir), name='plain-ca',
                        profile='generic')
    csr_pem = _make_csr().decode('ascii')

    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'x',
            'csr': csr_pem,
            'issuer_intermediate': 'plain-ca',
        })
    assert status == 400
    assert '§15.20' in body['detail']
    assert 'OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE' in body['detail']


def test_unknown_intermediate_404(adminctx, superuser):
    """Verifies §15.19 — issuer_intermediate that doesn't exist → 404."""
    csr_pem = _make_csr().decode('ascii')
    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'x',
            'csr': csr_pem,
            'issuer_intermediate': 'never-existed',
        })
    assert status == 404


# ---- request validation --------------------------------------------------


def test_missing_csr_rejected(adminctx, superuser, ca_dir):
    """Verifies §15.19 — external-use REQUIRES a csr field; the CA
    does not generate keys for external-use certs."""
    _mint_intermediate(Path(adminctx.ca_dir), name='mfg',
                        profile='device-identity')
    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'x',
            'issuer_intermediate': 'mfg',
        })
    assert status == 400
    assert 'csr' in body['detail']
    assert '§15.19' in body['detail']


def test_missing_cn_rejected(adminctx, superuser):
    """Verifies §15.19 — cn required."""
    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'csr': _make_csr().decode('ascii'),
            'issuer_intermediate': 'x',
        })
    assert status == 400
    assert 'cn' in body['detail']


def test_missing_issuer_intermediate_rejected(adminctx, superuser):
    """Verifies §15.19 — issuer_intermediate required."""
    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'x',
            'csr': _make_csr().decode('ascii'),
        })
    assert status == 400
    assert 'issuer_intermediate' in body['detail']


def test_malformed_csr_rejected(adminctx, superuser, ca_dir):
    """Verifies §15.18 — CSR validation surfaces as a 400."""
    _mint_intermediate(Path(adminctx.ca_dir), name='mfg',
                        profile='device-identity')
    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'x',
            'csr': '-----BEGIN CERTIFICATE REQUEST-----\ngarbage\n-----END CERTIFICATE REQUEST-----',
            'issuer_intermediate': 'mfg',
        })
    assert status == 400
    assert 'CSR' in body['detail']


# ---- RBAC --------------------------------------------------------------


def test_auditor_forbidden(adminctx, auditor, ca_dir):
    """Verifies §15.19 — auditor role cannot mint external-use leaves."""
    _mint_intermediate(Path(adminctx.ca_dir), name='mfg',
                        profile='device-identity')
    status, body = admin_handlers.external_use_cert_mint(
        adminctx, auditor, {
            'cn': 'x',
            'csr': _make_csr().decode('ascii'),
            'issuer_intermediate': 'mfg',
        })
    assert status == 403


# ---- custom OID injection (§15.21) ------------------------------------


def test_custom_oid_attached_to_leaf(adminctx, superuser, ca_dir):
    """Verifies §15.21 — operator-supplied allowlisted OID lands on
    the issued leaf."""
    _mint_intermediate(Path(adminctx.ca_dir), name='mfg',
                        profile='device-identity')
    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'device-0099',
            'csr': _make_csr('device-0099').decode('ascii'),
            'issuer_intermediate': 'mfg',
            'custom_oids': [{'name': 'device_oem', 'value': 'acme'}],
        })
    assert status == 201
    leaf = x509.load_pem_x509_certificate(
        body['credentials']['leaf_only_pem'].encode('ascii'))
    ext = leaf.extensions.get_extension_for_oid(
        x509.ObjectIdentifier('1.3.6.1.4.1.55555.5001.1'))
    # UTF8String DER: tag 0x0c, length 0x04, value "acme"
    assert ext.value.value.startswith(b'\x0c\x04acme')


def test_disallowed_custom_oid_rejected(adminctx, superuser, ca_dir):
    """Verifies §15.21 — OID not on the allowlist → 400."""
    _mint_intermediate(Path(adminctx.ca_dir), name='mfg',
                        profile='device-identity')
    status, body = admin_handlers.external_use_cert_mint(
        adminctx, superuser, {
            'cn': 'x',
            'csr': _make_csr().decode('ascii'),
            'issuer_intermediate': 'mfg',
            'custom_oids': [
                {'oid': '1.3.6.1.4.1.99999.99.1', 'value': 'sneaky'},
            ],
        })
    assert status == 400
    assert 'allowlist' in body['detail']


# ---- mint-external profile flag tests (§15.20) -------------------------


def test_mint_external_generic_no_marker(adminctx, superuser):
    """Verifies §15.20 — `--profile generic` produces an intermediate
    WITHOUT the .2.1 purpose marker (preserves v0.4.x behavior)."""
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'plain-int'})
    assert status == 201
    assert body['profile'] == 'generic'
    cert = x509.load_pem_x509_certificate(
        body['cert_pem'].encode('ascii'))
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_oid(
            cert_minter.OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE)


def test_mint_external_device_identity_attaches_marker(adminctx, superuser):
    """Verifies §15.20 — `--profile device-identity` stamps the
    intermediate-purpose marker (.2.1)."""
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {
            'name': 'device-pki',
            'profile': 'device-identity',
        })
    assert status == 201
    assert body['profile'] == 'device-identity'
    cert = x509.load_pem_x509_certificate(
        body['cert_pem'].encode('ascii'))
    ext = cert.extensions.get_extension_for_oid(
        cert_minter.OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE)
    assert ext.critical is False
    # NULL DER: tag 0x05, length 0x00
    assert ext.value.value == b'\x05\x00'


def test_mint_external_device_identity_default_validity(adminctx, superuser):
    """Verifies §15.20 — device-identity profile defaults to 30yr
    (10950 days) when validity_days isn't specified."""
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {
            'name': 'device-pki-long',
            'profile': 'device-identity',
        })
    assert status == 201
    cert = x509.load_pem_x509_certificate(
        body['cert_pem'].encode('ascii'))
    span = cert.not_valid_after_utc - cert.not_valid_before_utc
    # ~30 years; allow 1 day slack.
    assert span >= _dt.timedelta(days=10949)


def test_mint_external_unknown_profile_rejected(adminctx, superuser):
    """Verifies §15.20 — unknown profile name → 400."""
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {
            'name': 'bad-profile-test',
            'profile': 'totally-made-up',
        })
    assert status == 400
    assert 'totally-made-up' in body['detail']


def test_mint_external_persists_profile_json(adminctx, superuser):
    """Verifies §15.20 — profile name is persisted to
    <ca_dir>/external/<name>/profile.json so the CA knows on future
    loads which leaves the intermediate is allowed to issue."""
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {
            'name': 'persisted-int',
            'profile': 'device-identity',
        })
    assert status == 201
    profile_path = Path(adminctx.ca_dir) / 'external' / 'persisted-int' / 'profile.json'
    assert profile_path.exists()
    data = json.loads(profile_path.read_text())
    assert data['profile'] == 'device-identity'
