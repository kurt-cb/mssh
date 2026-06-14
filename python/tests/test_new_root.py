"""§15.22 separate-Root tests.

Covers the multi-Root storage layout (roots.py), the
mint-external `new_root: true` opt-in, and verifying that
leaves under a non-primary Root validate against that Root only.

Tests: §15.22
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from mssh.ca import admin as admin_handlers
from mssh.ca import cert_minter, roots
from mssh.ca.admin import AdminContext
from mssh.ca.audit import AuditLog
from mssh.ca.enrollment import Admin, Enrollment


@pytest.fixture
def adminctx(ca_dir):
    """Standard AdminContext with ca_dir set so external-intermediate
    + new-root flows work."""
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
    )


@pytest.fixture
def superuser():
    return Admin(name='boot', role='superuser', mtls_subject='CN=boot')


# ---- roots.py module-level tests ----------------------------------------


def test_load_all_roots_populates_primary(ca_dir):
    """Verifies §15.22 — load_all_roots always populates the primary
    entry from root-{cert,key}.pem in ca_dir."""
    out = roots.load_all_roots(ca_dir)
    assert 'primary' in out
    assert out['primary'].name == 'primary'
    assert out['primary'].cert is not None


def test_create_new_root_persists_to_disk(ca_dir):
    """Verifies §15.22 — create_new_root writes cert.pem + key.pem
    under roots/<name>/ with mode 0600 on the key."""
    entry = roots.create_new_root(ca_dir, name='device-mfg')
    assert entry.name == 'device-mfg'
    target = Path(ca_dir) / 'roots' / 'device-mfg'
    assert (target / 'cert.pem').exists()
    assert (target / 'key.pem').exists()
    # Mode 0600 on the key.
    assert (target / 'key.pem').stat().st_mode & 0o777 == 0o600


def test_create_new_root_refuses_primary_name(ca_dir):
    """Verifies §15.22 — 'primary' is reserved."""
    with pytest.raises(ValueError) as exc:
        roots.create_new_root(ca_dir, name='primary')
    assert 'primary' in str(exc.value)


def test_create_new_root_refuses_duplicate(ca_dir):
    """Verifies §15.22 — re-using an existing root name fails."""
    roots.create_new_root(ca_dir, name='mfg-1')
    with pytest.raises(ValueError) as exc:
        roots.create_new_root(ca_dir, name='mfg-1')
    assert 'already exists' in str(exc.value)


def test_create_new_root_rejects_path_traversal(ca_dir):
    """Verifies §15.22 — names with slashes / leading dots refused."""
    with pytest.raises(ValueError):
        roots.create_new_root(ca_dir, name='../escape')
    with pytest.raises(ValueError):
        roots.create_new_root(ca_dir, name='.hidden')


def test_load_all_roots_picks_up_new_roots(ca_dir):
    """Verifies §15.22 — load_all_roots re-reads disk; a Root created
    via create_new_root shows up on the next load."""
    roots.create_new_root(ca_dir, name='mfg-a')
    roots.create_new_root(ca_dir, name='mfg-b')
    out = roots.load_all_roots(ca_dir)
    assert set(out.keys()) == {'primary', 'mfg-a', 'mfg-b'}


def test_new_root_cert_is_self_signed(ca_dir):
    """Verifies §15.22 — the new Root cert is self-signed (issuer ==
    subject)."""
    entry = roots.create_new_root(ca_dir, name='checked')
    assert entry.cert.issuer == entry.cert.subject


# ---- mint-external --new-root end-to-end -------------------------------


def test_mint_external_new_root_creates_separate_root(adminctx, superuser):
    """Verifies §15.22 — `new_root: true` creates a fresh Root and
    signs the intermediate under it; primary Root unaffected."""
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {
            'name': 'device-mfg',
            'new_root': True,
            'root_name': 'mfg-pki',
        })
    assert status == 201
    assert body['root_name'] == 'mfg-pki'
    # The new Root is on disk.
    target = Path(adminctx.ca_dir) / 'roots' / 'mfg-pki'
    assert (target / 'cert.pem').exists()
    # Intermediate's cert chains to the new Root, not the primary.
    inter_cert = x509.load_pem_x509_certificate(body['cert_pem'].encode('ascii'))
    new_root_cert = cert_minter.load_certificate(target / 'cert.pem')
    primary_root_cert = cert_minter.load_root_cert(adminctx.ca_dir)
    assert inter_cert.issuer == new_root_cert.subject
    assert inter_cert.issuer != primary_root_cert.subject


def test_mint_external_without_new_root_uses_primary(adminctx, superuser):
    """Verifies §15.22 — omitting `new_root` keeps v0.4.x behavior:
    the intermediate is signed by the primary Root."""
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {'name': 'plain-int'})
    assert status == 201
    assert body['root_name'] == 'primary'
    primary_root_cert = cert_minter.load_root_cert(adminctx.ca_dir)
    inter_cert = x509.load_pem_x509_certificate(body['cert_pem'].encode('ascii'))
    assert inter_cert.issuer == primary_root_cert.subject


def test_mint_external_new_root_then_reuse(adminctx, superuser):
    """Verifies §15.22 — once a non-primary Root exists, subsequent
    intermediates can chain to it by name without recreating it."""
    # First call creates the Root.
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {
            'name': 'first-int',
            'new_root': True,
            'root_name': 'shared-mfg',
        })
    assert status == 201
    target = Path(adminctx.ca_dir) / 'roots' / 'shared-mfg' / 'cert.pem'
    first_root_pem = target.read_bytes()

    # Second call reuses the same Root.
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {
            'name': 'second-int',
            'new_root': True,
            'root_name': 'shared-mfg',
        })
    assert status == 201
    assert body['root_name'] == 'shared-mfg'
    second_root_pem = target.read_bytes()
    assert first_root_pem == second_root_pem  # not regenerated


def test_mint_external_invalid_root_name_400(adminctx, superuser):
    """Verifies §15.22 — invalid root_name surfaces as 400."""
    status, body = admin_handlers.external_intermediate_mint(
        adminctx, superuser, {
            'name': 'whatever',
            'new_root': True,
            'root_name': 'primary',     # reserved
        })
    assert status == 400
    assert 'primary' in body['detail']
