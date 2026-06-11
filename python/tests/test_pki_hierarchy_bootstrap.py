"""Tests for the v0.2.1 PKI hierarchy bootstrap.

bootstrap_ca now produces:
  - root-{cert,key}.pem
  - intermediates/<role>/{cert,key}.pem for the 4 named intermediates
  - tls-server / bootstrap-admin certs signed by their assigned
    intermediates (host-mint / auth respectively)
  - legacy alias files (signing-*.pem, tls-ca-*.pem) for callers
    that haven't migrated to load_intermediates()

See design/notes-pki-hierarchy.md.

Tests: §2.2
"""

from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mssh.ca import cert_minter
from mssh.ca.cert_minter import (INTERMEDIATE_ROLES, BootstrapArtifacts,
                                  bootstrap_ca, load_certificate,
                                  load_intermediates, load_private_key,
                                  load_root_cert)


# ---- new layout on disk ------------------------------------------------

def test_bootstrap_writes_root_pair(tmp_path):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    assert (d / 'root-cert.pem').exists()
    assert (d / 'root-key.pem').exists()
    root = load_root_cert(d)
    # Self-signed.
    assert root.issuer == root.subject


def test_bootstrap_writes_all_4_intermediates(tmp_path):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    for role in INTERMEDIATE_ROLES:
        rdir = d / 'intermediates' / role
        assert (rdir / 'cert.pem').exists(), f'{role}/cert.pem missing'
        assert (rdir / 'key.pem').exists(), f'{role}/key.pem missing'


def test_intermediates_signed_by_root(tmp_path):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    root = load_root_cert(d)
    intermediates = load_intermediates(d)
    for role, inter in intermediates.items():
        assert inter.cert.issuer == root.subject, (
            f'{role} cert issuer != root subject')


def test_intermediate_certs_are_ca_path_length_0(tmp_path):
    """Internal intermediates can sign leaves only — path_length=0."""
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    intermediates = load_intermediates(d)
    for role, inter in intermediates.items():
        bc = inter.cert.extensions.get_extension_for_class(
            x509.BasicConstraints).value
        assert bc.ca is True, f'{role} not a CA'
        assert bc.path_length == 0, f'{role} path_length != 0'


def test_tls_server_cert_signed_by_host_mint(tmp_path):
    """The CA's own TLS server cert is issued by host-mint."""
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    intermediates = load_intermediates(d)
    tls_server = load_certificate(d / 'tls-server-cert.pem')
    assert tls_server.issuer == intermediates['host-mint'].cert.subject


def test_bootstrap_admin_cert_signed_by_auth(tmp_path):
    """Bootstrap superuser admin's mTLS cert is issued by auth."""
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    intermediates = load_intermediates(d)
    boot = load_certificate(d / 'bootstrap-admin-cert.pem')
    assert boot.issuer == intermediates['auth'].cert.subject


def test_legacy_signing_aliases_point_at_user_mint(tmp_path):
    """signing-{key,cert}.pem are bytewise copies of user-mint's pair."""
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    assert ((d / 'signing-cert.pem').read_bytes()
            == (d / 'intermediates' / 'user-mint' / 'cert.pem').read_bytes())
    assert ((d / 'signing-key.pem').read_bytes()
            == (d / 'intermediates' / 'user-mint' / 'key.pem').read_bytes())


def test_legacy_tls_ca_cert_alias_is_auth_plus_root_bundle(tmp_path):
    """tls-ca-cert.pem is a PEM bundle: auth's cert then the root.
    Bundling the root lets default OpenSSL chain validation work
    without the PARTIAL_CHAIN flag."""
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    pem = (d / 'tls-ca-cert.pem').read_bytes()
    auth_cert_pem = (d / 'intermediates' / 'auth' / 'cert.pem').read_bytes()
    root_cert_pem = (d / 'root-cert.pem').read_bytes()
    assert pem == auth_cert_pem + root_cert_pem


def test_legacy_tls_ca_key_alias_is_auth_key(tmp_path):
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    assert ((d / 'tls-ca-key.pem').read_bytes()
            == (d / 'intermediates' / 'auth' / 'key.pem').read_bytes())


def test_load_intermediates_yields_intermediate_objects(tmp_path):
    """Round-trip: bootstrap, then load_intermediates returns
    populated Intermediate dataclass instances."""
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    intermediates = load_intermediates(d)
    assert set(intermediates.keys()) == set(INTERMEDIATE_ROLES)
    for role, inter in intermediates.items():
        assert inter.short_name == role
        assert inter.cert is not None
        assert inter.key is not None
        assert len(inter.pubkey_fp16) == 16
        assert ':' in inter.issuer_id   # '<role>:<fp16>'


def test_artifacts_includes_root_and_intermediates(tmp_path):
    """BootstrapArtifacts now exposes root + intermediates dict."""
    d = tmp_path / 'ca'
    artifacts = bootstrap_ca(d)
    assert artifacts.root_cert_pem
    assert artifacts.root_key_pem
    assert set(artifacts.intermediates.keys()) == set(INTERMEDIATE_ROLES)
    for role in INTERMEDIATE_ROLES:
        key_pem, cert_pem = artifacts.intermediates[role]
        assert key_pem
        assert cert_pem
        # Should match what's on disk.
        assert key_pem == (d / 'intermediates' / role / 'key.pem').read_bytes()
        assert cert_pem == (d / 'intermediates' / role / 'cert.pem').read_bytes()


def test_key_files_are_mode_600(tmp_path):
    """All private-key files (root + 4 intermediates + tls-server +
    bootstrap-admin + 2 legacy aliases) must be mode 0600."""
    import stat
    d = tmp_path / 'ca'
    bootstrap_ca(d)
    targets = [
        d / 'root-key.pem',
        d / 'tls-server-key.pem',
        d / 'bootstrap-admin-key.pem',
        d / 'signing-key.pem',         # legacy alias
        d / 'tls-ca-key.pem',          # legacy alias
    ]
    for role in INTERMEDIATE_ROLES:
        targets.append(d / 'intermediates' / role / 'key.pem')
    for p in targets:
        m = stat.S_IMODE(p.stat().st_mode)
        assert m == 0o600, f'{p.name} mode {oct(m)} != 0o600'
