"""Generate keys and mint X.509 certs.

Three responsibilities:

1. **CA bootstrap.** Generates the root CA + 4 named intermediates +
   the CA's own TLS server cert + the bootstrap admin cert.
2. **Authorization-cert minting.** X.509 cert with mssh-specific
   policy extensions, signed by the user-mint intermediate (or by
   the bypass-mint intermediate for CA-bypass certs).
3. **Leaf cert issuance** (server identities, admin mTLS certs).
   Signed by host-mint (for server identities) or auth (for admins).

PKI hierarchy (see design/notes-pki-hierarchy.md):

    root
    ├── user-mint     issues short-lived authz certs (per session)
    ├── bypass-mint   issues operator-presentable bypass authz certs
    ├── host-mint     issues server identities (CA's TLS, msshd's mTLS)
    └── auth          issues admin/client mTLS certs

Each intermediate has its own private key and is signed by the root.
Each intermediate carries an `issuer_id` of the form
``<short-name>:<pubkey-fp16>`` — short-name for humans, pubkey
fingerprint for cryptographic stability across renames.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509 import oid


# OID arc for mssh's custom critical extensions on authz certs.
_OID_BASE = '1.3.6.1.4.1.55555.1'
OID_SOURCE_BIND     = x509.ObjectIdentifier(f'{_OID_BASE}.1')
OID_SERVER_BIND     = x509.ObjectIdentifier(f'{_OID_BASE}.2')
OID_CHANNEL_POLICY  = x509.ObjectIdentifier(f'{_OID_BASE}.3')
OID_FORCE_COMMAND   = x509.ObjectIdentifier(f'{_OID_BASE}.4')
OID_ENVIRONMENT     = x509.ObjectIdentifier(f'{_OID_BASE}.5')
OID_MAX_SESSION     = x509.ObjectIdentifier(f'{_OID_BASE}.6')
OID_2FA_EVIDENCE    = x509.ObjectIdentifier(f'{_OID_BASE}.7')
# Marker for operator-injectable bypass certs. When set (critical),
# msshd accepts the cert as a cache-injectable authz cert without
# a live CA call. See archive/design/notes-bypass-cache.md.
OID_CA_BYPASS       = x509.ObjectIdentifier(f'{_OID_BASE}.8')


# ---------------------------------------------------------------------------
# Intermediate CA model
# ---------------------------------------------------------------------------

# Named intermediate roles. Each gets its own keypair, signed by root.
INTERMEDIATE_ROLES: tuple[str, ...] = (
    'user-mint',     # short-lived authz certs (per session)
    'bypass-mint',   # operator-presentable CA-bypass authz certs
    'host-mint',     # server identities (CA TLS, msshd mTLS)
    'auth',          # admin/client mTLS certs
)


@dataclass
class Intermediate:
    """One named intermediate CA under the root.

    Holds the private key, the cert (signed by root), and a cached
    pubkey fingerprint used to derive the wire-format ``issuer_id``.
    """
    short_name: str
    key: Any                            # ed25519 / ec / rsa private key
    cert: x509.Certificate
    pubkey_fp16: str                    # first 16 hex of SHA256(SPKI)

    @property
    def issuer_id(self) -> str:
        """``<short-name>:<pubkey-fp16>`` — wire-format issuer
        identifier. Short name for readability; pubkey-fp for
        cryptographic stability (survives renames; differs across
        rotations)."""
        return f'{self.short_name}:{self.pubkey_fp16}'


def compute_pubkey_fp16(public_key) -> str:
    """First 16 hex of SHA256 over the cert's SubjectPublicKeyInfo
    DER bytes. Used as the stable identifier for an intermediate
    even across cert renewals (as long as the keypair is unchanged)."""
    spki = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest()[:16]


def make_issuer_id(short_name: str, public_key) -> str:
    """Convenience: build an issuer_id directly from a short-name
    and a public key (typically the intermediate's pubkey)."""
    return f'{short_name}:{compute_pubkey_fp16(public_key)}'


# ---------------------------------------------------------------------------
# Key generation + (de)serialization
# ---------------------------------------------------------------------------

def generate_signing_key(key_type: str = 'ed25519'):
    if key_type == 'ed25519':
        return ed25519.Ed25519PrivateKey.generate()
    if key_type == 'ec':
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == 'rsa':
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raise ValueError(f'unknown key type: {key_type}')


def _sig_hash_for(key) -> hashes.HashAlgorithm | None:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return None
    return hashes.SHA256()


def serialize_private_key(key, password: bytes | None = None) -> bytes:
    enc = (serialization.BestAvailableEncryption(password) if password
           else serialization.NoEncryption())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )


def load_private_key(path: str | Path, password: bytes | None = None):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=password)


def serialize_certificate(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def load_certificate(path: str | Path) -> x509.Certificate:
    data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(data)


# ---------------------------------------------------------------------------
# Root + intermediate creation
# ---------------------------------------------------------------------------

def _self_signed_root(subject_cn: str, key, validity_days: int = 7300
                      ) -> x509.Certificate:
    """Create a self-signed root CA certificate. ~20 year validity
    by default — root certs are long-lived on purpose."""
    subject = x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, subject_cn),
        x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, 'mssh'),
    ])
    not_before = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=1)
    not_after = not_before + _dt.timedelta(days=validity_days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), 'big') | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
    )
    return builder.sign(private_key=key, algorithm=_sig_hash_for(key))


def _issue_intermediate(short_name: str, intermediate_key,
                        root_key, root_cert: x509.Certificate,
                        validity_days: int = 3650) -> x509.Certificate:
    """Issue an intermediate CA cert signed by the root. ~10 year
    default validity — long enough to outlive most rotations of
    leaf certs but short enough to encourage periodic rotation."""
    subject = x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, f'mssh-{short_name}'),
        x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, 'mssh'),
        x509.NameAttribute(oid.NameOID.ORGANIZATIONAL_UNIT_NAME, short_name),
    ])
    not_before = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=1)
    not_after = not_before + _dt.timedelta(days=validity_days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), 'big') | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                intermediate_key.public_key()),
            critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_key.public_key()),
            critical=False)
    )
    return builder.sign(private_key=root_key,
                        algorithm=_sig_hash_for(root_key))


# ---------------------------------------------------------------------------
# Leaf cert issuance (used for the CA's TLS server cert, bootstrap admin,
# enrolled server mTLS certs, and admin mTLS certs)
# ---------------------------------------------------------------------------

def _issue_leaf(subject_cn: str, leaf_key,
                signing: Intermediate,
                *, validity_days: int = 365,
                server_auth: bool = False, client_auth: bool = True,
                sans: list[str] | None = None) -> x509.Certificate:
    """Issue a leaf cert, signed by the given intermediate."""
    subject = x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, subject_cn),
    ])
    not_before = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=1)
    not_after = not_before + _dt.timedelta(days=validity_days)
    eku = []
    if server_auth:
        eku.append(oid.ExtendedKeyUsageOID.SERVER_AUTH)
    if client_auth:
        eku.append(oid.ExtendedKeyUsageOID.CLIENT_AUTH)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(signing.cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), 'big') | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                signing.key.public_key()),
            critical=False)
    )
    san_entries: list[x509.GeneralName] = []
    if sans:
        for s in sans:
            if s.startswith('IP:'):
                import ipaddress
                san_entries.append(x509.IPAddress(ipaddress.ip_address(s[3:])))
            elif s.startswith('DNS:'):
                san_entries.append(x509.DNSName(s[4:]))
            else:
                san_entries.append(x509.DNSName(s))
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False)
    return builder.sign(private_key=signing.key,
                        algorithm=_sig_hash_for(signing.key))


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

@dataclass
class BootstrapArtifacts:
    """Output of bootstrap_ca(). PEMs are returned so callers can
    distribute them (CA host vs operator workstation).

    Legacy single-signer fields are populated today. The PKI
    hierarchy migration (Phase 2+) will add ``root_cert_pem``,
    ``intermediates_pem``, etc. — see design/notes-pki-hierarchy.md.
    """
    signing_key_pem: bytes
    signing_cert_pem: bytes        # authorization trust root (legacy)
    tls_ca_cert_pem: bytes         # signs server/admin mTLS certs
    tls_ca_key_pem: bytes
    tls_server_cert_pem: bytes     # CA's own listener cert
    tls_server_key_pem: bytes
    bootstrap_admin_cert_pem: bytes
    bootstrap_admin_key_pem: bytes
    bootstrap_admin_subject: str


def _chain_pem(*certs: x509.Certificate) -> bytes:
    """Concatenate certs into a single PEM bundle (leaf first, then
    intermediates). Lets a TLS server send the chain in one file."""
    return b''.join(serialize_certificate(c) for c in certs)


def _self_signed(subject_cn: str, key, validity_days: int = 3650,
                 is_ca: bool = True) -> x509.Certificate:
    """Legacy single-level self-signed cert. Kept for backward
    compat with the v1 single-signer bootstrap. The new hierarchy
    uses _self_signed_root + _issue_intermediate instead."""
    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, subject_cn)])
    not_before = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=1)
    not_after = not_before + _dt.timedelta(days=validity_days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), 'big') | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
    )
    return builder.sign(private_key=key, algorithm=_sig_hash_for(key))


def bootstrap_ca(ca_dir: str | Path, *, key_type: str = 'ec',
                 mtls_key_type: str = 'ec',
                 bootstrap_admin_cn: str = 'bootstrap-admin',
                 tls_server_cn: str = 'mssh-ca',
                 tls_server_sans: list[str] | None = None
                 ) -> BootstrapArtifacts:
    """First-time init: create the CA's keys, root certs, and
    bootstrap admin.

    **Current behavior:** single-signer layout (one signing key
    for authz certs, one TLS CA for mTLS certs). Files written:
    ``signing-{key,cert}.pem``, ``tls-ca-{key,cert}.pem``,
    ``tls-server-{key,cert}.pem``, ``bootstrap-admin-{key,cert}.pem``.

    **Future (Phase 2+):** ``bootstrap_ca`` will be refactored to
    produce a root + 4 intermediates layout (user-mint, bypass-mint,
    host-mint, auth) — see design/notes-pki-hierarchy.md. The
    helpers ``_self_signed_root``, ``_issue_intermediate``,
    ``load_intermediates`` are in place and ready to use; only the
    bootstrap-time wiring still uses the legacy single-signer path.
    """
    ca_dir = Path(ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)

    # Authorization signing key (signs short-lived X.509 authorization certs).
    signing_key = generate_signing_key(key_type)
    signing_cert = _self_signed('mssh-authorization-root', signing_key)

    # mTLS CA (signs server + admin client certs and the CA's TLS server cert).
    tls_ca_key = generate_signing_key(mtls_key_type)
    tls_ca_cert = _self_signed('mssh-mtls-root', tls_ca_key)

    # CA's TLS server cert (what shims/admins see when connecting).
    tls_server_key = generate_signing_key(mtls_key_type)
    tls_server_cert = _issue_leaf_legacy(
        tls_server_cn, tls_server_key, tls_ca_key, tls_ca_cert,
        server_auth=True, client_auth=False,
        sans=tls_server_sans or ['DNS:localhost', 'IP:127.0.0.1'],
    )

    # Bootstrap superuser admin cert.
    boot_admin_key = generate_signing_key(mtls_key_type)
    boot_admin_cert = _issue_leaf_legacy(
        bootstrap_admin_cn, boot_admin_key, tls_ca_key, tls_ca_cert,
        server_auth=False, client_auth=True,
    )

    artifacts = BootstrapArtifacts(
        signing_key_pem=serialize_private_key(signing_key),
        signing_cert_pem=serialize_certificate(signing_cert),
        tls_ca_cert_pem=serialize_certificate(tls_ca_cert),
        tls_ca_key_pem=serialize_private_key(tls_ca_key),
        tls_server_cert_pem=serialize_certificate(tls_server_cert),
        tls_server_key_pem=serialize_private_key(tls_server_key),
        bootstrap_admin_cert_pem=serialize_certificate(boot_admin_cert),
        bootstrap_admin_key_pem=serialize_private_key(boot_admin_key),
        bootstrap_admin_subject=f'CN={bootstrap_admin_cn}',
    )

    # Persist.
    (ca_dir / 'signing-key.pem').write_bytes(artifacts.signing_key_pem)
    (ca_dir / 'signing-cert.pem').write_bytes(artifacts.signing_cert_pem)
    (ca_dir / 'tls-ca-cert.pem').write_bytes(artifacts.tls_ca_cert_pem)
    (ca_dir / 'tls-ca-key.pem').write_bytes(artifacts.tls_ca_key_pem)
    (ca_dir / 'tls-server-cert.pem').write_bytes(artifacts.tls_server_cert_pem)
    (ca_dir / 'tls-server-key.pem').write_bytes(artifacts.tls_server_key_pem)
    (ca_dir / 'bootstrap-admin-cert.pem').write_bytes(artifacts.bootstrap_admin_cert_pem)
    (ca_dir / 'bootstrap-admin-key.pem').write_bytes(artifacts.bootstrap_admin_key_pem)
    for p in [
        'signing-key.pem', 'tls-ca-key.pem', 'tls-server-key.pem',
        'bootstrap-admin-key.pem',
    ]:
        os.chmod(ca_dir / p, 0o600)
    return artifacts


def _issue_leaf_legacy(subject_cn: str, leaf_key, ca_key, ca_cert,
                       *, validity_days: int = 365,
                       server_auth: bool = False, client_auth: bool = True,
                       sans: list[str] | None = None) -> x509.Certificate:
    """Legacy leaf-cert issuer that takes a (key, cert) signer pair
    directly. Used by the legacy bootstrap_ca path. The new
    Intermediate-based ``_issue_leaf`` helper is preferred for new
    code; this exists for compatibility with the single-signer
    bootstrap that v1 deployments still use."""
    signing = Intermediate(
        short_name='legacy', key=ca_key, cert=ca_cert,
        pubkey_fp16=compute_pubkey_fp16(ca_key.public_key()),
    )
    return _issue_leaf(subject_cn, leaf_key, signing,
                       validity_days=validity_days,
                       server_auth=server_auth, client_auth=client_auth,
                       sans=sans)


def load_intermediates(ca_dir: str | Path) -> dict[str, Intermediate]:
    """Load all 4 intermediates from ``ca_dir/intermediates/<role>/``.
    Returns a dict keyed by short_name. Raises if any role is missing
    or malformed."""
    ca_dir = Path(ca_dir)
    int_dir = ca_dir / 'intermediates'
    out: dict[str, Intermediate] = {}
    for role in INTERMEDIATE_ROLES:
        rd = int_dir / role
        cert_path = rd / 'cert.pem'
        key_path = rd / 'key.pem'
        if not cert_path.exists() or not key_path.exists():
            raise FileNotFoundError(
                f'intermediate {role!r} missing at {rd} — '
                f're-run bootstrap_ca to populate')
        key = load_private_key(key_path)
        cert = load_certificate(cert_path)
        out[role] = Intermediate(
            short_name=role, key=key, cert=cert,
            pubkey_fp16=compute_pubkey_fp16(key.public_key()),
        )
    return out


def load_root_cert(ca_dir: str | Path) -> x509.Certificate:
    """Load the root CA cert. Trust anchor for chain validation."""
    return load_certificate(Path(ca_dir) / 'root-cert.pem')


# ---------------------------------------------------------------------------
# Server / admin mTLS cert issuance
# ---------------------------------------------------------------------------

@dataclass
class IssuedClientCert:
    cert_pem: bytes                     # leaf + intermediate chain
    key_pem: bytes
    ca_cert_pem: bytes                  # the root cert
    subject_cn: str


def issue_client_cert(common_name: str,
                      tls_ca_key=None, tls_ca_cert=None,
                      *,
                      signing: Intermediate | None = None,
                      validity_days: int = 365,
                      key_type: str = 'ec',
                      root_cert: x509.Certificate | None = None,
                      ) -> IssuedClientCert:
    """Issue a leaf mTLS CLIENT cert.

    Two calling conventions for backward compatibility:

      - **Legacy (positional):** ``issue_client_cert(name, tls_ca_key,
        tls_ca_cert, validity_days=..., key_type=...)``. Used by
        existing single-signer code. The given key+cert pair acts as
        the signing intermediate. No chain bundle is produced
        (``cert_pem`` is the leaf alone).
      - **New (keyword):** ``issue_client_cert(name, signing=intermediate,
        validity_days=..., root_cert=root)``. Used by the multi-
        intermediate path. ``cert_pem`` includes leaf + intermediate;
        ``ca_cert_pem`` is the root if supplied.

    See design/notes-pki-hierarchy.md for the migration plan.
    """
    if signing is None:
        if tls_ca_key is None or tls_ca_cert is None:
            raise TypeError(
                'issue_client_cert needs either signing=Intermediate '
                'or both tls_ca_key + tls_ca_cert (legacy)')
        # Legacy path: build a transient Intermediate so the leaf-
        # issuer logic stays uniform. No chain bundling.
        signing = Intermediate(
            short_name='legacy', key=tls_ca_key, cert=tls_ca_cert,
            pubkey_fp16=compute_pubkey_fp16(tls_ca_key.public_key()),
        )
        chain_bundle = False
    else:
        chain_bundle = True
    key = generate_signing_key(key_type)
    cert = _issue_leaf(common_name, key, signing,
                       validity_days=validity_days,
                       server_auth=False, client_auth=True)
    return IssuedClientCert(
        cert_pem=(_chain_pem(cert, signing.cert) if chain_bundle
                  else serialize_certificate(cert)),
        key_pem=serialize_private_key(key),
        ca_cert_pem=(serialize_certificate(root_cert)
                     if root_cert is not None
                     else serialize_certificate(signing.cert)),
        subject_cn=common_name,
    )


def issue_server_cert(common_name: str, signing: Intermediate,
                      *, validity_days: int = 365,
                      key_type: str = 'ec',
                      sans: list[str] | None = None,
                      root_cert: x509.Certificate | None = None,
                      ) -> IssuedClientCert:
    """Issue a leaf mTLS SERVER cert signed by the given intermediate.
    Same bundle shape as ``issue_client_cert`` but EKU = serverAuth."""
    key = generate_signing_key(key_type)
    cert = _issue_leaf(common_name, key, signing,
                       validity_days=validity_days,
                       server_auth=True, client_auth=False,
                       sans=sans)
    return IssuedClientCert(
        cert_pem=_chain_pem(cert, signing.cert),
        key_pem=serialize_private_key(key),
        ca_cert_pem=(serialize_certificate(root_cert)
                     if root_cert is not None else b''),
        subject_cn=common_name,
    )


# ---------------------------------------------------------------------------
# Authorization-cert minting (user-mint and bypass-mint paths)
# ---------------------------------------------------------------------------

def _load_ssh_pub_from_blob(blob: bytes):
    """Decode an SSH wire-format pubkey blob into a cryptography
    PublicKey object. ed25519 only — pin the curve here so the cert
    minter doesn't have to know about other types."""
    # Wire format: 4-byte length, key type string, then key data.
    if len(blob) < 4:
        raise ValueError('blob too short')
    n = int.from_bytes(blob[:4], 'big')
    if 4 + n > len(blob):
        raise ValueError('truncated key-type field')
    key_type = blob[4:4 + n].decode('ascii', errors='strict')
    if key_type != 'ssh-ed25519':
        raise ValueError(f'unsupported key type: {key_type}')
    # ed25519: one more length-prefixed field, the raw 32-byte pubkey.
    p = 4 + n
    if p + 4 > len(blob):
        raise ValueError('truncated ed25519 pubkey length')
    kn = int.from_bytes(blob[p:p + 4], 'big')
    p += 4
    if kn != 32 or p + kn > len(blob):
        raise ValueError(f'bad ed25519 pubkey length: {kn}')
    return ed25519.Ed25519PublicKey.from_public_bytes(blob[p:p + 32])


def mint_authorization_cert(
    *,
    subject_username: str,
    subject_pubkey_blob: bytes,
    signing: Intermediate | None = None,
    signing_key=None,                  # legacy single-signer path
    signing_cert=None,                  # legacy single-signer path
    not_before: _dt.datetime,
    not_after: _dt.datetime,
    source_bind: str,
    server_bind: str,
    channels: list[str],
    force_command: str | None = None,
    environment: dict[str, str] | None = None,
    max_session_seconds: int | None = None,
    two_fa_evidence: str | None = None,
    ca_bypass: bool = False,
) -> tuple[x509.Certificate, str]:
    """Mint an X.509 authorization cert.

    Two calling conventions:

      - **Legacy:** ``signing_key=...`` + ``signing_cert=...`` — the
        v1 single-signer path. Used by existing code that hasn't been
        migrated to the multi-intermediate model.
      - **New:** ``signing=intermediate`` — Phase 2+ of the PKI
        hierarchy work. Typically user-mint for live session grants,
        bypass-mint for operator bypass certs (set
        ``ca_bypass=True`` for the marker).

    Returns (cert, serial_hex).
    """
    if signing is None:
        if signing_key is None or signing_cert is None:
            raise TypeError(
                'mint_authorization_cert needs either signing=Intermediate '
                'or both signing_key + signing_cert (legacy)')
        signing = Intermediate(
            short_name='legacy', key=signing_key, cert=signing_cert,
            pubkey_fp16=compute_pubkey_fp16(signing_key.public_key()),
        )
    subject = x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, subject_username),
        x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, 'mssh'),
    ])
    serial_int = int.from_bytes(secrets.token_bytes(16), 'big') | 1
    serial_hex = format(serial_int, 'x')
    pub = _load_ssh_pub_from_blob(subject_pubkey_blob)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(signing.cert.subject)
        .public_key(pub)
        .serial_number(serial_int)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        # Critical policy extensions
        .add_extension(_utf8_ext(OID_SOURCE_BIND, source_bind), critical=True)
        .add_extension(_utf8_ext(OID_SERVER_BIND, server_bind), critical=True)
        .add_extension(_seq_utf8_ext(OID_CHANNEL_POLICY, sorted(channels)),
                       critical=True)
        # AKI helps clients walk the chain to find the issuer cert.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                signing.key.public_key()),
            critical=False)
    )
    if force_command:
        builder = builder.add_extension(
            _utf8_ext(OID_FORCE_COMMAND, force_command), critical=False)
    if environment:
        kv = [f'{k}={v}' for k, v in sorted(environment.items())]
        builder = builder.add_extension(
            _seq_utf8_ext(OID_ENVIRONMENT, kv), critical=False)
    if max_session_seconds is not None:
        builder = builder.add_extension(
            _int_ext(OID_MAX_SESSION, max_session_seconds), critical=False)
    if two_fa_evidence:
        builder = builder.add_extension(
            _utf8_ext(OID_2FA_EVIDENCE, two_fa_evidence), critical=False)
    if ca_bypass:
        builder = builder.add_extension(
            _utf8_ext(OID_CA_BYPASS, 'true'), critical=True)

    cert = builder.sign(private_key=signing.key,
                        algorithm=_sig_hash_for(signing.key))
    return cert, serial_hex


# ---------------------------------------------------------------------------
# ASN.1 helpers for custom extensions (minimal DER hand-rolling).
# ---------------------------------------------------------------------------

def _utf8_ext(oid_: x509.ObjectIdentifier, value: str) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(oid_, _der_utf8(value))


def _seq_utf8_ext(oid_: x509.ObjectIdentifier,
                  values: list[str]) -> x509.UnrecognizedExtension:
    body = b''.join(_der_utf8(v) for v in values)
    return x509.UnrecognizedExtension(oid_, _der_tag(0x30, body))  # SEQUENCE


def _int_ext(oid_: x509.ObjectIdentifier, value: int) -> x509.UnrecognizedExtension:
    return x509.UnrecognizedExtension(oid_, _der_int(value))


def _der_tag(tag: int, body: bytes) -> bytes:
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    length_bytes = []
    n = len(body)
    while n > 0:
        length_bytes.append(n & 0xff)
        n >>= 8
    length_bytes.reverse()
    return bytes([tag, 0x80 | len(length_bytes)]) + bytes(length_bytes) + body


def _der_utf8(s: str) -> bytes:
    body = s.encode('utf-8')
    return _der_tag(0x0c, body)         # UTF8String


def _der_int(n: int) -> bytes:
    if n == 0:
        return _der_tag(0x02, b'\x00')
    body = b''
    x = n
    while x > 0:
        body = bytes([x & 0xff]) + body
        x >>= 8
    if body[0] & 0x80:
        body = b'\x00' + body
    return _der_tag(0x02, body)
