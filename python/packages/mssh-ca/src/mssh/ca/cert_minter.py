"""Generate keys and mint X.509 certs.

Design: §4.3.4 (see design/mssh_design_v1.md) — cert minter.
See also: §2.2 intermediate hierarchy, §2.4 cert profiles,
§14.5 OID arc, §14.8 profile templates.

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
# §14.5 OID registry — all extension OIDs in this file are defined there.
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


# §15.23 intermediate-purpose marker arc (1.3.6.1.4.1.55555.2.*).
# A non-critical NULL extension stamped on intermediates minted via
# `mint-external --profile <name>` (§15.20). Lets external-use leaf
# mints verify the issuer intermediate is authorized to sign them.
_OID_PURPOSE_BASE = '1.3.6.1.4.1.55555.2'
OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE = x509.ObjectIdentifier(
    f'{_OID_PURPOSE_BASE}.1')


# §15.23 leaf cert-kind marker arc (1.3.6.1.4.1.55555.3.*). A
# non-critical NULL extension stamped on every leaf the CA emits, so
# the cert's kind is provable from the cert bytes themselves. Nine
# markers cover every kind the CA mints today + the new external-use
# kind (§15.19).
_OID_KIND_BASE = '1.3.6.1.4.1.55555.3'
OID_KIND_AUTHZ_USER    = x509.ObjectIdentifier(f'{_OID_KIND_BASE}.1')
OID_KIND_AUTHZ_BYPASS  = x509.ObjectIdentifier(f'{_OID_KIND_BASE}.2')
OID_KIND_SERVER_TLS    = x509.ObjectIdentifier(f'{_OID_KIND_BASE}.3')
OID_KIND_ADMIN_MTLS    = x509.ObjectIdentifier(f'{_OID_KIND_BASE}.4')
OID_KIND_CLIENT_MTLS   = x509.ObjectIdentifier(f'{_OID_KIND_BASE}.5')
OID_KIND_HTTPS_USER    = x509.ObjectIdentifier(f'{_OID_KIND_BASE}.6')
OID_KIND_CODE_SIGN     = x509.ObjectIdentifier(f'{_OID_KIND_BASE}.7')
OID_KIND_OPENVPN       = x509.ObjectIdentifier(f'{_OID_KIND_BASE}.8')
OID_KIND_EXTERNAL_USE  = x509.ObjectIdentifier(f'{_OID_KIND_BASE}.9')

# kind name → marker OID. The kind names match the strings used by
# admin handlers (e.g. `cert_mint` body 'type' field) plus the legacy
# `tls-server` alias that already lands in the cert-mint API.
KIND_MARKER = {
    'authz-user':    OID_KIND_AUTHZ_USER,
    'authz-bypass':  OID_KIND_AUTHZ_BYPASS,
    'server-tls':    OID_KIND_SERVER_TLS,
    'tls-server':    OID_KIND_SERVER_TLS,   # legacy alias
    'admin-mtls':    OID_KIND_ADMIN_MTLS,
    'client-mtls':   OID_KIND_CLIENT_MTLS,
    'https-user':    OID_KIND_HTTPS_USER,
    'code-sign':     OID_KIND_CODE_SIGN,
    'openvpn':       OID_KIND_OPENVPN,
    'external-use':  OID_KIND_EXTERNAL_USE,
}


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
                code_signing: bool = False,
                sans: list[str] | None = None,
                crl_url: str | None = None,
                kind: str | None = None,
                public_key=None) -> x509.Certificate:
    """Issue a leaf cert, signed by the given intermediate.

    §15.23 — when ``kind`` is set, attaches a non-critical NULL marker
    OID from ``KIND_MARKER`` to identify the cert's kind.

    v0.5.3 CSR path: when ``public_key`` is passed, that key is used
    for the cert subject rather than deriving it from ``leaf_key``.
    ``leaf_key`` may be ``None`` in that case — the CA never sees
    the private key.
    """
    if public_key is None:
        if leaf_key is None:
            raise TypeError(
                '_issue_leaf needs either leaf_key (CA-generates-key path) '
                'or public_key (CSR-based path)')
        public_key = leaf_key.public_key()
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
    if code_signing:
        eku.append(oid.ExtendedKeyUsageOID.CODE_SIGNING)
    # Key Usage selection driven by the EKU set:
    #   - serverAuth or clientAuth → digital signature + key encipherment
    #     (the latter for legacy RSA key-exchange paths; OpenVPN with
    #     --remote-cert-tls server checks digital_signature + keyEncipherment
    #     unless ECDHE-only is forced)
    #   - code-signing → digital signature alone
    is_tls_leaf = server_auth or client_auth
    ku = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=is_tls_leaf,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(signing.cert.subject)
        .public_key(public_key)
        .serial_number(int.from_bytes(secrets.token_bytes(16), 'big') | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(ku, critical=True)
        .add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
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
    if crl_url:
        # Embed a CRLDistributionPoints extension so consumers like
        # OpenVPN (`--crl-verify` w/o explicit URL) can self-discover
        # the revocation list. URL is the CA's /v1/crl.pem endpoint.
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None, reasons=None, crl_issuer=None),
            ]),
            critical=False,
        )
    # §15.23 cert-kind marker. Non-critical so legacy verifiers that
    # don't recognize the OID ignore it; CA-side mint + renew enforces
    # type-based policy.
    if kind is not None and kind in KIND_MARKER:
        builder = builder.add_extension(
            _null_ext(KIND_MARKER[kind]), critical=False)
    return builder.sign(private_key=signing.key,
                        algorithm=_sig_hash_for(signing.key))


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

@dataclass
class BootstrapArtifacts:
    """Output of bootstrap_ca(). PEMs are returned so callers can
    distribute them (CA host vs operator workstation).

    Both the legacy single-signer fields AND the new PKI-hierarchy
    fields are populated since v0.2.1: the legacy files are aliases
    of two of the intermediates (user-mint, auth) so callers that
    haven't migrated keep working — see design/notes-pki-hierarchy.md.
    """
    # --- Legacy single-signer aliases (still written to disk) ---
    signing_key_pem: bytes         # alias: user-mint's key
    signing_cert_pem: bytes        # alias: user-mint's cert (authz signing)
    tls_ca_cert_pem: bytes         # alias: auth's cert (mTLS signing)
    tls_ca_key_pem: bytes          # alias: auth's key
    tls_server_cert_pem: bytes     # CA's own listener cert, signed by host-mint
    tls_server_key_pem: bytes
    bootstrap_admin_cert_pem: bytes  # signed by auth
    bootstrap_admin_key_pem: bytes
    bootstrap_admin_subject: str
    # --- New PKI-hierarchy artifacts (v0.2.1+) ---
    # Root certificate (long-lived self-signed); the SINGLE document
    # ultimately trusted by everyone. Validators DON'T trust this
    # directly for leaves — they pin to the appropriate intermediate
    # per the trust-model amendment.
    root_cert_pem: bytes = b''
    root_key_pem: bytes = b''
    # The 4 named intermediates, by short_name. Each value is a tuple
    # of (key_pem, cert_pem). short_names match INTERMEDIATE_ROLES:
    # 'user-mint', 'bypass-mint', 'host-mint', 'auth'.
    intermediates: dict[str, tuple[bytes, bytes]] = field(default_factory=dict)


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


def _default_root_cn() -> str:
    """v0.5.7 — placeholder Root CA Common Name for callers that don't
    supply one. Deliberately obvious and unfit-for-production so an
    operator seeing it in a trust-store listing or audit log knows
    something skipped the required config step. `mssh-admin init`
    REQUIRES `--root-cn` and does not fall back to this; the
    programmatic `bootstrap_ca()` API keeps this default so tests +
    embedded uses don't have to synthesize a name every time.

    Pre-v0.5.6 the CN was hard-coded 'mssh-root'. v0.5.6 shifted the
    default to '<hostname> Root CA' — legible but still easy to accept
    silently. v0.5.7 makes it obviously-placeholder ('Unspecified cert
    from host <hostname>') and forces operators through --root-cn at
    init time."""
    import socket
    hostname = socket.gethostname() or 'unknown'
    return f'Unspecified cert from host {hostname}'


def bootstrap_ca(ca_dir: str | Path, *, key_type: str = 'ec',
                 mtls_key_type: str = 'ec',
                 bootstrap_admin_cn: str = 'bootstrap-admin',
                 tls_server_cn: str = 'mssh-ca',
                 tls_server_sans: list[str] | None = None,
                 root_cn: str | None = None,
                 ) -> BootstrapArtifacts:
    """First-time init: create the CA's root + 4 named intermediates,
    the CA's TLS server cert, and a bootstrap superuser admin cert.

    Layout written (since v0.2.1):

        ca_dir/
          root-cert.pem
          root-key.pem                  (mode 600)
          intermediates/
            user-mint/{cert,key}.pem    — signs per-session authz certs
            bypass-mint/{cert,key}.pem  — signs operator bypass certs
            host-mint/{cert,key}.pem    — signs server identities
            auth/{cert,key}.pem         — signs admin/client mTLS certs
          tls-server-cert.pem           — chain bundle (leaf + host-mint)
          tls-server-key.pem            (mode 600)
          bootstrap-admin-cert.pem      — chain bundle (leaf + auth)
          bootstrap-admin-key.pem       (mode 600)

    Legacy aliases also written (for callers that haven't migrated):

        signing-{key,cert}.pem   — copies of intermediates/user-mint/*
        tls-ca-{key,cert}.pem    — copies of intermediates/auth/*

    The aliasing reflects what existing code DID with those files:
    `signing-*.pem` signed authz certs (now → user-mint), and
    `tls-ca-*.pem` signed admin/server mTLS certs (now → auth).
    Callers verifying a leaf's signature against the alias keep
    working; new code should pin directly to the relevant
    intermediate per the trust-model amendment.

    See design/notes-pki-hierarchy.md for the design rationale.
    """
    # §4.3.4 CA bootstrap; intermediates per §2.2
    ca_dir = Path(ca_dir)
    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / 'intermediates').mkdir(exist_ok=True)

    # 1. Root: self-signed, ~20-year validity. CN is operator-supplied
    # (via `--root-cn` on init) or derived from hostname — pre-v0.5.6
    # every mssh CA got the identical CN "mssh-root", which made every
    # CA look like every other in a trust-store listing or audit log.
    root_key = generate_signing_key(key_type)
    effective_root_cn = (root_cn or _default_root_cn()).strip()
    if not effective_root_cn:
        raise ValueError('root_cn must be a non-empty string')
    root_cert = _self_signed_root(effective_root_cn, root_key)

    # 2. Four named intermediates, all signed by root, ~10-year validity.
    intermediates: dict[str, Intermediate] = {}
    for role in INTERMEDIATE_ROLES:
        inter_key = generate_signing_key(key_type)
        inter_cert = _issue_intermediate(role, inter_key, root_key, root_cert)
        intermediates[role] = Intermediate(
            short_name=role, key=inter_key, cert=inter_cert,
            pubkey_fp16=compute_pubkey_fp16(inter_key.public_key()),
        )

    # 3. CA's TLS server cert — signed by host-mint, written as chain bundle.
    tls_server_key = generate_signing_key(mtls_key_type)
    tls_server_cert = _issue_leaf(
        tls_server_cn, tls_server_key, intermediates['host-mint'],
        server_auth=True, client_auth=False,
        sans=tls_server_sans or ['DNS:localhost', 'IP:127.0.0.1'],
        kind='server-tls',
    )

    # 4. Bootstrap superuser admin cert — signed by auth.
    boot_admin_key = generate_signing_key(mtls_key_type)
    boot_admin_cert = _issue_leaf(
        bootstrap_admin_cn, boot_admin_key, intermediates['auth'],
        server_auth=False, client_auth=True,
        kind='admin-mtls',
    )

    # 5. Persist new layout.
    (ca_dir / 'root-cert.pem').write_bytes(serialize_certificate(root_cert))
    (ca_dir / 'root-key.pem').write_bytes(serialize_private_key(root_key))
    os.chmod(ca_dir / 'root-key.pem', 0o600)
    inter_pems: dict[str, tuple[bytes, bytes]] = {}
    for role, inter in intermediates.items():
        role_dir = ca_dir / 'intermediates' / role
        role_dir.mkdir(exist_ok=True)
        key_pem = serialize_private_key(inter.key)
        cert_pem = serialize_certificate(inter.cert)
        (role_dir / 'cert.pem').write_bytes(cert_pem)
        (role_dir / 'key.pem').write_bytes(key_pem)
        os.chmod(role_dir / 'key.pem', 0o600)
        inter_pems[role] = (key_pem, cert_pem)

    # CA TLS server cert. PRESENTED on wire as leaf + host-mint chain
    # bundle. The host-mint cert in the bundle is what lets OpenSSL
    # walk from the leaf to a trust anchor that the client recognizes.
    # Two valid client trust-store configurations both work:
    #   - Pinned: trust store has host-mint only → server's chain
    #     terminates immediately at host-mint (the trust anchor).
    #   - Legacy: trust store has auth+root (the tls-ca-cert.pem
    #     bundle) → chain walks leaf → host-mint (from server) →
    #     root (from trust store). Standard X.509 path-building.
    # Leaf-only on the wire would force clients into pinned mode,
    # which broke v0.2.0 callers that still use tls-ca-cert.pem.
    tls_server_bundle = _chain_pem(tls_server_cert,
                                    intermediates['host-mint'].cert)
    (ca_dir / 'tls-server-cert.pem').write_bytes(tls_server_bundle)
    (ca_dir / 'tls-server-key.pem').write_bytes(
        serialize_private_key(tls_server_key))
    os.chmod(ca_dir / 'tls-server-key.pem', 0o600)

    # Bootstrap admin cert. Same chain-bundle rationale as the TLS
    # server cert above — leaf + auth lets validators walk to either
    # auth-pinned or root-pinned trust stores.
    admin_bundle = _chain_pem(boot_admin_cert, intermediates['auth'].cert)
    (ca_dir / 'bootstrap-admin-cert.pem').write_bytes(admin_bundle)
    (ca_dir / 'bootstrap-admin-key.pem').write_bytes(
        serialize_private_key(boot_admin_key))
    os.chmod(ca_dir / 'bootstrap-admin-key.pem', 0o600)

    # 6. Legacy alias files. These exist so existing callers don't
    # break across the bootstrap refactor; new code should pin to the
    # specific intermediate via load_intermediates() instead.
    #
    # For files used as OpenSSL trust stores (tls-ca-cert.pem in
    # particular), include the root cert alongside the intermediate
    # so default OpenSSL chain validation finds a self-signed anchor
    # without needing the PARTIAL_CHAIN flag. The intermediate is
    # what AUTHORIZES the leaf (pinning rule per the trust-model
    # amendment); the root is included only to terminate the chain.
    user_mint_key_pem, user_mint_cert_pem = inter_pems['user-mint']
    auth_key_pem, auth_cert_pem = inter_pems['auth']
    root_cert_pem = serialize_certificate(root_cert)
    (ca_dir / 'signing-key.pem').write_bytes(user_mint_key_pem)
    (ca_dir / 'signing-cert.pem').write_bytes(user_mint_cert_pem)
    (ca_dir / 'tls-ca-key.pem').write_bytes(auth_key_pem)
    (ca_dir / 'tls-ca-cert.pem').write_bytes(auth_cert_pem + root_cert_pem)
    os.chmod(ca_dir / 'signing-key.pem', 0o600)
    os.chmod(ca_dir / 'tls-ca-key.pem', 0o600)

    return BootstrapArtifacts(
        signing_key_pem=user_mint_key_pem,
        signing_cert_pem=user_mint_cert_pem,
        tls_ca_cert_pem=auth_cert_pem,
        tls_ca_key_pem=auth_key_pem,
        tls_server_cert_pem=tls_server_bundle,
        tls_server_key_pem=serialize_private_key(tls_server_key),
        bootstrap_admin_cert_pem=admin_bundle,
        bootstrap_admin_key_pem=serialize_private_key(boot_admin_key),
        bootstrap_admin_subject=f'CN={bootstrap_admin_cn}',
        root_cert_pem=serialize_certificate(root_cert),
        root_key_pem=serialize_private_key(root_key),
        intermediates=inter_pems,
    )


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


def issue_external_intermediate(name: str, *, root_key, root_cert,
                                 path_length: int = 0,
                                 key_type: str = 'ec',
                                 validity_days: int = 3650,
                                 profile: str = 'generic',
                                 ) -> tuple[Any, x509.Certificate]:
    """Mint an external intermediate CA cert signed by root.

    External CAs delegate signing authority to a third party (per
    §25 of design/future-ideas.md + the trust-model amendment in
    notes-pki-hierarchy.md). They are signed by the same root as the
    4 internal intermediates BUT carry distinguishing markers and
    are NEVER added to any mssh validator's trust store. A leaf
    chaining through external-<name> terminates without a trust
    anchor for any mssh auth decision — exactly the property that
    isolates the operator's auth surface from external-entity certs.

    Markers:
        Organization        = <name>
        OrganizationalUnit  = external
        BasicConstraints.ca = True
        path_length         = <path_length>  (operator-chosen; 0 or 1+)
    """
    external_key = generate_signing_key(key_type)
    subject = x509.Name([
        x509.NameAttribute(oid.NameOID.COMMON_NAME, f'mssh-external-{name}'),
        x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, name),
        x509.NameAttribute(oid.NameOID.ORGANIZATIONAL_UNIT_NAME, 'external'),
    ])
    not_before = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=1)
    not_after = not_before + _dt.timedelta(days=validity_days)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(external_key.public_key())
        .serial_number(int.from_bytes(secrets.token_bytes(16), 'big') | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=int(path_length)),
            critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False,
            encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                external_key.public_key()),
            critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                root_key.public_key()),
            critical=False)
    )
    # §15.20/§15.23 — non-generic profiles stamp the intermediate-
    # purpose marker so external-use leaf mints (§15.19) can verify
    # the issuer is authorized to sign them.
    if profile and profile != 'generic':
        builder = builder.add_extension(
            _null_ext(OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE),
            critical=False)
    cert = builder.sign(private_key=root_key, algorithm=_sig_hash_for(root_key))
    return external_key, cert


def load_external_intermediates(ca_dir: str | Path) -> dict[str, x509.Certificate]:
    """Discover all external intermediates on disk. Returns
    name → cert. Private keys are not retained on the CA side (they
    were handed to the external entity at mint time)."""
    base = Path(ca_dir) / 'external'
    if not base.exists():
        return {}
    out: dict[str, x509.Certificate] = {}
    for sub in sorted(base.iterdir()):
        cert_path = sub / 'cert.pem'
        if cert_path.exists():
            out[sub.name] = load_certificate(cert_path)
    return out


# ---------------------------------------------------------------------------
# Server / admin mTLS cert issuance
# ---------------------------------------------------------------------------

@dataclass
class IssuedClientCert:
    # `cert_pem` shape depends on the calling convention (preserved for
    # v0.4.x/v0.5.3 backward compat, reverted from v0.5.4's breaking
    # default-fullchain change):
    #   - Legacy positional path (`issue_*_cert(name, tls_ca_key,
    #     tls_ca_cert, ...)`, which is what every admin.py callsite
    #     uses in production): cert_pem is LEAF-ONLY.
    #   - Multi-intermediate path (`signing=<Intermediate>`): cert_pem
    #     is leaf + issuing intermediate.
    # `full_chain_pem` is ALWAYS the leaf + issuing intermediate,
    # regardless of calling convention — that's the field to reach for
    # when you know you need a TLS-handshake-ready fullchain. Operators
    # opt in via `mssh-admin cert mint --fullchain`.
    cert_pem: bytes                     # legacy-path: leaf-only; new-path: leaf+chain
    full_chain_pem: bytes               # always: leaf + issuing intermediate
    key_pem: bytes
    ca_cert_pem: bytes                  # issuing intermediate (or root if supplied)
    subject_cn: str


def issue_client_cert(common_name: str,
                      tls_ca_key=None, tls_ca_cert=None,
                      *,
                      signing: Intermediate | None = None,
                      validity_days: int = 365,
                      key_type: str = 'ec',
                      root_cert: x509.Certificate | None = None,
                      crl_url: str | None = None,
                      kind: str = 'client-mtls',
                      csr_public_key=None,
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
    # §4.3.4 leaf mTLS client cert; profile per §14.8 client template;
    # signed by 'auth' intermediate per §2.2
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
    # CSR path — don't generate a key; use the CSR's public key.
    if csr_public_key is not None:
        key_pem_out = b''
        cert = _issue_leaf(common_name, None, signing,
                           validity_days=validity_days,
                           server_auth=False, client_auth=True,
                           crl_url=crl_url, kind=kind,
                           public_key=csr_public_key)
    else:
        key = generate_signing_key(key_type)
        key_pem_out = serialize_private_key(key)
        cert = _issue_leaf(common_name, key, signing,
                           validity_days=validity_days,
                           server_auth=False, client_auth=True,
                           crl_url=crl_url, kind=kind)
    # `cert_pem` follows the legacy calling convention (leaf-only for
    # positional path, chain for the multi-intermediate path) so
    # v0.5.3-and-earlier consumers don't break. `full_chain_pem` is
    # always the fullchain — reach for it when you know you need one
    # (CLI --fullchain flag).
    return IssuedClientCert(
        cert_pem=(_chain_pem(cert, signing.cert) if chain_bundle
                  else serialize_certificate(cert)),
        full_chain_pem=_chain_pem(cert, signing.cert),
        key_pem=key_pem_out,
        ca_cert_pem=(serialize_certificate(root_cert)
                     if root_cert is not None
                     else serialize_certificate(signing.cert)),
        subject_cn=common_name,
    )


def issue_server_cert(common_name: str,
                      tls_ca_key=None, tls_ca_cert=None,
                      *,
                      signing: Intermediate | None = None,
                      validity_days: int = 365,
                      key_type: str = 'ec',
                      sans: list[str] | None = None,
                      root_cert: x509.Certificate | None = None,
                      crl_url: str | None = None,
                      csr_public_key=None,
                      ) -> IssuedClientCert:
    """Issue a leaf mTLS / TLS SERVER cert (EKU = serverAuth).

    Same two calling conventions as :func:`issue_client_cert`:

      - **Legacy (positional):** ``issue_server_cert(name, tls_ca_key,
        tls_ca_cert, sans=..., validity_days=...)``. Uses the given
        key+cert pair as the signing intermediate; ``cert_pem`` is the
        leaf alone.
      - **New (keyword):** ``issue_server_cert(name, signing=intermediate,
        sans=..., root_cert=root)``. ``cert_pem`` is leaf + intermediate;
        ``ca_cert_pem`` is the root if supplied.
    """
    # §4.3.4 leaf TLS server cert; profile per §14.8 server template;
    # signed by 'host-mint' intermediate per §2.2
    if signing is None:
        if tls_ca_key is None or tls_ca_cert is None:
            raise TypeError(
                'issue_server_cert needs either signing=Intermediate '
                'or both tls_ca_key + tls_ca_cert (legacy)')
        signing = Intermediate(
            short_name='legacy', key=tls_ca_key, cert=tls_ca_cert,
            pubkey_fp16=compute_pubkey_fp16(tls_ca_key.public_key()),
        )
        chain_bundle = False
    else:
        chain_bundle = True
    # CSR path — don't generate a key; use the CSR's public key.
    # Response's key_pem is empty (operator's private key stays off-CA).
    if csr_public_key is not None:
        key_pem_out = b''
        cert = _issue_leaf(common_name, None, signing,
                           validity_days=validity_days,
                           server_auth=True, client_auth=False,
                           sans=sans, crl_url=crl_url,
                           kind='server-tls',
                           public_key=csr_public_key)
    else:
        key = generate_signing_key(key_type)
        key_pem_out = serialize_private_key(key)
        cert = _issue_leaf(common_name, key, signing,
                           validity_days=validity_days,
                           server_auth=True, client_auth=False,
                           sans=sans, crl_url=crl_url,
                           kind='server-tls')
    # v0.5.3 compat: cert_pem shape follows the calling convention;
    # full_chain_pem is always the fullchain.
    return IssuedClientCert(
        cert_pem=(_chain_pem(cert, signing.cert) if chain_bundle
                  else serialize_certificate(cert)),
        full_chain_pem=_chain_pem(cert, signing.cert),
        key_pem=key_pem_out,
        ca_cert_pem=(serialize_certificate(root_cert)
                     if root_cert is not None
                     else serialize_certificate(signing.cert)),
        subject_cn=common_name,
    )


@dataclass
class IssuedExternalUseCert:
    """Output of issue_external_use_cert (§15.19).

    Unlike IssuedClientCert, no private key is returned — the
    operator's CSR-supplied key stays on-device.
    """
    cert_pem: bytes                     # chain: leaf + intermediate
    leaf_only_pem: bytes                # leaf cert alone
    ca_cert_pem: bytes                  # the issuer intermediate cert
    subject_cn: str
    not_valid_after: Any                # datetime; for warnings


# §15.19 indefinite-expiry sentinel per RFC 5280 §4.1.2.5 — used for
# ROM-burned device identity certs that "match the lifetime of the
# device." Standard X.509 validators treat this as a far-future date.
_NEVER_EXPIRES = _dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=_dt.timezone.utc)


def _intermediate_has_purpose(cert: x509.Certificate,
                              purpose_oid: x509.ObjectIdentifier) -> bool:
    """Verifies §15.20 — returns True iff the intermediate cert carries
    the given purpose marker OID."""
    try:
        cert.extensions.get_extension_for_oid(purpose_oid)
        return True
    except x509.ExtensionNotFound:
        return False


def issue_external_use_cert(
    csr: x509.CertificateSigningRequest, *,
    issuer_key, issuer_cert: x509.Certificate,
    cn: str,
    validity_days: int,
    never_expires: bool = False,
    custom_oids: list[dict] | None = None,
    allowlist=None,                      # CustomOIDAllowlist | None
    crl_url: str | None = None,
) -> IssuedExternalUseCert:
    """§15.19 — issue an external-use leaf signed by an operator-named
    external intermediate (one minted via `--profile <name>`).

    The intermediate MUST carry OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE
    (§15.20 marker); otherwise the caller gets ValueError before any
    cert is built.

    The CSR supplies the public key + subject CN. The CA owns
    KeyUsage / EKU / SAN (none) / validity / kind marker / custom OIDs.
    """
    if not _intermediate_has_purpose(
            issuer_cert, OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE):
        raise ValueError(
            'issuer intermediate lacks OID_PURPOSE_EXTERNAL_USE_INTERMEDIATE '
            '(§15.20); mint it with --profile <name> instead of --profile generic')

    public_key = csr.public_key()
    subject = x509.Name([x509.NameAttribute(oid.NameOID.COMMON_NAME, cn)])

    not_before = _dt.datetime.now(tz=_dt.timezone.utc) - _dt.timedelta(minutes=1)
    if never_expires:
        not_after = _NEVER_EXPIRES
    else:
        not_after = not_before + _dt.timedelta(days=validity_days)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(int.from_bytes(secrets.token_bytes(16), 'big') | 1)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_key.public_key()),
            critical=False)
    )
    if crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None, reasons=None, crl_issuer=None),
            ]),
            critical=False,
        )
    # §15.23 cert-kind marker (.3.9 external-use).
    builder = builder.add_extension(
        _null_ext(OID_KIND_EXTERNAL_USE), critical=False)
    # §15.21 operator-supplied custom OIDs.
    if custom_oids:
        builder = attach_custom_extensions(builder, custom_oids, allowlist)

    cert = builder.sign(private_key=issuer_key,
                        algorithm=_sig_hash_for(issuer_key))
    leaf_pem = serialize_certificate(cert)
    chain_pem = _chain_pem(cert, issuer_cert)
    return IssuedExternalUseCert(
        cert_pem=chain_pem,
        leaf_only_pem=leaf_pem,
        ca_cert_pem=serialize_certificate(issuer_cert),
        subject_cn=cn,
        not_valid_after=not_after,
    )


def issue_codesign_cert(common_name: str,
                        tls_ca_key=None, tls_ca_cert=None,
                        *,
                        signing: Intermediate | None = None,
                        validity_days: int = 365,
                        key_type: str = 'ec',
                        root_cert: x509.Certificate | None = None,
                        csr_public_key=None,
                        ) -> IssuedClientCert:
    """Issue a leaf code-signing cert (EKU = codeSigning).

    No clientAuth / serverAuth — the leaf is for signing artifacts,
    not TLS. Same dual-calling convention as the other ``issue_*`` helpers.
    """
    if signing is None:
        if tls_ca_key is None or tls_ca_cert is None:
            raise TypeError(
                'issue_codesign_cert needs either signing=Intermediate '
                'or both tls_ca_key + tls_ca_cert (legacy)')
        signing = Intermediate(
            short_name='legacy', key=tls_ca_key, cert=tls_ca_cert,
            pubkey_fp16=compute_pubkey_fp16(tls_ca_key.public_key()),
        )
        chain_bundle = False
    else:
        chain_bundle = True
    # CSR path — don't generate a key; use the CSR's public key.
    if csr_public_key is not None:
        key_pem_out = b''
        cert = _issue_leaf(common_name, None, signing,
                           validity_days=validity_days,
                           server_auth=False, client_auth=False,
                           code_signing=True, kind='code-sign',
                           public_key=csr_public_key)
    else:
        key = generate_signing_key(key_type)
        key_pem_out = serialize_private_key(key)
        cert = _issue_leaf(common_name, key, signing,
                           validity_days=validity_days,
                           server_auth=False, client_auth=False,
                           code_signing=True, kind='code-sign')
    # v0.5.3 compat: cert_pem shape follows the calling convention;
    # full_chain_pem is always the fullchain.
    return IssuedClientCert(
        cert_pem=(_chain_pem(cert, signing.cert) if chain_bundle
                  else serialize_certificate(cert)),
        full_chain_pem=_chain_pem(cert, signing.cert),
        key_pem=key_pem_out,
        ca_cert_pem=(serialize_certificate(root_cert)
                     if root_cert is not None
                     else serialize_certificate(signing.cert)),
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
    crl_url: str | None = None,        # R-2: CRLDP embedded if set
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
    # §4.3.4 authz cert mint; profile per §14.8 authz template;
    # OIDs per §14.5; intermediate roles per §2.2
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
        # R-2: standard X.509 hardening — restrict the cert to its
        # intended role (client-auth + digital-signature) so it
        # cannot be presented as e.g. a server cert.
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=True)
        # Critical policy extensions
        .add_extension(_utf8_ext(OID_SOURCE_BIND, source_bind), critical=True)
        .add_extension(_utf8_ext(OID_SERVER_BIND, server_bind), critical=True)
        .add_extension(_seq_utf8_ext(OID_CHANNEL_POLICY, sorted(channels)),
                       critical=True)
        # R-2: SAN carries the alternative principal binding as an
        # rfc822 name so external validators (non-mssh) can recognise
        # the cert holder without parsing custom OIDs.
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.RFC822Name(f'{subject_username}@mssh')]),
            critical=False)
        # R-2: SKI helps chain walkers locate the leaf's pubkey.
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub),
            critical=False)
        # AKI helps clients walk the chain to find the issuer cert.
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                signing.key.public_key()),
            critical=False)
    )
    # R-2: CRLDistributionPoints lets external validators discover
    # revocation without a custom protocol. URL points at the CA's
    # /v1/crl.pem with the issuer query parameter.
    if crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(crl_url)],
                    relative_name=None, reasons=None, crl_issuer=None),
            ]),
            critical=False)
    if force_command:
        # R-1: critical-when-present; a validator that ignores the
        # extension would silently let the user out of the force-command.
        # KNOWN_CRITICAL on the consumer side allows it.
        builder = builder.add_extension(
            _utf8_ext(OID_FORCE_COMMAND, force_command), critical=True)
    if environment:
        # R-1: critical-when-present (same reason as FORCE_COMMAND).
        kv = [f'{k}={v}' for k, v in sorted(environment.items())]
        builder = builder.add_extension(
            _seq_utf8_ext(OID_ENVIRONMENT, kv), critical=True)
    if max_session_seconds is not None:
        builder = builder.add_extension(
            _int_ext(OID_MAX_SESSION, max_session_seconds), critical=False)
    if two_fa_evidence:
        builder = builder.add_extension(
            _utf8_ext(OID_2FA_EVIDENCE, two_fa_evidence), critical=False)
    if ca_bypass:
        # R-1: marker-only extension; format is ASN.1 NULL per §14.5.
        # Was UTF8String 'true' before; switched to NULL because the
        # presence of the marker is the signal — no value is meaningful.
        builder = builder.add_extension(
            _null_ext(OID_CA_BYPASS), critical=True)

    # §15.23 cert-kind marker. Non-critical NULL — defense-in-depth so
    # the cert's kind is provable from the bytes themselves. authz-user
    # vs. authz-bypass distinguished by the ca_bypass flag.
    _authz_kind = 'authz-bypass' if ca_bypass else 'authz-user'
    builder = builder.add_extension(
        _null_ext(KIND_MARKER[_authz_kind]), critical=False)

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


def _null_ext(oid_: x509.ObjectIdentifier) -> x509.UnrecognizedExtension:
    # ASN.1 NULL: tag 0x05, zero-length body. Used for marker-only
    # extensions whose presence is the signal (e.g. OID_CA_BYPASS).
    # Design: §14.5 (OID_CA_BYPASS format = NULL).
    return x509.UnrecognizedExtension(oid_, b'\x05\x00')


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


def _der_octet(b: bytes) -> bytes:
    return _der_tag(0x04, b)            # OCTET STRING


def _der_printable(s: str) -> bytes:
    # PrintableString: subset of ASCII; we don't validate here, just tag.
    return _der_tag(0x13, s.encode('ascii'))


def attach_custom_extensions(
    builder: x509.CertificateBuilder,
    requested: list[dict] | None,
    allowlist,                          # CustomOIDAllowlist | None
) -> x509.CertificateBuilder:
    """§15.21 — wire operator-supplied custom OIDs onto a cert builder.

    Each entry in ``requested`` is a dict ``{oid_or_name, value,
    critical?}``. The OID is resolved against ``allowlist`` (which may
    reference entries by either dotted OID or by ``name``); unknown
    references raise ``ValueError``. The encoding is dispatched per
    the allowlist entry to the ``_utf8_ext`` / ``_int_ext`` / etc.
    helpers above. ``critical`` on the request overrides the
    allowlist entry's default.

    Returns the builder with extensions added.

    Design: §15.21.
    """
    if not requested:
        return builder
    if allowlist is None:
        raise ValueError(
            'request supplies custom_oids but the CA has no allowlist '
            'configured (§13.9.7 default-deny + §15.21)')
    from . import config as _cfg
    for raw in requested:
        if not isinstance(raw, dict):
            raise ValueError(
                f'custom_oids entry must be a dict, got {type(raw).__name__}')
        key = (raw.get('oid') or raw.get('name') or '').strip()
        if not key:
            raise ValueError('custom_oids entry missing oid/name')
        entry = allowlist.lookup(key)
        if entry is None:
            raise ValueError(
                f'custom_oids: {key!r} is not in the operator allowlist '
                f'(§15.21 strict allowlist)')
        # Double-check: reject any reference to the mssh-reserved arc
        # even if the allowlist somehow contains it (belt + suspenders;
        # validate_self() should have caught at startup).
        if _cfg._check_oid_against_reserved(entry.oid):
            raise ValueError(
                f'custom_oids: {entry.oid} is in the mssh-reserved arc '
                f'and cannot be used by operators (§15.21)')
        value = raw.get('value')
        critical = bool(raw.get('critical', entry.critical))
        if entry.max_length is not None:
            if isinstance(value, (str, bytes)) and len(value) > entry.max_length:
                raise ValueError(
                    f'custom_oids: value for {entry.oid} exceeds '
                    f'max_length={entry.max_length} (§15.21)')
        oid_obj = x509.ObjectIdentifier(entry.oid)
        if entry.encoding == 'utf8':
            ext = _utf8_ext(oid_obj, '' if value is None else str(value))
        elif entry.encoding == 'integer':
            try:
                ext = _int_ext(oid_obj, int(value))
            except (TypeError, ValueError):
                raise ValueError(
                    f'custom_oids: value for {entry.oid} must be an integer '
                    f'(encoding=integer); got {value!r}')
        elif entry.encoding == 'null':
            ext = _null_ext(oid_obj)
        elif entry.encoding == 'octet':
            if isinstance(value, str):
                # Hex-decoded if it looks hex; otherwise treat as ascii.
                try:
                    value = bytes.fromhex(value)
                except ValueError:
                    value = value.encode('utf-8')
            elif value is None:
                value = b''
            ext = x509.UnrecognizedExtension(oid_obj, _der_octet(value))
        elif entry.encoding == 'printable':
            ext = x509.UnrecognizedExtension(
                oid_obj, _der_printable('' if value is None else str(value)))
        else:
            raise ValueError(
                f'custom_oids: unknown encoding {entry.encoding!r} for '
                f'{entry.oid} (§15.21)')
        builder = builder.add_extension(ext, critical=critical)
    return builder
