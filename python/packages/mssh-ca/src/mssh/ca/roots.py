"""§15.22 multi-Root support — load + persist non-primary Roots.

v0.5.0 scope is intentionally limited: the storage layout and load
path are laid down so operators can opt into a separate Root for
fully segregated manufacturing PKI (`mssh-admin intermediate
mint-external --new-root <name>`). Per-Root rotation, revocation, and
admin-web visibility are deferred to v0.6+ (§15.22 follow-up).

Layout::

    <ca_dir>/
      root-cert.pem         # primary Root (bootstrap)
      root-key.pem
      roots/
        <root-name>/
          cert.pem          # non-primary Root cert
          key.pem           # non-primary Root key (mode 0600)

Design: §15.22.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.x509.oid import NameOID

from . import cert_minter


@dataclass
class RootEntry:
    """One root key + cert loaded from disk."""
    name: str                           # 'primary' or operator-supplied
    cert: x509.Certificate
    key: Any                            # private key
    path: Path                          # directory holding the pair


def load_all_roots(ca_dir: str | Path) -> dict[str, RootEntry]:
    """Discover every Root on disk (primary + any non-primary).

    Always populates ``primary`` from ``<ca_dir>/root-{cert,key}.pem``.
    Adds an entry per ``<ca_dir>/roots/<name>/{cert,key}.pem`` pair.

    Returns name → RootEntry. Empty dict only if the primary is
    missing too (shouldn't happen on a bootstrapped CA).

    Design: §15.22.
    """
    ca_dir = Path(ca_dir)
    out: dict[str, RootEntry] = {}

    primary_cert = ca_dir / 'root-cert.pem'
    primary_key = ca_dir / 'root-key.pem'
    if primary_cert.exists() and primary_key.exists():
        out['primary'] = RootEntry(
            name='primary',
            cert=cert_minter.load_certificate(primary_cert),
            key=cert_minter.load_private_key(primary_key),
            path=ca_dir,
        )

    roots_dir = ca_dir / 'roots'
    if roots_dir.exists():
        for sub in sorted(roots_dir.iterdir()):
            if not sub.is_dir():
                continue
            cert_path = sub / 'cert.pem'
            key_path = sub / 'key.pem'
            if cert_path.exists() and key_path.exists():
                out[sub.name] = RootEntry(
                    name=sub.name,
                    cert=cert_minter.load_certificate(cert_path),
                    key=cert_minter.load_private_key(key_path),
                    path=sub,
                )
    return out


def create_new_root(ca_dir: str | Path, *, name: str,
                    key_type: str = 'ec',
                    validity_days: int = 18250,    # 50yr
                    ) -> RootEntry:
    """§15.22 — generate a fresh Root + persist under
    ``<ca_dir>/roots/<name>/{cert.pem,key.pem}``.

    Raises ValueError if ``name`` is invalid or a Root with that name
    already exists. Returns the new RootEntry.
    """
    if not name or '/' in name or name.startswith('.') or name == 'primary':
        raise ValueError(
            f'Root name {name!r} is invalid; must be short alphanumeric, '
            f'no slashes, no leading dot, not the reserved name "primary"')
    ca_dir = Path(ca_dir)
    target = ca_dir / 'roots' / name
    if target.exists():
        raise ValueError(
            f'Root {name!r} already exists at {target}; pick a different name')
    target.mkdir(parents=True)
    # Build the new Root — self-signed, long-lived.
    new_key = cert_minter.generate_signing_key(key_type)
    new_cert = _self_signed_root(f'mssh-root-{name}', new_key, validity_days)
    import os
    (target / 'cert.pem').write_bytes(cert_minter.serialize_certificate(new_cert))
    (target / 'key.pem').write_bytes(cert_minter.serialize_private_key(new_key))
    os.chmod(target / 'key.pem', 0o600)
    return RootEntry(name=name, cert=new_cert, key=new_key, path=target)


def _self_signed_root(common_name: str, key, validity_days: int) -> x509.Certificate:
    """Build a self-signed Root cert. Same shape as
    cert_minter._self_signed_root but with operator-chosen CN +
    validity, used for non-primary Roots."""
    import secrets
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'mssh'),
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
    return builder.sign(private_key=key,
                        algorithm=cert_minter._sig_hash_for(key))
