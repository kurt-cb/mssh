#!/usr/bin/env python3
"""mint-user-pki.py — mint the user-facing PKI material mssh needs.

mssh-admin manages the *CA-internal* hierarchy (authz certs, server mTLS,
admin mTLS). It does NOT manage the user-facing hierarchy:

  - user-CA cert + signing key
  - per-container wrapper TLS server cert (the cert msshd serves on
    port 2200)
  - per-user mTLS client cert (presented by the mssh client)

In production operators use their existing org PKI (Vault, AWS PCA,
openssl, ...) for these. This script is a self-contained reference
implementation suitable for labs and small deployments — same shape as
what python/tests/lxc/test_setup_only_msshd.py provisions for the
adhoc lab. See design/future-ideas.md for the open question of folding
this into `mssh-admin pki ...`.

Usage:
  python scripts/mint-user-pki.py \
      --out-dir ./user-pki \
      --servers srv-acct:10.1.1.1,srv-sales:10.1.1.2 \
      --users alice,bob,carol

Produces under --out-dir:
  user-ca.crt                  # trust anchor (push to every msshd as user-ca.pub)
  user-ca.key                  # KEEP SAFE — signs everything else
  wrapper-<server>.crt/.key    # per-server TLS material (push to that server)
  <user>.crt/.key              # per-user mTLS material (give to that user)
  <user>.pub                   # ssh-ed25519 pubkey (feed to `mssh-admin user add --key`)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import os
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:
    sys.stderr.write(
        "error: 'cryptography' not installed. Install mssh's deps:\n"
        "  pip install cryptography\n")
    sys.exit(2)


def _ssh_pubkey_blob_from_ed25519(pub) -> bytes:
    """Build the ssh-ed25519 wire blob (matches `ssh-keygen -y` output
    sans the ' user@host' suffix and base64-decoded)."""
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    name = b'ssh-ed25519'
    return (len(name).to_bytes(4, 'big') + name +
            len(raw).to_bytes(4, 'big') + raw)


def _ssh_authorized_keys_line(pub) -> str:
    import base64
    blob = _ssh_pubkey_blob_from_ed25519(pub)
    return f'ssh-ed25519 {base64.b64encode(blob).decode("ascii")}\n'


def mint(out: Path, *, servers: dict[str, str],
         users: list[str], validity_days: int = 30) -> None:
    out.mkdir(parents=True, exist_ok=True)
    now = _dt.datetime.now(_dt.timezone.utc)

    ca_key = ed25519.Ed25519PrivateKey.generate()
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'mssh-user-ca')])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .sign(ca_key, None))
    (out / 'user-ca.crt').write_bytes(
        ca_cert.public_bytes(serialization.Encoding.PEM))
    (out / 'user-ca.key').write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    os.chmod(out / 'user-ca.key', 0o600)
    print(f'  user-ca → {out}/user-ca.{{crt,key}}')

    for name, ip in servers.items():
        ws_key = ed25519.Ed25519PrivateKey.generate()
        try:
            san = x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(ip)),
                 x509.DNSName('localhost')])
        except ValueError:
            san = x509.SubjectAlternativeName(
                [x509.DNSName(ip), x509.DNSName('localhost')])
        ws_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, ip)]))
            .issuer_name(ca_name)
            .public_key(ws_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(san, critical=False)
            .sign(ca_key, None))
        cp, kp = out / f'wrapper-{name}.crt', out / f'wrapper-{name}.key'
        cp.write_bytes(ws_cert.public_bytes(serialization.Encoding.PEM))
        kp.write_bytes(ws_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        os.chmod(kp, 0o600)
        print(f'  wrapper TLS for {name} ({ip}) → wrapper-{name}.{{crt,key}}')

    for u in users:
        ck = ed25519.Ed25519PrivateKey.generate()
        cc = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u)]))
            .issuer_name(ca_name)
            .public_key(ck.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(minutes=5))
            .not_valid_after(now + _dt.timedelta(days=validity_days))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False)
            .sign(ca_key, None))
        (out / f'{u}.crt').write_bytes(
            cc.public_bytes(serialization.Encoding.PEM))
        (out / f'{u}.key').write_bytes(ck.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        os.chmod(out / f'{u}.key', 0o600)
        (out / f'{u}.pub').write_text(_ssh_authorized_keys_line(ck.public_key()))
        print(f'  user {u} → {u}.{{crt,key,pub}}')


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--out-dir', required=True, type=Path)
    p.add_argument('--servers', required=True,
                   help='Comma-separated name:ip pairs, e.g. srv-acct:10.1.1.1,srv-sales:10.1.1.2')
    p.add_argument('--users', required=True,
                   help='Comma-separated usernames')
    p.add_argument('--validity-days', type=int, default=30)
    args = p.parse_args()

    servers: dict[str, str] = {}
    for tok in args.servers.split(','):
        if ':' not in tok:
            sys.stderr.write(f'error: --servers token {tok!r} not in name:ip form\n')
            return 2
        name, ip = tok.split(':', 1)
        servers[name.strip()] = ip.strip()
    users = [u.strip() for u in args.users.split(',') if u.strip()]

    print(f'Minting user-facing PKI under {args.out_dir} ...')
    mint(args.out_dir, servers=servers, users=users,
         validity_days=args.validity_days)
    print('done.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
