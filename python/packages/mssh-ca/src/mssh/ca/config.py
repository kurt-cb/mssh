"""CA configuration loading."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class CAConfig:
    listen_host: str = '127.0.0.1'
    listen_port: int = 8443

    # Legacy single-signer paths. Still the operative config today;
    # PKI hierarchy migration (intermediates) is Phase 2+ — see
    # design/notes-pki-hierarchy.md.
    signing_key: str = ''
    signing_cert: str = ''

    # Optional: directory containing the full PKI layout (root +
    # intermediates). When set, the CA prefers loading from here
    # over the legacy single-signer paths. v1 deployments don't
    # use this; v2 deployments bootstrap with cert_minter.bootstrap_ca
    # which produces this layout.
    ca_dir: str = ''

    tls_cert: str = ''
    tls_key: str = ''
    client_ca_cert: str = ''

    identity_trust_roots: list[str] = field(default_factory=list)

    enrollment_path: str = ''
    audit_path: str = ''

    default_max_cert_validity_seconds: int = 3600
    timestamp_drift_seconds: int = 60

    server_cert_validity_days: int = 365
    admin_cert_validity_days: int = 365
    mtls_key_type: str = 'ec'

    # CRL Distribution Point URL stamped into each issued leaf (TLS
    # server, HTTPS user, OpenVPN). Consumers fetch this URL when
    # checking revocation. Typically points at the CA's own
    # GET /v1/crl.pem. Unset → no CRLDP extension embedded.
    crl_url: str = ''

    # WireGuard storage path — JSON catalog of servers + peers.
    # Created on-demand by `mssh-admin wireguard server init`.
    # Unset → WireGuard endpoints respond 503 (not configured).
    wireguard_path: str = ''

    @classmethod
    def load(cls, path: str | Path) -> 'CAConfig':
        with Path(path).open() as f:
            data = yaml.safe_load(f) or {}
        listen = (data.get('listen') or '127.0.0.1:8443')
        host, _, port = listen.rpartition(':')
        c = cls(
            listen_host=host or '127.0.0.1',
            listen_port=int(port or 8443),
            signing_key=str(data.get('signing_key') or ''),
            signing_cert=str(data.get('signing_cert') or ''),
            ca_dir=str(data.get('ca_dir') or ''),
            tls_cert=str(data.get('tls_cert') or ''),
            tls_key=str(data.get('tls_key') or ''),
            client_ca_cert=str(data.get('client_ca_cert') or ''),
            identity_trust_roots=list(data.get('identity_trust_roots') or []),
            enrollment_path=str((data.get('enrollment') or {}).get('path') or ''),
            audit_path=str((data.get('audit') or {}).get('path') or ''),
            default_max_cert_validity_seconds=int(
                (data.get('defaults') or {}).get('max_cert_validity_seconds') or 3600),
            timestamp_drift_seconds=int(
                (data.get('defaults') or {}).get('timestamp_drift_seconds') or 60),
            server_cert_validity_days=int(
                (data.get('cert_generation') or {}).get('server_cert_validity_days') or 365),
            admin_cert_validity_days=int(
                (data.get('cert_generation') or {}).get('admin_cert_validity_days') or 365),
            mtls_key_type=str(
                (data.get('cert_generation') or {}).get('key_type') or 'ec'),
            crl_url=str(
                (data.get('cert_generation') or {}).get('crl_url') or ''),
            wireguard_path=str(
                (data.get('wireguard') or {}).get('path') or ''),
        )
        return c
