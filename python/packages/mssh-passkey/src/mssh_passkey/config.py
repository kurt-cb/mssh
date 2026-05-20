"""YAML config loader for mssh-passkey."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class ListenConfig:
    """Where Flask binds.

    In `front_end: apache` mode, this is the localhost socket
    Apache2's ProxyPass points at — no TLS in-process.
    In `front_end: dev` mode, the dev server terminates TLS itself
    on the configured ports.
    """
    bind: str = '127.0.0.1'
    port: int = 5000
    # Dev-mode only: separate public-HTTPS and broker-mTLS listeners.
    public_https: Optional[dict] = None      # {host, port, cert, key}
    broker_mtls: Optional[dict] = None       # {host, port, cert, key, client_ca_cert}


@dataclass
class CallbackConfig:
    """mTLS material the broker presents when calling back-end
    clients' callback URLs."""
    client_cert: str = ''
    client_key: str = ''
    ca_cert: str = ''     # to verify the back-end's TLS server cert

    # Retry policy. Hard-coded for v1; configurable later if needed.
    max_attempts: int = 5


@dataclass
class RPConfig:
    """WebAuthn relying-party info — the broker passes these through
    to back-end clients building options_json. The broker doesn't
    verify against them itself, but the values are useful in the
    landing page metadata."""
    rp_id: str = ''
    rp_name: str = 'mssh passkey broker'
    expected_origins: list[str] = field(default_factory=list)


@dataclass
class Config:
    front_end: str                # 'apache' | 'dev'
    listen: ListenConfig
    allowed_client_cns: list[str]
    callback: CallbackConfig
    rp: RPConfig
    database_path: str
    public_base_url: str          # how the broker tells back-end clients
                                  # to construct URLs the user will hit

    @classmethod
    def load(cls, path: str | Path) -> 'Config':
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        front_end = data.get('front_end', 'dev')
        if front_end not in ('apache', 'dev'):
            raise ValueError(f'front_end must be apache or dev, got {front_end!r}')

        listen_raw = data.get('listen') or {}
        listen = ListenConfig(
            bind=str(listen_raw.get('bind', '127.0.0.1')),
            port=int(listen_raw.get('port', 5000)),
            public_https=listen_raw.get('public_https'),
            broker_mtls=listen_raw.get('broker_mtls'),
        )

        cbk_raw = data.get('callback') or {}
        cbk = CallbackConfig(
            client_cert=str(cbk_raw.get('client_cert', '')),
            client_key=str(cbk_raw.get('client_key', '')),
            ca_cert=str(cbk_raw.get('ca_cert', '')),
        )

        rp_raw = data.get('rp') or {}
        rp = RPConfig(
            rp_id=str(rp_raw.get('rp_id', '')),
            rp_name=str(rp_raw.get('rp_name', 'mssh passkey broker')),
            expected_origins=list(rp_raw.get('expected_origins') or []),
        )

        db_path = str((data.get('database') or {}).get('path', '/var/lib/mssh-passkey/state.db'))

        allowed_cns = list(data.get('allowed_client_cns') or [])
        if not allowed_cns:
            raise ValueError(
                'allowed_client_cns must list at least one back-end '
                'client CN; refusing to start with an open broker')

        public_base = str(data.get('public_base_url') or '').rstrip('/')
        if not public_base:
            raise ValueError(
                'public_base_url must be set — it is what the broker '
                'tells back-end clients to put in the user-facing URL')

        return cls(
            front_end=front_end, listen=listen,
            allowed_client_cns=allowed_cns,
            callback=cbk, rp=rp,
            database_path=db_path,
            public_base_url=public_base,
        )
