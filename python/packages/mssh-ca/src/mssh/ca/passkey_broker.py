"""HTTPS+mTLS client for the mssh-passkey broker.

mssh-ca instantiates a PasskeyBrokerClient at startup if a
``passkey:`` block is present in ca-config.yaml. The client wraps
``requests`` with the configured client cert + CA-trust pair and
exposes three operations: create-ceremony, get-status,
cancel-ceremony.

See design/mssh-passkey-module.md § 5 for the wire contract.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

import requests

log = logging.getLogger('mssh.ca.passkey_broker')


@dataclass
class BrokerCeremony:
    """Result of a successful POST /broker/ceremony — the URL the
    user opens and the ceremony_id mssh-ca remembers locally."""
    ceremony_id: str
    url: str
    expires_at: str


@dataclass
class BrokerCeremonyStatus:
    """Result of GET /broker/ceremony/<id>."""
    ceremony_id: str
    type: str
    outcome: Optional[str]
    consumed_at: Optional[str]
    response_json: Optional[str]
    callback_status: Optional[str]


class PasskeyBrokerError(RuntimeError):
    """Raised on transport or HTTP-status failures from the broker."""
    def __init__(self, status: int, body):
        super().__init__(f'HTTP {status}: {body}')
        self.status = status
        self.body = body


class PasskeyBrokerClient:
    """mTLS client for the mssh-passkey broker. Bypasses HTTP_PROXY
    env vars (matches CAClient's approach)."""

    def __init__(self, base_url: str,
                 client_cert: str, client_key: str,
                 ca_cert: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip('/')
        self.client_cert = client_cert
        self.client_key = client_key
        self.ca_cert = ca_cert
        self.timeout = timeout
        self._session = requests.Session()
        self._session.trust_env = False

    def _request(self, method: str, path: str, *,
                  json_body: Optional[dict] = None) -> dict:
        url = self.base_url + path
        resp = self._session.request(
            method=method, url=url,
            json=json_body,
            cert=(self.client_cert, self.client_key),
            verify=self.ca_cert,
            timeout=self.timeout,
        )
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        if not (200 <= resp.status_code < 300):
            raise PasskeyBrokerError(resp.status_code, body)
        if not isinstance(body, dict):
            raise PasskeyBrokerError(resp.status_code,
                                      f'expected JSON object, got {type(body).__name__}')
        return body

    # ---- API ------------------------------------------------------------

    def create_ceremony(self, *, ceremony_type: str,
                        options_json: str,
                        description: str,
                        callback_url: str,
                        display_name: Optional[str] = None,
                        ttl_seconds: int = 300) -> BrokerCeremony:
        """POST /broker/ceremony — create register-or-approve ceremony."""
        if ceremony_type not in ('register', 'approve'):
            raise ValueError(f'bad ceremony_type {ceremony_type!r}')
        body = {
            'type': ceremony_type,
            'options_json': options_json,
            'description': description,
            'callback_url': callback_url,
            'ttl_seconds': int(ttl_seconds),
        }
        if display_name:
            body['display_name'] = display_name
        resp = self._request('POST', '/broker/ceremony', json_body=body)
        return BrokerCeremony(
            ceremony_id=resp['ceremony_id'],
            url=resp['url'],
            expires_at=resp['expires_at'],
        )

    def get_ceremony(self, ceremony_id: str) -> BrokerCeremonyStatus:
        """GET /broker/ceremony/<id> — poll for status."""
        resp = self._request('GET', f'/broker/ceremony/{ceremony_id}')
        return BrokerCeremonyStatus(
            ceremony_id=resp['ceremony_id'],
            type=resp['type'],
            outcome=resp.get('outcome'),
            consumed_at=resp.get('consumed_at'),
            response_json=resp.get('response_json'),
            callback_status=resp.get('callback_status'),
        )

    def cancel_ceremony(self, ceremony_id: str) -> None:
        """DELETE /broker/ceremony/<id> — cancel pending ceremony.
        Idempotent-ish: a 409 (already terminal) is suppressed."""
        try:
            self._request('DELETE', f'/broker/ceremony/{ceremony_id}')
        except PasskeyBrokerError as e:
            if e.status == 409:
                # Already terminal — fine.
                return
            raise
