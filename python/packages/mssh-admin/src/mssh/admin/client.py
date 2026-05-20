"""mTLS HTTP client for the admin API."""
from __future__ import annotations

from typing import Any

import requests


class CAClientError(RuntimeError):
    """API call returned a non-2xx response."""

    def __init__(self, status: int, body: dict | str):
        super().__init__(f'CA returned HTTP {status}: {body}')
        self.status = status
        self.body = body


class CAClient:
    """Admin API mTLS client. Bypasses HTTP_PROXY env vars."""

    def __init__(self, base_url: str, admin_cert: str, admin_key: str,
                 ca_cert: str, timeout: float = 10.0):
        self.base_url = base_url
        self.admin_cert = admin_cert
        self.admin_key = admin_key
        self.ca_cert = ca_cert
        self.timeout = timeout
        self._session = requests.Session()
        self._session.trust_env = False

    def _request(self, method: str, path: str, *,
                 json: dict[str, Any] | None = None,
                 params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.base_url.rstrip('/') + path
        resp = self._session.request(
            method=method, url=url,
            json=json, params=params,
            cert=(self.admin_cert, self.admin_key),
            verify=self.ca_cert,
            timeout=self.timeout,
        )
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        if not (200 <= resp.status_code < 300):
            raise CAClientError(resp.status_code, body)
        return body

    # ---- server ----
    def server_add(self, name: str, groups: list[str] | None = None) -> dict[str, Any]:
        return self._request('POST', '/v1/admin/server/add',
                             json={'name': name, 'groups': groups or []})

    def server_remove(self, name: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/server/{name}')

    def server_set_groups(self, name: str, groups: list[str]) -> dict[str, Any]:
        return self._request('PUT', f'/v1/admin/server/{name}/groups',
                             json={'groups': groups})

    def server_list(self, *, group: str | None = None,
                    name_prefix: str | None = None) -> list[dict[str, Any]]:
        params = {}
        if group:
            params['group'] = group
        if name_prefix:
            params['name'] = name_prefix
        return self._request('GET', '/v1/admin/server/list',
                             params=params)['servers']

    # ---- user ----
    def user_add(self, username: str) -> dict[str, Any]:
        return self._request('POST', '/v1/admin/user/add',
                             json={'username': username})

    def user_remove(self, username: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/user/{username}')

    def user_key_add(self, username: str, type_: str,
                     data_b64: str) -> dict[str, Any]:
        return self._request('POST', f'/v1/admin/user/{username}/key',
                             json={'type': type_, 'data': data_b64})

    def user_key_remove(self, username: str,
                        fingerprint: str) -> dict[str, Any]:
        return self._request('DELETE',
                             f'/v1/admin/user/{username}/key/{fingerprint}')

    def user_list(self, *, username: str | None = None,
                  fingerprint: str | None = None) -> list[dict[str, Any]]:
        params = {}
        if username:
            params['username'] = username
        if fingerprint:
            params['fingerprint'] = fingerprint
        return self._request('GET', '/v1/admin/user/list',
                             params=params)['users']

    # ---- policy ----
    def policy_add(self, username: str,
                   policy: dict[str, Any]) -> dict[str, Any]:
        return self._request('POST', '/v1/admin/policy/add',
                             json={'username': username, 'policy': policy})

    def policy_remove(self, policy_id: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/policy/{policy_id}')

    # ---- admin ----
    def admin_add(self, name: str, role: str) -> dict[str, Any]:
        return self._request('POST', '/v1/admin/admin/add',
                             json={'name': name, 'role': role})

    def admin_remove(self, name: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/admin/{name}')

    def admin_list(self) -> list[dict[str, Any]]:
        return self._request('GET', '/v1/admin/admin/list')['admins']

    # ---- audit ----
    def audit(self, **filters) -> dict[str, Any]:
        return self._request('GET', '/v1/admin/audit', params=filters)

    # ---- templates ----
    def template_set(self, scope: str, kind: str, content: str, *,
                     scope_name: str | None = None) -> dict[str, Any]:
        """Set or replace a template at the given scope.

        ``scope`` is one of 'default', 'group', 'server'. ``scope_name``
        is required for 'group' and 'server' (the group name or the
        server canonical name) and ignored for 'default'.
        """
        body: dict[str, Any] = {'scope': scope, 'kind': kind, 'content': content}
        if scope_name is not None:
            body['scope_name'] = scope_name
        return self._request('POST', '/v1/admin/template/set', json=body)

    def template_unset(self, scope: str, kind: str, *,
                       scope_name: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {'scope': scope, 'kind': kind}
        if scope_name is not None:
            body['scope_name'] = scope_name
        return self._request('POST', '/v1/admin/template/unset', json=body)

    def template_list(self) -> dict[str, Any]:
        """Return every template the CA knows about."""
        return self._request('GET', '/v1/admin/template/list')

    def template_effective(self, server_name: str,
                           kind: str = 'openssh') -> dict[str, Any]:
        """Return the effective (post-precedence) template for a server."""
        return self._request(
            'GET', f'/v1/admin/template/effective/{server_name}',
            params={'kind': kind})

    # ---- CA-bypass cert ----
    def bypass_cert_mint(self, username: str, pubkey_b64: str, *,
                         validity_days: int = 90,
                         source_bind: str | None = None,
                         server_bind: str | None = None,
                         channels: list[str] | None = None,
                         force_command: str | None = None,
                         max_session_seconds: int | None = None) -> dict[str, Any]:
        """Mint a CA-bypass authz cert for the named user.

        The cert is PEM-returned; operator stores it offline and
        presents it via ``mssh --inject-bypass-cert <cert>`` to
        inject directly into a msshd's authz cache.
        """
        body: dict[str, Any] = {
            'username': username, 'pubkey_b64': pubkey_b64,
            'validity_days': validity_days,
        }
        if source_bind is not None:
            body['source_bind'] = source_bind
        if server_bind is not None:
            body['server_bind'] = server_bind
        if channels is not None:
            body['channels'] = list(channels)
        if force_command is not None:
            body['force_command'] = force_command
        if max_session_seconds is not None:
            body['max_session_seconds'] = max_session_seconds
        return self._request('POST', '/v1/admin/bypass-cert/mint', json=body)

    # ---- §5 cert minting (TLS server / HTTPS user / code-signing) ----
    def cert_mint(self, cert_type: str, cn: str, *,
                  sans: list[str] | None = None,
                  validity_days: int | None = None) -> dict[str, Any]:
        """Mint an X.509 leaf cert against the TLS CA hierarchy.

        ``cert_type`` is one of ``tls-server`` | ``https-user`` |
        ``code-sign``. ``sans`` are only valid for ``tls-server``;
        each entry must be of the form ``DNS:<name>``, ``IP:<addr>``,
        or a bare DNS name.
        """
        body: dict[str, Any] = {'type': cert_type, 'cn': cn}
        if sans is not None:
            body['sans'] = list(sans)
        if validity_days is not None:
            body['validity_days'] = int(validity_days)
        return self._request('POST', '/v1/admin/cert/mint', json=body)

    def openvpn_issue(self, cn: str, server_endpoint: str, *,
                      proto: str = 'udp', dev: str = 'tun',
                      validity_days: int | None = None) -> dict[str, Any]:
        """Issue an OpenVPN client cert + key + CA bundle plus the
        connection metadata the CLI needs to assemble the ``.ovpn``
        file. ``server_endpoint`` is ``"host port"`` form (e.g.
        ``"vpn.example.com 1194"``)."""
        body: dict[str, Any] = {
            'cn': cn,
            'server_endpoint': server_endpoint,
            'proto': proto,
            'dev': dev,
        }
        if validity_days is not None:
            body['validity_days'] = int(validity_days)
        return self._request('POST', '/v1/admin/openvpn/issue', json=body)

    # ---- CRL ----
    def cert_revoke(self, serials: list[str], *,
                    reason: str = '') -> dict[str, Any]:
        """Append a CRL entry revoking the listed cert serials.
        Every msshd in the fleet picks this up on its next authorize
        call. See archive/design/notes-bypass-cache.md "CRL Amendment"."""
        body: dict[str, Any] = {'serials': list(serials)}
        if reason:
            body['reason'] = reason
        return self._request('POST', '/v1/admin/cert/revoke', json=body)

    def crl_list(self, after: int = 0,
                 limit: int | None = None) -> dict[str, Any]:
        """Return the CRL entries with seq > after."""
        params: dict[str, Any] = {'after': int(after)}
        if limit is not None:
            params['limit'] = int(limit)
        return self._request('GET', '/v1/admin/crl', params=params)
