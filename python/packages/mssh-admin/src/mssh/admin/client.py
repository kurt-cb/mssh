"""mTLS HTTP client for the admin API.

Design: §7.3.6 (CA client wrapper used by every mssh-admin subcommand)
+ §9.3.1 (the admin API surface this client targets).
"""
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
                 ca_cert: str, timeout: float = 10.0,
                 origin: str | None = None):
        # Phase 2 §12.4.2 origin tagging — when set (e.g. 'mcp' for
        # mssh-mcp's CA client), every request carries X-MSSH-Origin
        # so the CA audits + capability-gates accordingly (§13.9.2).
        self.base_url = base_url
        self.admin_cert = admin_cert
        self.admin_key = admin_key
        self.ca_cert = ca_cert
        self.timeout = timeout
        self.origin = origin
        self._session = requests.Session()
        self._session.trust_env = False

    def _request(self, method: str, path: str, *,
                 json: dict[str, Any] | None = None,
                 params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = self.base_url.rstrip('/') + path
        # §12.4.2 X-MSSH-Origin: mcp header on MCP-originated calls.
        headers = {}
        if self.origin:
            headers['X-MSSH-Origin'] = self.origin
        resp = self._session.request(
            method=method, url=url,
            json=json, params=params,
            cert=(self.admin_cert, self.admin_key),
            verify=self.ca_cert,
            timeout=self.timeout,
            headers=headers or None,
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
                  validity_days: int | None = None,
                  csr_pem: str | None = None) -> dict[str, Any]:
        """Mint an X.509 leaf cert against the TLS CA hierarchy.

        ``cert_type`` is one of ``tls-server`` | ``https-user`` |
        ``code-sign``. ``sans`` are only valid for ``tls-server``;
        each entry must be of the form ``DNS:<name>``, ``IP:<addr>``,
        or a bare DNS name.

        v0.5.3 CSR path: when ``csr_pem`` is set, the CA uses the CSR's
        public key + SANs (union with ``sans``) instead of generating
        a keypair. Response's ``credentials.key_pem`` is empty — the
        operator's private key never touches the CA. Recommended for
        TLS server certs where the key should stay on the target host.
        """
        body: dict[str, Any] = {'type': cert_type, 'cn': cn}
        if sans is not None:
            body['sans'] = list(sans)
        if validity_days is not None:
            body['validity_days'] = int(validity_days)
        if csr_pem is not None:
            body['csr'] = csr_pem
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

    # ---- §5 WireGuard catalog ----
    def wireguard_server_init(self, name: str,
                              endpoint: str, *,
                              network: str = '',
                              network_v6: str = '',
                              listen_port: int = 51820) -> dict[str, Any]:
        # v0.4.0+: network + network_v6 are independently optional;
        # at least one is required (CA enforces).
        body: dict[str, Any] = {
            'name': name,
            'listen_port': listen_port, 'endpoint': endpoint,
        }
        if network:
            body['network'] = network
        if network_v6:
            body['network_v6'] = network_v6
        return self._request('POST', '/v1/admin/wireguard/server', json=body)

    def wireguard_server_remove(self, name: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/wireguard/server/{name}')

    def wireguard_server_show(self, name: str) -> dict[str, Any]:
        return self._request('GET', f'/v1/admin/wireguard/server/{name}')

    def wireguard_server_list(self) -> dict[str, Any]:
        return self._request('GET', '/v1/admin/wireguard/server')

    def wireguard_peer_issue(self, name: str, server: str, *,
                             persistent_keepalive: int = 0,
                             dns: str | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {
            'name': name, 'server': server,
            'persistent_keepalive': persistent_keepalive,
        }
        if dns:
            body['dns'] = dns
        return self._request('POST', '/v1/admin/wireguard/peer', json=body)

    def wireguard_peer_revoke(self, name: str, server: str) -> dict[str, Any]:
        return self._request('DELETE',
                             f'/v1/admin/wireguard/peer/{server}/{name}')

    def wireguard_peer_list(self, server: str | None = None
                            ) -> dict[str, Any]:
        params = {'server': server} if server else None
        return self._request('GET', '/v1/admin/wireguard/peer', params=params)

    # ---- Admin-2FA passkey flow (design/admin-2fa.md) ----
    def passkey_admin_enroll(self, admin_name: str, *,
                              label: str = '',
                              display_name: str = '') -> dict[str, Any]:
        body: dict[str, Any] = {'admin_name': admin_name}
        if label:
            body['label'] = label
        if display_name:
            body['display_name'] = display_name
        return self._request('POST', '/v1/admin/passkey/enroll-begin',
                              json=body)

    def passkey_admin_list(self, admin_name: str) -> dict[str, Any]:
        return self._request('GET', f'/v1/admin/passkey/{admin_name}/list')

    def passkey_admin_revoke(self, admin_name: str,
                              credential_id: str) -> dict[str, Any]:
        return self._request(
            'DELETE',
            f'/v1/admin/passkey/{admin_name}/{credential_id}')

    def passkey_poll(self, ceremony_id: str) -> dict[str, Any]:
        return self._request('GET', f'/v1/admin/passkey/ceremony/{ceremony_id}')

    # ---- external-tool admin (RP-service flow) ----
    def external_tool_add(self, name: str, rp_id: str,
                            outcome_url_prefix: str) -> dict[str, Any]:
        return self._request('POST', '/v1/admin/external-tool/add', json={
            'name': name, 'rp_id': rp_id,
            'outcome_url_prefix': outcome_url_prefix,
        })

    def external_tool_remove(self, name: str) -> dict[str, Any]:
        return self._request('DELETE', f'/v1/admin/external-tool/{name}')

    def external_tool_list(self) -> dict[str, Any]:
        return self._request('GET', '/v1/admin/external-tool/list')

    # ---- §4.3.10 + §13.4 cert renew ----
    def cert_renew(self, *,
                   revoke_predecessor: bool = False) -> dict[str, Any]:
        """POST /v1/cert/renew.

        The endpoint is mTLS-authenticated by the cert being renewed
        (passed via self.admin_cert / self.admin_key); the caller is
        responsible for setting those to the cert+key it wants
        renewed, not the admin creds. See ``mssh-admin cert renew``
        for the canonical call site.
        """
        body: dict[str, Any] = {}
        if revoke_predecessor:
            body['revoke_predecessor'] = True
        return self._request('POST', '/v1/cert/renew', json=body)

    # ---- CRL ----
    def cert_revoke(self, serials: list[str], *,
                    reason: str = '',
                    issuer: str = 'user-mint') -> dict[str, Any]:
        """Append a CRL entry revoking the listed cert serials under
        ``issuer`` (default user-mint, matching v0.2.0 behavior). Every
        msshd in the fleet picks this up on its next authorize call."""
        body: dict[str, Any] = {'serials': list(serials), 'issuer': issuer}
        if reason:
            body['reason'] = reason
        return self._request('POST', '/v1/admin/cert/revoke', json=body)

    def crl_list(self, after: int = 0,
                 limit: int | None = None,
                 issuer: str = 'user-mint') -> dict[str, Any]:
        """Return the CRL entries with seq > after for ``issuer``."""
        params: dict[str, Any] = {'after': int(after), 'issuer': issuer}
        if limit is not None:
            params['limit'] = int(limit)
        return self._request('GET', '/v1/admin/crl', params=params)

    # ---- intermediate management (v0.2.4+) ----
    def intermediate_list(self) -> dict[str, Any]:
        """Return metadata about each named intermediate (issuer_id,
        cert validity window, role). See /v1/admin/intermediate/list."""
        return self._request('GET', '/v1/admin/intermediate/list')

    def intermediate_rotate(self, role: str) -> dict[str, Any]:
        """Generate a fresh keypair for the named intermediate, sign
        a new cert via root, and archive the old one. Validators that
        pin to this intermediate need the new cert distributed
        out-of-band."""
        return self._request('POST',
                              '/v1/admin/intermediate/rotate',
                              json={'role': role})

    def intermediate_mint_external(self, name: str, *,
                                     path_length: int = 0,
                                     validity_days: int | None = None,
                                     profile: str = 'generic',
                                     new_root: bool = False,
                                     root_name: str | None = None,
                                     retain_key: bool | None = None,
                                     ) -> dict[str, Any]:
        """Mint an external Intermediate CA cert (§2.6 / §15.20 / §15.22).

        The response carries the cert + key — operator hands the key to
        the external entity OUT OF BAND. The CA retains only the public
        cert (plus `profile.json` when `profile != generic`).

        Args:
          name:          short identifier; becomes Organization= in cert
          path_length:   sub-CA depth (0 = leaves only)
          validity_days: overrides profile default (3650 for generic,
                         10950 for device-identity)
          profile:       'generic' (v0.4.x behavior) or 'device-identity'
                         (§15.20 — stamps §15.23 intermediate-purpose
                         marker so external-use leaves can pin to it)
          new_root:      opt into §15.22 separate-Root: create a fresh
                         Root at <ca_dir>/roots/<root_name>/ and sign
                         this intermediate under it
          root_name:     name for the new Root; defaults to `name`
          retain_key:    override CA-side key retention. Defaults are:
                         profile=generic → False (v0.4.x semantics);
                         profile=device-identity → True (CA needs the
                         key to sign external-use leaves). Set
                         retain_key=False on a non-generic profile to
                         opt into "external entity holds the key"
                         (§2.6) even for device-identity intermediates.
        """
        body: dict[str, Any] = {
            'name': name,
            'path_length': int(path_length),
            'profile': profile,
        }
        if validity_days is not None:
            body['validity_days'] = int(validity_days)
        if new_root:
            body['new_root'] = True
        if root_name:
            body['root_name'] = root_name
        if retain_key is not None:
            body['retain_key'] = bool(retain_key)
        return self._request('POST',
                              '/v1/admin/intermediate/mint-external',
                              json=body)

    def cert_external_use_mint(self, *, cn: str, csr_pem: str,
                                issuer_intermediate: str,
                                validity_days: int | None = None,
                                never_expires: bool = False,
                                custom_oids: list[dict] | None = None,
                                ) -> dict[str, Any]:
        """§15.19 — mint an external-use leaf from a CSR.

        The CA verifies the CSR's self-signature, checks the issuer
        intermediate carries the §15.20 purpose marker, and returns
        the signed leaf. Operator's private key never touches the CA.

        Args:
          cn:                  Common Name on the leaf
          csr_pem:             PKCS#10 PEM string
          issuer_intermediate: name of a `mint-external --profile`
                               intermediate on this CA
          validity_days:       overrides ca-config `cert_kinds.external-use`
          never_expires:       set notAfter to RFC 5280 §4.1.2.5 sentinel
          custom_oids:         [{oid|name, value, critical?}] from the
                               ca-config `custom_oids:` allowlist
        """
        body: dict[str, Any] = {
            'cn': cn,
            'csr': csr_pem,
            'issuer_intermediate': issuer_intermediate,
        }
        if validity_days is not None:
            body['validity_days'] = int(validity_days)
        if never_expires:
            body['never_expires'] = True
        if custom_oids:
            body['custom_oids'] = custom_oids
        return self._request('POST',
                              '/v1/admin/cert/external-use',
                              json=body)

    def intermediate_list_external(self) -> dict[str, Any]:
        """List external Intermediate CAs previously minted."""
        return self._request('GET',
                              '/v1/admin/intermediate/list-external')
