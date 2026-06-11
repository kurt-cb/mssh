"""WireGuard catalog — servers, peers, IP allocation.

Design: §4.3.11 (auxiliary WireGuard issuance) / §13.7
(see design/mssh_design_v1.md).

Unlike X.509 leaves the CA can sign, WireGuard credentials are raw
Curve25519 keypairs + peer metadata (AllowedIPs, endpoint, etc.).
Nothing to sign — the CA's value here is the catalog: who has which
public key, on which interface, with which AllowedIPs. Revoking a
peer is just removing it from the server's wg0.conf — the
operator's WireGuard daemon polls the CA for the latest config and
applies it.

Persistence: a single JSON file on disk. Atomic writes via
write-then-rename, file mode 0600 (the server's private key lives
here too).
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import logging
import os
import secrets
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

log = logging.getLogger('mssh.ca.wireguard')


# ---- Curve25519 keypair generation -----------------------------------------

def generate_wg_keypair() -> tuple[bytes, bytes]:
    """Generate a Curve25519 keypair for WireGuard.

    Returns ``(private_key_bytes, public_key_bytes)`` — both 32 bytes
    raw. Callers serialize to base64 for the wg0.conf or wg-quick
    config; we keep raw here so the storage round-trips cleanly.
    """
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives import serialization
    priv = x25519.X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def b64(b: bytes) -> str:
    import base64
    return base64.b64encode(b).decode('ascii')


# ---- Data model ------------------------------------------------------------

@dataclass
class WireGuardServer:
    """One WireGuard server (interface). Holds the server's keypair,
    the network it serves, and connection metadata for peers.

    Dual-stack (v0.4.0+): when ``network_v6`` is set, the server runs
    dual-stack — server address is v4 + v6 (rendered comma-joined on
    the wg-quick ``Address`` line) and every peer also gets a v6
    address registered in its ``[Peer] AllowedIPs``. Empty
    ``network_v6`` (default) is byte-identical to the pre-0.4.0
    v4-only behavior.
    """
    name: str
    network: str                # e.g. '10.20.0.0/24'
    listen_port: int            # e.g. 51820
    endpoint: str               # e.g. 'vpn.example.com:51820'
    private_key_b64: str        # CA-stored; never returned to operators in plain
    public_key_b64: str         # advertised to peers in their wg-quick config
    server_address: str         # the server's own address on the network (e.g. '10.20.0.1/24')
    created_at: str
    created_by: str             # admin name
    # Dual-stack (v0.4.0+). Empty string = v4-only server.
    network_v6: str = ''                # e.g. 'fd00:98:123::/64'
    server_address_v6: str = ''         # e.g. 'fd00:98:123::1/64'

    def to_dict(self) -> dict:
        return {
            'name': self.name, 'network': self.network,
            'listen_port': self.listen_port, 'endpoint': self.endpoint,
            'private_key_b64': self.private_key_b64,
            'public_key_b64': self.public_key_b64,
            'server_address': self.server_address,
            'created_at': self.created_at, 'created_by': self.created_by,
            'network_v6': self.network_v6,
            'server_address_v6': self.server_address_v6,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'WireGuardServer':
        return cls(
            name=str(d['name']), network=str(d['network']),
            listen_port=int(d['listen_port']),
            endpoint=str(d['endpoint']),
            private_key_b64=str(d['private_key_b64']),
            public_key_b64=str(d['public_key_b64']),
            server_address=str(d['server_address']),
            created_at=str(d.get('created_at') or ''),
            created_by=str(d.get('created_by') or ''),
            # New fields default to '' for backward-compat with v0.3.x JSON.
            network_v6=str(d.get('network_v6') or ''),
            server_address_v6=str(d.get('server_address_v6') or ''),
        )


@dataclass
class WireGuardPeer:
    """One WireGuard peer (client). Bound to a server by ``server_name``.
    Pubkey is the canonical identifier — the private key is given to
    the peer at issuance time and not retained.

    Dual-stack (v0.4.0+): when the peer's server has ``network_v6``,
    the peer also gets ``address_v6`` (parallel-numbered to its v4
    host portion — see ``_v6_address_for_v4_host()``). Empty
    ``address_v6`` (default) is byte-identical to v4-only behavior.
    """
    name: str                   # peer name (typically a username)
    server_name: str
    address: str                # peer's address on the network (e.g. '10.20.0.10/32')
    public_key_b64: str
    issued_at: str
    issued_by: str              # admin name
    persistent_keepalive: int = 0   # seconds; 0 disables
    # Dual-stack (v0.4.0+). Empty string = v4-only peer.
    address_v6: str = ''            # e.g. 'fd00:98:123::a/128'

    def to_dict(self) -> dict:
        return {
            'name': self.name, 'server_name': self.server_name,
            'address': self.address,
            'public_key_b64': self.public_key_b64,
            'issued_at': self.issued_at, 'issued_by': self.issued_by,
            'persistent_keepalive': self.persistent_keepalive,
            'address_v6': self.address_v6,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'WireGuardPeer':
        return cls(
            name=str(d['name']), server_name=str(d['server_name']),
            address=str(d['address']),
            public_key_b64=str(d['public_key_b64']),
            issued_at=str(d.get('issued_at') or ''),
            issued_by=str(d.get('issued_by') or ''),
            persistent_keepalive=int(d.get('persistent_keepalive') or 0),
            # New field defaults to '' for backward-compat with v0.3.x JSON.
            address_v6=str(d.get('address_v6') or ''),
        )


# ---- Errors ----------------------------------------------------------------

class WireGuardError(Exception):
    pass


class WireGuardConflict(WireGuardError):
    pass


class WireGuardNotFound(WireGuardError):
    pass


class WireGuardCapacityError(WireGuardError):
    """Raised when the network has no free IPs left."""


# ---- Store -----------------------------------------------------------------

@dataclass
class _Catalog:
    servers: dict[str, WireGuardServer] = field(default_factory=dict)
    peers: dict[tuple[str, str], WireGuardPeer] = field(default_factory=dict)


class WireGuardStore:
    """Coarse-locked JSON catalog. Read-modify-write semantics; all
    mutations fsync. The store reloads on every locked operation so
    concurrent processes against the same file stay coherent
    (unusual in practice — mssh-ca is single-process).
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _read(self) -> _Catalog:
        if not self.path.exists():
            return _Catalog()
        try:
            raw = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            log.warning('wireguard: catalog %s unreadable: %s', self.path, e)
            return _Catalog()
        servers = {s['name']: WireGuardServer.from_dict(s)
                   for s in raw.get('servers') or []}
        peers = {}
        for p in raw.get('peers') or []:
            pp = WireGuardPeer.from_dict(p)
            peers[(pp.server_name, pp.name)] = pp
        return _Catalog(servers=servers, peers=peers)

    def _write(self, cat: _Catalog) -> None:
        data = {
            'servers': [s.to_dict() for s in cat.servers.values()],
            'peers':   [p.to_dict() for p in cat.peers.values()],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + '.tmp.' +
                                    secrets.token_hex(4))
        try:
            with tmp.open('w') as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    # ---- Server CRUD -------------------------------------------------------

    def server_init(self, *, name: str, listen_port: int,
                    endpoint: str, created_by: str,
                    network: str = '',
                    network_v6: str = '') -> WireGuardServer:
        """Create a new WireGuard server. Server takes host number 1
        (``.1`` on v4, ``::1`` on v6); peers get host numbers ≥ 2.

        Family-agnostic (v0.4.0+): pass any combination of ``network``
        (v4) and ``network_v6`` (v6) — at least one is required. The
        server is dual-stack iff both are set, v4-only iff only
        ``network`` is set, v6-only iff only ``network_v6`` is set.
        For dual-stack, the server's v4 and v6 addresses share host
        number 1.
        """
        # §4.3.11 / §13.7 — WireGuard server provisioning
        if not network and not network_v6:
            raise WireGuardError(
                'at least one of network (v4) or network_v6 required')
        if not (1 <= listen_port <= 65535):
            raise WireGuardError(
                f'listen_port {listen_port} out of range')

        server_address = ''
        if network:
            try:
                net = ipaddress.ip_network(network, strict=False)
            except ValueError as e:
                raise WireGuardError(f'invalid network {network!r}: {e}')
            if net.num_addresses < 4:
                raise WireGuardError(
                    f'network {network!r} too small (need at least /30)')
            # Server takes host number 1 (network_address + 1).
            server_ip = net.network_address + 1
            server_address = f'{server_ip}/{net.prefixlen}'

        server_address_v6 = ''
        if network_v6:
            try:
                net6 = ipaddress.IPv6Network(network_v6, strict=False)
            except ValueError as e:
                raise WireGuardError(
                    f'invalid network_v6 {network_v6!r}: {e}')
            # Server takes host number 1 (network_address + 1). Avoids
            # listing 2^64 hosts via net6.hosts() which would OOM.
            server_ip_v6 = ipaddress.IPv6Address(
                int(net6.network_address) + 1)
            server_address_v6 = f'{server_ip_v6}/{net6.prefixlen}'

        priv, pub = generate_wg_keypair()
        srv = WireGuardServer(
            name=name, network=network,
            listen_port=listen_port, endpoint=endpoint,
            private_key_b64=b64(priv), public_key_b64=b64(pub),
            server_address=server_address,
            created_at=_now_iso(), created_by=created_by,
            network_v6=network_v6,
            server_address_v6=server_address_v6,
        )
        with self._lock:
            cat = self._read()
            if name in cat.servers:
                raise WireGuardConflict(
                    f'WireGuard server {name!r} already exists')
            cat.servers[name] = srv
            self._write(cat)
        return srv

    def server_remove(self, name: str) -> None:
        with self._lock:
            cat = self._read()
            if name not in cat.servers:
                raise WireGuardNotFound(f'no WireGuard server {name!r}')
            # Cascade: remove all peers on this server.
            cat.peers = {k: v for k, v in cat.peers.items()
                         if v.server_name != name}
            del cat.servers[name]
            self._write(cat)

    def server_get(self, name: str) -> WireGuardServer:
        cat = self._read()
        s = cat.servers.get(name)
        if s is None:
            raise WireGuardNotFound(f'no WireGuard server {name!r}')
        return s

    def server_list(self) -> list[WireGuardServer]:
        return sorted(self._read().servers.values(), key=lambda s: s.name)

    # ---- Peer CRUD ---------------------------------------------------------

    def peer_issue(self, *, name: str, server_name: str, issued_by: str,
                   persistent_keepalive: int = 0,
                   ) -> tuple[WireGuardPeer, bytes]:
        """Allocate the next free host number, mint a keypair, store
        the public half. Returns ``(peer_record, private_key_bytes)``
        — the private key is given to the recipient and not retained.

        Allocation rule (v0.4.0+, family-agnostic): the peer gets the
        next free host *number* in the tunnel. When both families are
        present, the same number is used in each (so peer's v4 ``.10``
        ⟷ v6 ``::a``). For v4-only servers, scan ``net.hosts()`` (still
        respects the /24 ceiling). For v6-only servers, pick the
        smallest integer ≥ 2 not in the peer catalog (never iterate
        the /64 address space).
        """
        # §4.3.11 / §13.7 — WireGuard peer issuance (keypair mint +
        # host-number allocation)
        with self._lock:
            cat = self._read()
            if server_name not in cat.servers:
                raise WireGuardNotFound(
                    f'no WireGuard server {server_name!r}')
            if (server_name, name) in cat.peers:
                raise WireGuardConflict(
                    f'peer {name!r} already issued on {server_name!r}')

            srv = cat.servers[server_name]

            # Build the set of host numbers already used (server is
            # always 1; each peer's number is derived from its address).
            used_nums = {1}
            for p in cat.peers.values():
                if p.server_name == server_name:
                    used_nums.add(_peer_host_number(srv, p))

            # Allocate the next free host number.
            if srv.network:
                # v4-only or dual-stack: walk net.hosts() so the /24
                # ceiling is enforced. host_number is the offset from
                # network_address (so 10.20.0.10 → 10).
                net = ipaddress.ip_network(srv.network, strict=False)
                free_num = None
                for host in net.hosts():
                    num = int(host) - int(net.network_address)
                    if num not in used_nums:
                        free_num = num
                        break
                if free_num is None:
                    raise WireGuardCapacityError(
                        f'no free addresses in {srv.network!r}')
                v4_addr = net.network_address + free_num
                address = f'{v4_addr}/32'
            else:
                # v6-only: scan the peer catalog for the smallest
                # unused integer ≥ 2. No /64 enumeration; the catalog
                # is tiny by definition.
                free_num = 2
                while free_num in used_nums:
                    free_num += 1
                address = ''

            # v6 derives from the same host number (when v6 is configured).
            address_v6 = ''
            if srv.network_v6:
                net6 = ipaddress.IPv6Network(srv.network_v6, strict=False)
                v6_addr = ipaddress.IPv6Address(
                    int(net6.network_address) + free_num)
                address_v6 = f'{v6_addr}/128'

            priv_bytes, pub_bytes = generate_wg_keypair()
            peer = WireGuardPeer(
                name=name, server_name=server_name,
                address=address,
                public_key_b64=b64(pub_bytes),
                issued_at=_now_iso(), issued_by=issued_by,
                persistent_keepalive=persistent_keepalive,
                address_v6=address_v6,
            )
            cat.peers[(server_name, name)] = peer
            self._write(cat)
            return peer, priv_bytes

    def peer_revoke(self, *, name: str, server_name: str) -> None:
        with self._lock:
            cat = self._read()
            key = (server_name, name)
            if key not in cat.peers:
                raise WireGuardNotFound(
                    f'no peer {name!r} on server {server_name!r}')
            del cat.peers[key]
            self._write(cat)

    def peer_list(self, server_name: str | None = None,
                  ) -> list[WireGuardPeer]:
        cat = self._read()
        peers = sorted(cat.peers.values(),
                       key=lambda p: (p.server_name, p.name))
        if server_name is not None:
            peers = [p for p in peers if p.server_name == server_name]
        return peers


# ---- Config emitters -------------------------------------------------------

def render_server_config(srv: WireGuardServer,
                         peers: Iterable[WireGuardPeer]) -> str:
    """Render ``/etc/wireguard/<srv.name>.conf`` for the WireGuard
    daemon. Each peer becomes a ``[Peer]`` block.

    Per-peer ``AllowedIPs`` lists the peer's host addresses only
    (``…/32`` + ``…/128``) — cryptokey routing. LAN routes are
    added client-side by the upstream operator (e.g. totaldns).
    """
    parts: list[str] = []
    parts.append('# mssh-admin wireguard server show — emitted config')
    parts.append('[Interface]')
    parts.append(f'Address    = {_join_addresses(srv.server_address, srv.server_address_v6)}')
    parts.append(f'ListenPort = {srv.listen_port}')
    parts.append(f'PrivateKey = {srv.private_key_b64}')
    parts.append('')
    for p in peers:
        parts.append(f'# {p.name}')
        parts.append('[Peer]')
        parts.append(f'PublicKey  = {p.public_key_b64}')
        parts.append(f'AllowedIPs = {_join_addresses(p.address, p.address_v6)}')
        parts.append('')
    return '\n'.join(parts)


def render_peer_config(srv: WireGuardServer, peer: WireGuardPeer,
                       peer_private_key_bytes: bytes,
                       *, dns: str | None = None) -> str:
    """Render the wg-quick config the recipient loads on their
    laptop. Embeds the peer's freshly-minted private key.

    The client-side ``[Peer] AllowedIPs`` is the server network(s) —
    routes that the client sends through the tunnel. Operators who
    want split tunnel or additional routes (e.g. totaldns's served
    LAN prefixes) edit/append after rendering.
    """
    parts: list[str] = []
    parts.append(f'# mssh-admin wireguard issue — config for {peer.name}')
    parts.append('[Interface]')
    parts.append(f'Address    = {_join_addresses(peer.address, peer.address_v6)}')
    parts.append(f'PrivateKey = {b64(peer_private_key_bytes)}')
    if dns:
        parts.append(f'DNS        = {dns}')
    parts.append('')
    parts.append(f'# {srv.name}')
    parts.append('[Peer]')
    parts.append(f'PublicKey  = {srv.public_key_b64}')
    parts.append(f'Endpoint   = {srv.endpoint}')
    # Route the whole server network through this peer (per family).
    # Operators who want split tunnel can edit this.
    parts.append(f'AllowedIPs = {_join_addresses(srv.network, srv.network_v6)}')
    if peer.persistent_keepalive:
        parts.append(f'PersistentKeepalive = {peer.persistent_keepalive}')
    parts.append('')
    return '\n'.join(parts)


# ---- helpers ---------------------------------------------------------------

def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _join_addresses(*addrs: str) -> str:
    """Comma-join the non-empty address strings, in family order.

    Used by both renderers so v4-only servers emit byte-identical
    output to pre-0.4.0 (no trailing comma, no empty fragments).
    """
    return ', '.join(a for a in addrs if a)


def _peer_host_number(srv: WireGuardServer, peer: WireGuardPeer) -> int:
    """Return the peer's host number — the integer offset of its
    address from the server's network start.

    For dual-stack peers, v4 and v6 share a number, so consulting
    either is sufficient; we prefer v4 when present (legacy v0.3.x
    peers have no v6, and the v4 path matches the original
    next-free-host algorithm exactly).
    """
    if peer.address:
        net = ipaddress.ip_network(srv.network, strict=False)
        ip = ipaddress.ip_interface(peer.address).ip
        return int(ip) - int(net.network_address)
    if peer.address_v6 and srv.network_v6:
        net6 = ipaddress.IPv6Network(srv.network_v6, strict=False)
        ip6 = ipaddress.ip_interface(peer.address_v6).ip
        return int(ip6) - int(net6.network_address)
    # Malformed peer (no address at all) — number 0 reserves the
    # network slot, will never collide with a real allocation.
    return 0
