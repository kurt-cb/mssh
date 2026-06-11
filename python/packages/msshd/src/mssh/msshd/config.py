"""msshd.yaml loader and validator.

Mirrors the schema in ``config/msshd.yaml.example``. The loader
is dataclass-based with explicit field types; ``validate()`` performs
cross-field checks and on-disk-permission checks for cert/key paths.

msshd YAML is intentionally small — see
[architecture.md § 11](../../design/architecture.md).
Operators do not edit the inner sshd config; that is rendered hermetically
by msshd from a template that ships in msshd package.

Design: §14.3.1 (see design/mssh_design_v1.md) — msshd.yaml schema,
field-by-field defaults. §13.9.7 — default-deny semantics when
config is missing / mode-required fields are empty (enforce-mode
validate() refuses to start, fallback degrades cleanly).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


MODE_FALLBACK = 'fallback'
MODE_GATED = 'gated'                    # Phase 2: §1.4.2 / §5.3.3
MODE_ENFORCE = 'enforce'
VALID_MODES = (MODE_FALLBACK, MODE_GATED, MODE_ENFORCE)


@dataclass
class FallbackConfig:
    host: str = '127.0.0.1'
    port: int = 22


@dataclass
class ListenConfig:
    external_address: str = '0.0.0.0'
    external_port: int = 2200
    interfaces: list[str] = field(default_factory=list)


@dataclass
class TLSConfig:
    server_cert: str = ''
    server_key: str = ''
    user_ca_pubkey: str = ''


@dataclass
class CAConfig:
    endpoints: list[str] = field(default_factory=list)
    client_cert: str = ''
    client_key: str = ''
    ca_pubkey: str = ''
    timeout_seconds: float = 5.0
    emergency_cert: str = ''
    # CRL sync controls. crl_fetch_limit caps each GET /v1/crl call
    # so a long-offline msshd doesn't ask the CA for a huge batch.
    # crl_strict_threshold: if (current_crl_seq - last_applied) >
    # this, msshd refuses cache hits and falls through to live CA
    # calls until sync catches up. 0 = disable strict gating (always
    # serve from cache regardless of staleness). See
    # archive/design/notes-bypass-cache.md "CRL Amendment".
    crl_fetch_limit: int = 100
    crl_strict_threshold: int = 50
    # Trust root for verifying CA-grant authz certs (mssh-ca's
    # user-mint intermediate cert in v0.2.1+; the legacy signing-cert
    # in v0.2.0). Used by inline cert verification paths that don't
    # go through the live CA. Required to enable bypass-cert injection
    # unless `bypass_trust_root` below is also set (in which case
    # bypass injection uses that one and auth_trust_root is optional).
    auth_trust_root: str = ''
    # Trust root for verifying inline-presented bypass certs (the
    # mssh-ca `bypass-mint` intermediate cert, since v0.2.1). When
    # unset, bypass-cert injection falls back to verifying against
    # `auth_trust_root` for backward-compat with v0.2.0 deployments
    # (single-signer layout where bypass certs and authz certs
    # share a signing key). New deployments must pin separately to
    # honor the trust-model amendment (validation pins to the
    # SPECIFIC intermediate). See design/security.md "Chain of
    # trust v2".
    bypass_trust_root: str = ''


INNER_MODE_LONG_LIVED = 'long-lived'
INNER_MODE_PER_CONNECTION = 'per-connection'
VALID_INNER_MODES = (INNER_MODE_LONG_LIVED, INNER_MODE_PER_CONNECTION)


@dataclass
class InnerConfig:
    sshd_binary: str = '/usr/sbin/sshd'
    port_range: tuple[int, int] = (49152, 65535)
    # 'long-lived'    (default) — one inner sshd at msshd boot, single
    #                  hermetic config, no per-session policy variability.
    # 'per-connection'         — fresh sshd per session, config rendered
    #                  by the CA. Honors per-session FROMCA_* policy
    #                  directly via OpenSSH. Opt-in for now; switches to
    #                  default in a future release once shaken out.
    mode: str = INNER_MODE_LONG_LIVED


@dataclass
class UsersConfig:
    allowed: list[str] = field(default_factory=list)


@dataclass
class LoggingConfig:
    level: str = 'info'
    destination: str = 'stderr'
    audit_destination: str = 'file:/var/log/mssh/msshd-audit.jsonl'


@dataclass
class PerformanceConfig:
    inner_cipher_none: bool = False
    max_concurrent_sessions: int = 200
    # Authz cache eviction policy. Per-principal cap is the primary
    # control; global cap is the safety net. Both can be set to 0 to
    # disable that level. See archive/design/notes-bypass-cache.md "Eviction
    # Amendment".
    #
    # On put(): if a principal would exceed `authz_cache_max_per_principal`
    # entries, the oldest entry FOR THAT PRINCIPAL is evicted first.
    # Then if the total cache size exceeds `authz_cache_max_total`,
    # the globally-oldest entry is evicted. FIFO by injected_at.
    #
    # Today the cache key is the principal alone (one entry per
    # principal); the per-principal cap is structurally enforced
    # at 1, so the knob is forward-compat for a future multi-key
    # cache. The total cap is the meaningful control today.
    authz_cache_max_per_principal: int = 10
    authz_cache_max_total: int = 10000


@dataclass
class BannerConfig:
    """Pre-auth banner customization.

    ``template_path``: optional path to a text file whose contents are
    shown to users at SSH-Banner time. ``{key}`` tokens are substituted
    with strings from ``values``. Missing tokens are left literal so a
    typo in the template doesn't crash msshd.

    Per-user / per-session substitution (e.g. ``{user}``) is not
    supported today — the inner sshd is long-lived and shares its banner
    file across all sessions. See future-ideas.md §1 (per-connection
    inner sshd) for the path to per-user substitution.
    """
    template_path: str = ''
    values: dict[str, str] = field(default_factory=dict)


@dataclass
class MsshdConfig:
    mode: str = MODE_FALLBACK
    fallback: FallbackConfig = field(default_factory=FallbackConfig)
    listen: ListenConfig = field(default_factory=ListenConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    ca: CAConfig = field(default_factory=CAConfig)
    inner: InnerConfig = field(default_factory=InnerConfig)
    users: UsersConfig = field(default_factory=UsersConfig)
    logging_: LoggingConfig = field(default_factory=LoggingConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    banner: BannerConfig = field(default_factory=BannerConfig)

    @classmethod
    def load(cls, path: str | Path) -> 'MsshdConfig':
        # §14.3.1 YAML loader: defaults applied per the schema.
        with Path(path).open() as f:
            data = yaml.safe_load(f) or {}
        fb = data.get('fallback') or {}
        ls = data.get('listen') or {}
        tls = data.get('tls') or {}
        ca = data.get('ca') or {}
        inner = data.get('inner') or {}
        users = data.get('users') or {}
        log_ = data.get('logging') or {}
        perf = data.get('performance') or {}

        # port_range can come in as [lo, hi] list — coerce to tuple.
        port_range = inner.get('port_range') or [49152, 65535]
        if len(port_range) != 2:
            raise ValueError('inner.port_range must be [low, high]')

        return cls(
            mode=str(data.get('mode') or MODE_FALLBACK),
            fallback=FallbackConfig(
                host=str(fb.get('host') or '127.0.0.1'),
                port=int(fb.get('port') or 22),
            ),
            listen=ListenConfig(
                external_address=str(ls.get('external_address') or '0.0.0.0'),
                external_port=int(ls.get('external_port') or 2200),
                interfaces=list(ls.get('interfaces') or []),
            ),
            tls=TLSConfig(
                server_cert=str(tls.get('server_cert') or ''),
                server_key=str(tls.get('server_key') or ''),
                user_ca_pubkey=str(tls.get('user_ca_pubkey') or ''),
            ),
            ca=CAConfig(
                endpoints=list(ca.get('endpoints') or []),
                client_cert=str(ca.get('client_cert') or ''),
                client_key=str(ca.get('client_key') or ''),
                ca_pubkey=str(ca.get('ca_pubkey') or ''),
                timeout_seconds=float(ca.get('timeout_seconds') or 5.0),
                emergency_cert=str(ca.get('emergency_cert') or ''),
                crl_fetch_limit=int(ca.get('crl_fetch_limit') or 100),
                crl_strict_threshold=int(
                    ca.get('crl_strict_threshold')
                    if ca.get('crl_strict_threshold') is not None
                    else 50),
                auth_trust_root=str(ca.get('auth_trust_root') or ''),
                bypass_trust_root=str(ca.get('bypass_trust_root') or ''),
            ),
            inner=InnerConfig(
                sshd_binary=str(inner.get('sshd_binary') or '/usr/sbin/sshd'),
                port_range=(int(port_range[0]), int(port_range[1])),
                mode=str(inner.get('mode') or INNER_MODE_LONG_LIVED),
            ),
            users=UsersConfig(
                allowed=list(users.get('allowed') or []),
            ),
            logging_=LoggingConfig(
                level=str(log_.get('level') or 'info'),
                destination=str(log_.get('destination') or 'stderr'),
                audit_destination=str(
                    log_.get('audit_destination')
                    or 'file:/var/log/mssh/msshd-audit.jsonl'),
            ),
            performance=PerformanceConfig(
                inner_cipher_none=bool(perf.get('inner_cipher_none')),
                max_concurrent_sessions=int(
                    perf.get('max_concurrent_sessions') or 200),
                authz_cache_max_per_principal=int(
                    perf.get('authz_cache_max_per_principal')
                    if perf.get('authz_cache_max_per_principal') is not None
                    else 10),
                authz_cache_max_total=int(
                    perf.get('authz_cache_max_total')
                    if perf.get('authz_cache_max_total') is not None
                    else 10000),
            ),
            banner=BannerConfig(
                template_path=str((data.get('banner') or {})
                                  .get('template_path') or ''),
                values={str(k): str(v) for k, v in
                        ((data.get('banner') or {}).get('values') or {}).items()},
            ),
        )

    def validate(self) -> None:
        # §13.9.7 default-deny: missing mode-required fields raise.
        """Cross-field validation. Raises ValueError on any problem."""
        if self.mode not in VALID_MODES:
            raise ValueError(
                f'mode must be one of {VALID_MODES}, got {self.mode!r}')

        if self.inner.mode not in VALID_INNER_MODES:
            raise ValueError(
                f'inner.mode must be one of {VALID_INNER_MODES}, '
                f'got {self.inner.mode!r}')

        if not (1 <= self.listen.external_port <= 65535):
            raise ValueError(
                f'listen.external_port out of range: '
                f'{self.listen.external_port}')

        if self.mode == MODE_FALLBACK:
            if not (1 <= self.fallback.port <= 65535):
                raise ValueError(
                    f'fallback.port out of range: {self.fallback.port}')
            # In fallback mode we don't strictly need TLS / CA / inner
            # config — they're all unused. So no further checks.
            return

        if self.mode == MODE_GATED:
            # §1.4.2 / §5.3.3 gated mode: needs outer mTLS + CA call
            # like enforce, plus fallback's upstream target (the
            # operator's existing sshd) — but no inner sshd or local
            # user-CA. Falls through to the enforce-mode checks for
            # TLS + CA fields, then validates the fallback target.
            if not (1 <= self.fallback.port <= 65535):
                raise ValueError(
                    f'gated mode requires a valid fallback.port (upstream '
                    f'sshd target); got: {self.fallback.port}')
            # Fall through to the shared mTLS + CA validation below.

        # Enforce-mode validation
        for field_name in ('server_cert', 'server_key', 'user_ca_pubkey'):
            v = getattr(self.tls, field_name)
            if not v:
                raise ValueError(f'tls.{field_name} required in enforce mode')
            if not Path(v).exists():
                raise ValueError(
                    f'tls.{field_name}={v} does not exist')

        if not self.ca.endpoints:
            raise ValueError(
                'ca.endpoints requires at least one URL in enforce mode')
        for field_name in ('client_cert', 'client_key', 'ca_pubkey'):
            v = getattr(self.ca, field_name)
            if not v:
                raise ValueError(f'ca.{field_name} required in enforce mode')
            if not Path(v).exists():
                raise ValueError(f'ca.{field_name}={v} does not exist')

        # R-9 §13.9.7: at least one of auth_trust_root or the legacy
        # ca_pubkey must be present so the user-mTLS chain pins to a
        # specific intermediate (§2.3 load-bearing rule). The legacy
        # ca_pubkey check above already enforces the latter; this
        # block adds the new field requirement.
        # bypass_trust_root is checked separately when bypass
        # injection is invoked — see enforce_listener._handle_bypass_injection.
        if self.ca.auth_trust_root:
            if not Path(self.ca.auth_trust_root).exists():
                raise ValueError(
                    f'ca.auth_trust_root={self.ca.auth_trust_root} '
                    'does not exist')
        if self.ca.bypass_trust_root:
            if not Path(self.ca.bypass_trust_root).exists():
                raise ValueError(
                    f'ca.bypass_trust_root={self.ca.bypass_trust_root} '
                    'does not exist')

        # Inner sshd + users.allowed only apply in enforce mode
        # (gated proxies to operator's sshd; doesn't run an inner one).
        if self.mode == MODE_ENFORCE:
            lo, hi = self.inner.port_range
            if not (1024 <= lo < hi <= 65535):
                raise ValueError(
                    f'inner.port_range out of range: ({lo}, {hi})')

            if not self.users.allowed:
                raise ValueError(
                    "users.allowed is empty in enforce mode — set ['*'] "
                    'to allow any user, or list specific usernames')

    def check_permissions(self) -> None:
        # §13.9.7 fail-closed on lax key-file permissions.
        """Check on-disk permissions of cert/key files. Raises ValueError
        if a private key file is group- or world-readable."""
        if self.mode != MODE_ENFORCE:
            return
        for path_ in (self.tls.server_key, self.ca.client_key):
            if not path_:
                continue
            try:
                mode = os.stat(path_).st_mode
            except OSError:
                continue
            if mode & 0o077:
                raise ValueError(
                    f'private key {path_} has insecure permissions '
                    f'(mode={mode & 0o777:o}). Run: chmod 0600 {path_}')
