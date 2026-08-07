"""CA configuration loading.

Design: §14.3.2 (see design/mssh_design_v1.md) — ca-config.yaml schema
parsing. The default-deny posture for unset/uncovered actions is the
§13.9.7 default-deny invariant. §15.23 cert_kinds policy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


# §15.23 per-kind validity fallback baselines. Used when the operator's
# ca-config.yaml has no `cert_kinds:` section (v0.4.x configs); also the
# floor when the operator sets `cert_kinds:` without a per-kind entry
# for a given kind. Each kind's (default, max) pair mirrors v0.4.x
# behavior — see §15.23 for the rationale per kind.
_FALLBACK_CERT_DEFAULT_VALIDITY = {
    'authz-user':    1,
    'authz-bypass':  90,
    'server-tls':    365,
    'admin-mtls':    365,
    'client-mtls':   365,
    'https-user':    90,
    'openvpn':       90,
    'code-sign':     365,
    'external-use':  7305,   # 20yr; §15.19
    # Legacy aliases still accepted by the cert-mint admin handler.
    'tls-server':    90,
}
_FALLBACK_CERT_MAX_VALIDITY = {
    'authz-user':    7,
    'authz-bypass':  3650,
    'server-tls':    825,
    'admin-mtls':    825,
    'client-mtls':   825,
    'https-user':    825,
    'openvpn':       365,
    'code-sign':     1825,
    'external-use':  9125,   # 25yr; §15.19
    # Legacy aliases still accepted by the cert-mint admin handler.
    'tls-server':    825,
}
_FALLBACK_BASE_DEFAULT = 90
_FALLBACK_BASE_MAX = 825


# §15.21 OID arc reservation. Operators submitting custom OIDs on cert
# mint requests must reference OIDs declared in `custom_oids:` AND not
# in the reserved range. The CA refuses to start if any allowlisted
# entry overlaps the reserved range (§13.9.7 default-deny).
#
# RESERVED_OID_RANGES is a tuple of (prefix, low_inclusive, high_inclusive,
# label) tuples — an OID like `<prefix>.<n>.…` is reserved when n is in
# [low, high]. The five-arc form catches all current and future mssh
# sub-arcs under `.1.*` through `.4999.*`.
RESERVED_OID_RANGES = (
    ('1.3.6.1.4.1.55555', 1, 4999, 'mssh-reserved'),
)

# OPERATOR_SUB_ARC is the mssh-assigned sub-arc available for operator
# custom OIDs without requiring an IANA PEN registration. OIDs whose
# fifth arc is in [5000, 65535] are guaranteed not to collide with
# mssh-internal OIDs.
OPERATOR_SUB_ARC = ('1.3.6.1.4.1.55555', 5000, 65535)


_CUSTOM_OID_ENCODINGS = ('utf8', 'octet', 'integer', 'null', 'printable')


def _check_oid_against_reserved(oid: str) -> str | None:
    """Return None if the OID is allowed in the operator allowlist;
    return a human-readable error message otherwise. The check matches
    any OID whose dotted form has the reserved prefix followed by a
    number in the reserved range.

    Design: §15.21.
    """
    parts = oid.split('.')
    if len(parts) < 6:
        return None
    for prefix, low, high, label in RESERVED_OID_RANGES:
        prefix_parts = prefix.split('.')
        if parts[: len(prefix_parts)] != prefix_parts:
            continue
        try:
            sub = int(parts[len(prefix_parts)])
        except (ValueError, IndexError):
            continue
        if low <= sub <= high:
            sub_lo, sub_hi, _ = OPERATOR_SUB_ARC[1], OPERATOR_SUB_ARC[2], None
            return (
                f'OID {oid} is in the {label} range '
                f'({prefix}.{low}-{high}.*); use {prefix}.{sub_lo}-{sub_hi}.* '
                f'(operator sub-arc) or your own IANA PEN instead'
            )
    return None


@dataclass
class CustomOIDEntry:
    """One operator-allowlisted X.509 extension OID (§15.21).

    Operators reference an entry by either ``oid`` (dotted form) or
    ``name`` (the human-friendly alias) on cert mint requests.
    """
    oid: str
    name: str
    encoding: str                  # one of _CUSTOM_OID_ENCODINGS
    max_length: int | None = None  # bytes; None = unbounded
    description: str = ''
    critical: bool = False         # default non-critical


@dataclass
class CustomOIDAllowlist:
    """§15.21 strict allowlist of operator-defined OIDs.

    The CA validates each operator-submitted ``custom_oids: [...]`` list
    on cert mint against this allowlist. Entries not on the list are
    rejected with a clear error naming the offending OID.

    A CA started with no `custom_oids:` section in ca-config.yaml gets
    an empty allowlist — any mint request that supplies a custom OID
    is rejected (§13.9.7 default-deny).
    """
    entries: dict[str, CustomOIDEntry] = field(default_factory=dict)
    # name -> oid map for `--custom-oid name=value` reference form.
    by_name: dict[str, str] = field(default_factory=dict)

    def is_allowed(self, oid: str) -> bool:
        return oid in self.entries

    def lookup(self, oid_or_name: str) -> CustomOIDEntry | None:
        if oid_or_name in self.entries:
            return self.entries[oid_or_name]
        oid = self.by_name.get(oid_or_name)
        if oid:
            return self.entries.get(oid)
        return None

    def validate_self(self) -> None:
        """Raises ValueError if any allowlisted entry overlaps the
        mssh-reserved arc or uses an unknown encoding.

        Called from CAConfig.validate() at CA startup (§13.9.7
        default-deny: refuse to start with an obviously misconfigured
        allowlist).

        Design: §15.21.
        """
        for oid, entry in self.entries.items():
            err = _check_oid_against_reserved(oid)
            if err:
                raise ValueError(
                    f'ca-config.yaml custom_oids: {err} (§15.21)')
            if entry.encoding not in _CUSTOM_OID_ENCODINGS:
                raise ValueError(
                    f'ca-config.yaml custom_oids: entry for {oid} has '
                    f'unknown encoding {entry.encoding!r}; '
                    f'must be one of {_CUSTOM_OID_ENCODINGS} (§15.21)')
            if entry.max_length is not None and entry.max_length < 1:
                raise ValueError(
                    f'ca-config.yaml custom_oids: entry for {oid} has '
                    f'non-positive max_length={entry.max_length} (§15.21)')

    @classmethod
    def from_yaml_section(cls, section: list | None) -> 'CustomOIDAllowlist':
        if not section:
            return cls()
        entries: dict[str, CustomOIDEntry] = {}
        by_name: dict[str, str] = {}
        for raw in section:
            if not isinstance(raw, dict):
                continue
            oid = str(raw.get('oid') or '').strip()
            if not oid:
                continue
            name = str(raw.get('name') or '').strip()
            encoding = str(raw.get('encoding') or 'utf8').strip()
            max_length = raw.get('max_length')
            critical = bool(raw.get('critical', False))
            entry = CustomOIDEntry(
                oid=oid, name=name, encoding=encoding,
                max_length=int(max_length) if max_length is not None else None,
                description=str(raw.get('description') or ''),
                critical=critical,
            )
            entries[oid] = entry
            if name:
                by_name[name] = oid
        return cls(entries=entries, by_name=by_name)


@dataclass
class CertKindsPolicy:
    """§15.23 per-kind validity policy parsed from ca-config.yaml.

    Operators set per-kind defaults + caps under the ``cert_kinds:``
    section. Each kind looked up via ``default_for()`` / ``cap_for()``
    falls through in this order:

      1. ``per_kind[<kind>][default_validity_days|max_validity_days]``
      2. ``default_validity_days`` / ``default_max_validity_days``
         (the operator's section-level defaults)
      3. ``_FALLBACK_CERT_DEFAULT_VALIDITY[<kind>]`` /
         ``_FALLBACK_CERT_MAX_VALIDITY[<kind>]`` (built-in mssh
         baseline; matches v0.4.x behavior)
      4. ``_FALLBACK_BASE_DEFAULT`` / ``_FALLBACK_BASE_MAX``
         (90d / 825d ultimate floor)

    Design: §15.23.
    """
    default_validity_days: int = _FALLBACK_BASE_DEFAULT
    default_max_validity_days: int = _FALLBACK_BASE_MAX
    per_kind: dict[str, dict[str, int]] = field(default_factory=dict)

    def default_for(self, kind: str) -> int:
        kpol = self.per_kind.get(kind) or {}
        if 'default_validity_days' in kpol:
            return int(kpol['default_validity_days'])
        if kind in _FALLBACK_CERT_DEFAULT_VALIDITY:
            return _FALLBACK_CERT_DEFAULT_VALIDITY[kind]
        return self.default_validity_days

    def cap_for(self, kind: str) -> int:
        kpol = self.per_kind.get(kind) or {}
        if 'max_validity_days' in kpol:
            return int(kpol['max_validity_days'])
        if kind in _FALLBACK_CERT_MAX_VALIDITY:
            return _FALLBACK_CERT_MAX_VALIDITY[kind]
        return self.default_max_validity_days

    @classmethod
    def from_yaml_section(cls, section: dict | None) -> 'CertKindsPolicy':
        # When the YAML has no `cert_kinds:` section at all, the
        # operator gets v0.4.x behavior byte-identical: the policy
        # is constructed with section-level fallbacks, and every
        # `default_for(kind)` / `cap_for(kind)` lookup goes through
        # the built-in `_FALLBACK_*` dicts.
        if not section:
            return cls()
        per_kind_raw = section.get('per_kind') or {}
        per_kind: dict[str, dict[str, int]] = {}
        for kind, kpol in per_kind_raw.items():
            if not isinstance(kpol, dict):
                continue
            entry: dict[str, int] = {}
            if 'default_validity_days' in kpol:
                entry['default_validity_days'] = int(kpol['default_validity_days'])
            if 'max_validity_days' in kpol:
                entry['max_validity_days'] = int(kpol['max_validity_days'])
            per_kind[str(kind)] = entry
        return cls(
            default_validity_days=int(
                section.get('default_validity_days') or _FALLBACK_BASE_DEFAULT),
            default_max_validity_days=int(
                section.get('default_max_validity_days') or _FALLBACK_BASE_MAX),
            per_kind=per_kind,
        )


# R-8 supplement / R-10 §14.3.6 — default MCP capability allow-list.
# Lives here (not in admin.py) so the operator's `mcp.capability_allow_list`
# in ca-config.yaml can override it. When ca-config has no `mcp:` block,
# this default is what `admin.py::_check` consults — preserving v0.4.0
# behavior byte-identical. Strict subset of mssh-admin; all
# bypass/mutating/destructive actions are excluded per §12.2.
DEFAULT_MCP_ALLOWED_ACTIONS: frozenset[str] = frozenset({
    'server.list',
    'user.list',
    'admin.list',
    'audit.read',
    'crl.read',
    'intermediate.list',
    'intermediate.external.list',
    'external_tool.list',
    'policy.read',
    'template.list',
    'template.show',
})


@dataclass
class MCPPolicy:
    """§12.4.3 / R-10 §14.3.6 / R-8 supplement — operator-tunable
    MCP-origin call gating, parsed from ``ca-config.yaml::mcp:``.

    ``enabled`` is informational at the CA edge (the CA refuses MCP
    calls outside ``capability_allow_list`` regardless); the MCP server
    itself reads it. ``capability_allow_list`` overrides the built-in
    ``DEFAULT_MCP_ALLOWED_ACTIONS`` set; when None, the default applies
    (v0.4.0 behavior preserved).
    """
    enabled: bool = False
    capability_allow_list: frozenset[str] | None = None

    @classmethod
    def from_yaml_section(cls, section: dict | None) -> 'MCPPolicy':
        if not section:
            return cls()
        actions = section.get('capability_allow_list')
        allow: frozenset[str] | None
        if actions is None:
            allow = None
        else:
            allow = frozenset(str(a) for a in actions)
        return cls(
            enabled=bool(section.get('enabled', False)),
            capability_allow_list=allow,
        )

    def effective_allow_list(self) -> frozenset[str]:
        """Returns the active allow-list — operator's override if set,
        otherwise the built-in default. Always non-empty."""
        return self.capability_allow_list \
               if self.capability_allow_list is not None \
               else DEFAULT_MCP_ALLOWED_ACTIONS


@dataclass
class AuditRotationPolicy:
    """R-8 supplement — operator-tunable audit log rotation knobs.

    Parsed from ``ca-config.yaml::audit.rotation:``. v0.5.1 ships the
    plumbing; enforcement (size-based + count-based file rolls) is the
    next sub-commit. Operators can populate the YAML now without
    breaking anything; the audit writer ignores the fields until the
    enforcement lands.
    """
    max_bytes: int = 0          # 0 = no size cap
    keep_files: int = 0         # 0 = no retention cap

    @classmethod
    def from_yaml_section(cls, section: dict | None) -> 'AuditRotationPolicy':
        if not section:
            return cls()
        return cls(
            max_bytes=int(section.get('max_bytes') or 0),
            keep_files=int(section.get('keep_files') or 0),
        )


@dataclass
class AuditIntegrityPolicy:
    """R-8 supplement — operator-tunable audit hash-chain knobs.

    Parsed from ``ca-config.yaml::audit.integrity:``. The chain is
    always on in v0.5.x (§13.9.6 ships unconditional); these knobs
    expose the operator-facing tuning surface. ``signed_checkpoints``
    is reserved for the v0.6+ signed-checkpoint extension to the
    hash chain. ``checkpoint_interval_seconds`` controls how often
    checkpoint records get written when that feature lands.
    """
    signed_checkpoints: bool = False
    checkpoint_interval_seconds: int = 0

    @classmethod
    def from_yaml_section(cls, section: dict | None) -> 'AuditIntegrityPolicy':
        if not section:
            return cls()
        return cls(
            signed_checkpoints=bool(section.get('signed_checkpoints', False)),
            checkpoint_interval_seconds=int(
                section.get('checkpoint_interval_seconds') or 0),
        )


@dataclass
class RateLimitsPolicy:
    """R-8 supplement — operator-tunable per-endpoint rate limits.

    Parsed from ``ca-config.yaml::ratelimits:``. Each entry maps an
    action / endpoint name to ``{calls_per_minute: int}``. v0.5.1
    ships the plumbing; enforcement is a v0.6+ follow-up at the
    Flask route layer.

    Shape::

        ratelimits:
          authorize:        {calls_per_minute: 600}
          intermediate.rotate: {calls_per_minute: 5}
    """
    per_endpoint: dict[str, dict[str, int]] = field(default_factory=dict)

    @classmethod
    def from_yaml_section(cls, section: dict | None) -> 'RateLimitsPolicy':
        if not section:
            return cls()
        out: dict[str, dict[str, int]] = {}
        for endpoint, raw in section.items():
            if not isinstance(raw, dict):
                continue
            entry: dict[str, int] = {}
            if 'calls_per_minute' in raw:
                entry['calls_per_minute'] = int(raw['calls_per_minute'])
            if entry:
                out[str(endpoint)] = entry
        return cls(per_endpoint=out)


@dataclass
class TemplatesPolicy:
    """R-8 supplement — operator-tunable templates directory.

    Parsed from ``ca-config.yaml::templates::builtin_dir``. When set,
    overrides the location of built-in template definitions (default:
    `<package>/templates/builtin/`). Empty string = use the package
    default — preserves v0.4.x behavior.
    """
    builtin_dir: str = ''

    @classmethod
    def from_yaml_section(cls, section: dict | None) -> 'TemplatesPolicy':
        if not section:
            return cls()
        return cls(builtin_dir=str(section.get('builtin_dir') or ''))


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

    # mssh-passkey broker config. When set, mssh-ca acts as a
    # WebAuthn RP using the broker for both admin-2FA and
    # external-tool flows. Unset → passkey endpoints respond 503.
    passkey_broker_url: str = ''
    passkey_client_cert: str = ''
    passkey_client_key: str = ''
    passkey_ca_cert: str = ''
    passkey_callback_url: str = ''
    passkey_rp_id: str = ''        # WebAuthn RP ID — usually the broker's public hostname
    passkey_rp_name: str = ''
    passkey_expected_origin: str = ''  # https://<rp_id>
    passkey_aaguid_allowlist_path: str = ''

    # Admin-2FA gating. Listed admin actions (e.g. 'cert.revoke',
    # 'admin.add') require the calling admin to satisfy a passkey
    # ceremony before the operation proceeds. Empty list (default) =
    # nothing gated — current behavior. Requires the passkey broker
    # to be configured; if listed when the broker is unset, requests
    # to gated actions respond 503. See design/admin-2fa.md.
    admin_2fa_protected_actions: list[str] = field(default_factory=list)
    admin_2fa_within_seconds: int = 300

    # §15.23 per-kind validity policy. Empty CertKindsPolicy() means
    # built-in v0.4.x baseline applies to every kind — operators can
    # opt into per-kind tuning by setting `cert_kinds:` in ca-config.yaml.
    cert_kinds: CertKindsPolicy = field(default_factory=CertKindsPolicy)

    # §15.21 strict allowlist of operator-defined extension OIDs.
    # Empty allowlist (default) = no operator OIDs accepted.
    custom_oids: CustomOIDAllowlist = field(default_factory=CustomOIDAllowlist)

    # R-10 §14.3.6 / R-8 supplement — MCP gating policy (capability
    # allow-list + enabled flag) from `ca-config.yaml::mcp:`. When
    # the section is absent, the built-in DEFAULT_MCP_ALLOWED_ACTIONS
    # applies — v0.4.0 behavior preserved byte-identical.
    mcp: MCPPolicy = field(default_factory=MCPPolicy)

    # R-8 supplement — audit log rotation + integrity policy. Plumbing
    # only in v0.5.1; enforcement (size-based rolls, signed checkpoints)
    # lands incrementally. Operators can populate the YAML without
    # breaking anything.
    audit_rotation: AuditRotationPolicy = field(
        default_factory=AuditRotationPolicy)
    audit_integrity: AuditIntegrityPolicy = field(
        default_factory=AuditIntegrityPolicy)

    # R-8 supplement — per-endpoint rate-limit caps. Plumbing only;
    # Flask-route enforcement is a v0.6+ follow-up.
    ratelimits: RateLimitsPolicy = field(default_factory=RateLimitsPolicy)

    # R-8 supplement — operator-tunable templates directory.
    templates: TemplatesPolicy = field(default_factory=TemplatesPolicy)

    @classmethod
    def load(cls, path: str | Path) -> 'CAConfig':
        # §14.3.2 ca-config.yaml parse; unset fields fall through to
        # safe defaults per §13.9.7 default-deny.
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
            passkey_broker_url=str(
                (data.get('passkey') or {}).get('broker_url') or ''),
            passkey_client_cert=str(
                (data.get('passkey') or {}).get('client_cert') or ''),
            passkey_client_key=str(
                (data.get('passkey') or {}).get('client_key') or ''),
            passkey_ca_cert=str(
                (data.get('passkey') or {}).get('ca_cert') or ''),
            passkey_callback_url=str(
                (data.get('passkey') or {}).get('callback_url') or ''),
            passkey_rp_id=str(
                (data.get('passkey') or {}).get('rp_id') or ''),
            passkey_rp_name=str(
                (data.get('passkey') or {}).get('rp_name') or 'mssh-ca'),
            passkey_expected_origin=str(
                (data.get('passkey') or {}).get('expected_origin') or ''),
            passkey_aaguid_allowlist_path=str(
                (data.get('passkey') or {}).get('aaguid_allowlist_path') or ''),
            admin_2fa_protected_actions=list(
                (data.get('admin_2fa') or {}).get('protected_actions') or []),
            admin_2fa_within_seconds=int(
                (data.get('admin_2fa') or {}).get('within_seconds') or 300),
            cert_kinds=CertKindsPolicy.from_yaml_section(
                data.get('cert_kinds')),
            custom_oids=CustomOIDAllowlist.from_yaml_section(
                data.get('custom_oids')),
            # R-10 §14.3.6 / R-8 supplement.
            mcp=MCPPolicy.from_yaml_section(data.get('mcp')),
            audit_rotation=AuditRotationPolicy.from_yaml_section(
                (data.get('audit') or {}).get('rotation')),
            audit_integrity=AuditIntegrityPolicy.from_yaml_section(
                (data.get('audit') or {}).get('integrity')),
            ratelimits=RateLimitsPolicy.from_yaml_section(
                data.get('ratelimits')),
            templates=TemplatesPolicy.from_yaml_section(
                data.get('templates')),
        )
        return c

    def validate(self) -> None:
        """Cross-field validation. Raises ``ValueError`` on any problem.

        R-9 §13.9.7 default-deny: security-critical paths must be
        present and exist. Missing fields → refuse-to-start with an
        explicit error message.

        Design: §13.9.7.
        """
        # §13.9.7 default-deny enforcement (R-9).
        from pathlib import Path as _Path

        required_paths = {
            'signing_key': self.signing_key,
            'signing_cert': self.signing_cert,
            'tls_cert': self.tls_cert,
            'tls_key': self.tls_key,
            'client_ca_cert': self.client_ca_cert,
        }
        for name, value in required_paths.items():
            if not value:
                raise ValueError(
                    f'ca-config.yaml: {name} is required '
                    f'(§13.9.7 default-deny)')
            if not _Path(value).exists():
                raise ValueError(
                    f'ca-config.yaml: {name}={value} does not exist '
                    f'(§13.9.7 default-deny)')

        if not self.identity_trust_roots:
            raise ValueError(
                'ca-config.yaml: identity_trust_roots is empty '
                '(§13.9.7 default-deny; cannot validate any client '
                'identity without at least one trust root)')

        if not (1 <= self.listen_port <= 65535):
            raise ValueError(
                f'ca-config.yaml: listen port out of range: '
                f'{self.listen_port}')

        # §15.21 — refuse to start if the operator allowlist contains
        # OIDs in the mssh-reserved arc or an unknown encoding.
        self.custom_oids.validate_self()
