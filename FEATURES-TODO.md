# mssh — FEATURES-TODO

Companion to [design/mssh_design_v1.md](design/mssh_design_v1.md) §0.4.
Every row carries a §-ref into the design. New rows added only when
the design admits a new §-reference.

Columns: `ref` (§ from design), `title`, `priority` (P1–P9), `status`
(🟡/🚧), `branch` (working branch, blank if none), `notes`.

---

## v1 release plan (6 phases)

**Guiding rule:** §14 (interfaces) has the highest cost-to-change after
v1 ships. Anything that touches §14 lands in Phases 1–2 — before
test-writing begins — so the test surface can't be invalidated by a
later contract change.

Estimated total: **40–55 working days** (8–11 weeks at 1 person, 4–6
weeks at 2). Updated 2026-05-22 after Phase-1 audit surfaced larger drift
than originally scoped. Phase 1 grew from 5–7 days → 12–15 days; other
phases unchanged.

### Phase 1 — Audit + reconcile design vs. code drift (12–15 days, expanded)

**Status:** audits complete (2026-05-22). Drift was larger than expected:
the design I drafted is substantially aspirational vs. shipped code.
Reconciliation strategy is **Path Z (hybrid)** — Code→Design where the
design's interface is meaningfully better; Design→Code where the
design is just renamed differently; DROP where the design over-spec'd
unbuilt features.

Audit findings logged in §17.6 discrepancy block of the design.

#### Reconciliation commit plan (10 commits, each ships tests-green)

**R-1 — §14.5 + §14.8 small cert-profile fixes (~50 LOC + 10 tests)**
- Rewrite §14.5 OID table with code's actual arc names (`.1=OID_SOURCE_BIND` … `.7=OID_2FA_EVIDENCE`) — D→C
- Document `.6=OID_MAX_SESSION`, `.7=OID_2FA_EVIDENCE` (currently undocumented) — D→C
- **Drop** OIDs `.9–.12` from §14.5 (`USER_NAME`, `ADMIN_ROLE`, `INNER_SSHD_CONFIG_SIG`, `TOOL_ID`) — over-spec; add only when implementations land
- Fix `OID_CA_BYPASS` encoding from UTF8String `'true'` to ASN.1 NULL in code — C→D ~5 LOC
- Flip `OID_FORCE_COMMAND` + `OID_ENVIRONMENT` to `critical=True` — C→D ~2 LOC (security claim)
- Document `BasicConstraints(ca=False)` in §14.8 (code adds it; design omits) — D→C

**R-2 — §14.8 authz/bypass cert missing extensions (~50 LOC + 5 tests)**
- Add to authz + bypass cert mint: `CRLDistributionPoints` (required for §13.3 CRL story), `KeyUsage(digitalSignature, critical)`, `ExtendedKeyUsage(id-kp-clientAuth, critical)`, `SubjectAlternativeName(rfc822Name)`, `SubjectKeyIdentifier`
- Enforce `bypass-mint` intermediate when `ca_bypass=True` (currently any intermediate can sign a bypass cert)
- Verify mTLS server cert adds `clientAuth` EKU (msshd needs it for outbound to CA) — C→D ~5 LOC

**R-3 — §14.1 response envelope normalization (~70 LOC + 8 tests)**
- Rewrite CA responses to use design envelope: `result` not `status`, add `request_id` + `ca_server_id` + `issued_at` + `protocol_version` on every response, wrap authorize-granted in `credentials: {...}`, rename `reason` → `denied_reason` on denies
- Update shim consumers in msshd + mssh-admin to read the new shape
- C→D throughout — the envelope is the v1 contract; align code now before any 3rd-party clients exist

**R-4 — §14.1 admin path catalog (~30 LOC + 5 tests)**
- Add `DELETE /v1/external/passkey/ceremony/<id>` (cancel route) — design has it, code missing — C→D
- Document existing routes in §14.1.2: `POST /v1/admin/cert/mint`, `GET /v1/admin/intermediate/list-external`, `POST/GET/DELETE /v1/admin/wireguard/server[/<name>]` — D→C
- Rewrite §14.1.2 WireGuard paths to code's `peer` (POST/GET/DELETE) shape — D→C
- Rewrite §14.1.2 passkey paths to code's `enroll-begin` / `callback` / `<admin_name>/<credential_id>` shape — D→C
- Broaden `intermediate.list` RBAC in code to include `server-admin` + `user-admin` — C→D
- Normalize action names: pick underscore (code's spelling) across audit log + design — C→D
- Add `intermediate.rotate` + `intermediate.external.mint` to §14.1.2's (2FA) list (code already gates them) — D→C

**R-5 — §3.6 + §15.4 broker per-ceremony binding (~10 LOC + 4 tests)**
- Add `ceremony.created_by == X-Client-CN` check in `views_broker.py::get_ceremony` + `delete_ceremony` — C→D
- 404 (not 403) for cross-tool access to keep ceremony existence opaque
- New tests: tool-A cannot read/cancel tool-B's ceremonies

**R-6 — §14.6 audit.jsonl key normalization (~50 LOC + 5 tests)**
- Rewrite every `_audit*()` call site to use design's keys: `ts`, `request_id`, `actor`, `action`, `target`, `result`, `detail`, `origin`
- Today's writes use `timestamp`/`type`/`decision`/`reason` (authorize) and `timestamp`/`type`/`action`/`admin`/`target`/`result` (admin)
- C→D — audit format is operator-facing forensic record; needs to match design
- This commit also adds the `origin` field as an empty default (the §12.4.2 wire-in lands in Phase 2)

**R-7 — §14.6 + §14.4 on-disk state shape (~80 LOC + 8 tests)**
- `authz_cache.json`: keep `cert_der_b64` (faster than re-encoding to PEM); document in §14.6 — D→C
- Add `not_before` + `last_used_at` to authz_cache entries; track `last_used_at` on get — C→D
- Document the extra `inner_sshd_config` + `protocol_version` per-entry fields + legacy `last_crl_seq` scalar — D→C
- `ceremonies.sqlite`: rewrite §14.6 + §8.3.1 to match code's actual columns (`ceremony_type`, `options_json`, `created_by`, etc.) — D→C
- Allowed-value set for `outcome`: design says `pending|approved|denied|expired`; code uses `approved|denied|expired|cancelled` (no `pending`); rewrite §14.6 — D→C
- `enrollment.yaml`: add `intermediates:` top-level key to persistence (~20 LOC code) — C→D
- Rewrite §14.4 `users[].keys[]` + `policies[]` + `external_tools[]` shapes to match `KeyBinding` / `Policy` / `ExternalTool` dataclasses — D→C
- `passkey_credentials[]`: keep code's extra fields (`transports`, `label`, `enrolled_by`, `revoked_at`); document in §14.4 — D→C
- `policies[].require_2fa`: code uses `'none'` string default; switch to `null` to match design — C→D ~5 LOC

**R-8 — §14.3.1 + §14.3.2 + §14.3.4 schema rewrites (~150 LOC + 12 tests)**
- §14.3.1 msshd.yaml: rewrite design to match code's actual loader — D→C:
  - `outer_mtls:` block → split as `listen:` + `tls:` (code's shape)
  - Drop `state_dir`/`log_dir` from design (code uses `logging.audit_destination`)
  - Document `users.allowed` (REQUIRED in enforce mode), `logging.{level,destination,audit_destination}`, `performance.*`, `banner.*`
  - `inner:` block: rewrite to code's actual fields (`sshd_binary`, `port_range`, `mode: long-lived|per-connection`); document hyphen separator
- §14.3.2 ca-config.yaml: rewrite design to flat shape (code's actual layout) — D→C:
  - Top-level `signing_key`, `signing_cert`, `tls_cert`, `tls_key`, `client_ca_cert`, `identity_trust_roots`
  - `passkey:` block with code's actual field names
  - Document `cert_generation.*`, `wireguard.path`
  - **Land NEW parsing** in this commit: `mcp:` block (enabled + capability_allow_list), `audit.rotation`, `audit.integrity`, `ratelimits.*`, `templates.builtin_dir` — C→D for these specifically; design promised, code never read
- §14.3.4 mssh-passkey: rewrite design to use code's `listen:` + `database:` blocks — D→C; parse missing `callback.retry_schedule_seconds`, `callback.retention_window_seconds`, `sweeper.tick_seconds` (~25 LOC) — C→D

**R-9 — §13.9.7 default-deny verification (~30 LOC + 12 tests)**
- msshd `validate()`: add `auth_trust_root` + `bypass_trust_root` to required-in-enforce-mode list — C→D
- CA `CAConfig.load`: add a `validate()` method that fail-closes on missing `signing_key`/`signing_cert`/`tls_cert`/`tls_key`/`client_ca_cert`/`identity_trust_roots` — C→D ~30 LOC
- mssh-passkey: fail-closed on missing TLS material under `listen.broker_mtls`/`listen.public_https` — C→D
- Parametrized test: every required field absent → refuse-to-start with explicit error message
- This is the §13.9.7 hardening member from Phase 3, pulled earlier because schemas are settling

**R-10 — §14.3.3 + §14.3.5 + §14.3.6 (client + admin-web + mcp configs) (~80 LOC + 8 tests)**
- §14.3.3 mssh client config: **pick format**. Recommendation: keep code's flat `key=value` for v1 (YAML is post-v1) — D→C:
  - Drop `endpoints:` list from design (client supports single endpoint per config in v1)
  - Drop `host_overrides:` map
  - Drop `framing: true` (auto-negotiation only)
  - Rename `trust.pem` → `ca.pem` in design OR add `trust.pem` alias in code (recommend C→D: keep `ca.pem`, document it; rename in §14.3.3)
  - Env var: keep `MSSH_CA` in code, add `MSSH_TRUST` alias — C→D ~5 LOC
- §14.3.5 mssh-admin-web config: **implement YAML loader** to match design (~50 LOC) — C→D
  - Add `flask.secret_key_file` parsing
  - Add `apache_integration.trusted_client_cn_header` parsing + use in route handlers
- §14.3.6 mcp config: **architectural fix** — move MCP config from `~/.mssh-admin/config` to `ca-config.yaml::mcp:` block (~30 LOC) — C→D
  - Parse `capability_allow_list` from CA config (currently hardcoded in `tools.TOOL_REGISTRY`)
  - Add CA-side enforcement: refuse non-allowed actions when `Origin: mcp` header present (~20 LOC) — this is §12.4.3 CA-side defense-in-depth
  - Wires in §13.9.2 hardening member at the CA edge

#### Design-only additions (no code; happen during R-1..R-10)

Insert into design while doing R-1 etc.:
- **§15.12** — PGP user key management (status 🚧, scheduled Phase 2)
- **§15.13** — OpenVPN server-side registration (status 🚧, Phase 2)
- **§15.14** — WireGuard server-side registration (status 🚧 — actually `wireguard/server` exists in code per R-4; promote to ✅ once §14.1.2 + §14.2.2 updated)
- **§15.15** — Webhook / event subscription (status 🚧 v2; mention in §18)
- **§15.16** — HSM / external Root key custody (status 🚧 v3)
- **§17.6 update** — replace "discrepancies surfaced by initial verification pass" block with reconciliation outcome log (one line per R-* commit)

**Exit:** every §14 section has a passing static-equivalence test in
`test_design_xref.py`. Design and code agree at the wire/disk surface.
§0 status still "FROZEN BASELINE — pending verification" because §1–§16
features aren't all ✅ yet (Phase 2 still ahead).

**Phase 1 totals:** ~600 LOC + ~80 tests. **12–15 working days.**

### Phase 2 — Interface-shaping ship blockers (15–20 days)

Goal: land every 🚧 that *adds* to §14, so the contract is finalized
before test-writing.

**TIER 2A — base infrastructure changes (parallel, no deps)**
- §5.3.3 gated mode (~400 LOC + 20 tests) — touches §14.3.1, §13.8, §15.7
- §13.9.6 audit log tamper-resistance (~300 LOC + 15 tests) — touches §14.6, §14.2.2, §14.3.2
- §12.4.2 + §12.4.3 MCP hardening (~200 LOC + 13 tests) — touches §14.6, §14.1
- §8.3.7 broker hardening v2 (~400 LOC + 20 tests) — touches §14.3.2 + §3.6 reconciliation

**TIER 2B — PKI surface completion (after 2A)**
- §7.3.4 `mssh-admin pki` subcommand (~120 LOC + 8 tests) — promotes `scripts/mint-user-pki.py`
- §15.12 PGP user key management (~400 LOC + 15 tests) — new §; composes with §7.3.4 + §13.7
- §15.13 OpenVPN server-side registration (~80 LOC + 4 tests) — small extension to §13.7
- §15.14 WireGuard server-side registration (~80 LOC + 4 tests) — symmetric

**TIER 2C — UX additions (no new contracts, depend on 2A/2B)**
- §6.3.5 mssh `-L` (~150 LOC + 8 tests) — touches §14.2.1
- §11.3.3 admin-web mutating CRUD + api_user_pki (~600 LOC + 25 tests) — depends on §7.3.4
- §11.3.5 admin-web tunneled localhost (~80 LOC + 5 tests) — depends on §6.3.5

**Exit:** §14 is bit-for-bit final. §0 status moves from "FROZEN
BASELINE — pending verification" → "FROZEN BASELINE."

### Phase 3 — Hardening sweep (3–4 days)

No new interfaces; broaden the verification:
- §13.9.7 default-deny on missing config — parametrized matrix
- §13.9.8 cert OID + marker enforcement — cross-validator matrix

**Exit:** every §13.9 hardening member has both implementation and
tests.

### Phase 4 — Verification-pass tooling (2–3 days)

Build `python/tests/test_design_xref.py`:
- Walk code, every `.py` must have `Design: §X.Y`. Fail otherwise.
- Walk tests, every test file must have `Tests: §X.Y`. Fail otherwise.
- Every § in §1–§16 with ✅ status must have ≥1 code-mapping AND
  ≥1 test-mapping.
- Every `§X.Y.Z` referenced in code/tests must resolve to an actual
  section.
- HARD ERROR: §14 endpoints / CLI flags / OIDs in code not in
  design (or vice versa).
- Regenerates §17.6 / §17.7 / §17.8 matrices in-place.

**Exit:** verification gate is now automated; runs on every commit.

### Phase 5 — Test gap closure (7–10 days)

Drain TESTS-TODO.md. Safe now — §14 is frozen, so tests cannot be
invalidated by a contract change.

Priorities:
1. P1 meta-tests (§17 tooling) — done in Phase 4
2. P2 hardening + ship-blocker tests
3. P3 implemented-but-untested §s
4. P4 polish (formatters, debug_sshd direct, apache integration, systemd units)

### Phase 6 — Final FREEZE (1 day)

1. `test_design_xref.py` green.
2. Every § in §1–§16 is ✅. No 🟡 / 🚧 in those chapters.
3. `mssh-admin audit verify` clean on fresh adhoc lab.
4. LXC suite green on Ubuntu 22.04 + Fedora 41.
5. Kurt sign-off.
6. §0 status → "FROZEN BASELINE" (drop "pending verification").
7. Tag v1.0.0.

After this: any change to §1–§16 requires a new design revision
document. No edits in place.

### §15 3rd-party integration — v1/v2/drop classification

| § | Title | Status | Decision |
|---|-------|--------|----------|
| §15.1 | Extension model taxonomy | ✅ | v1 (doc-only) |
| §15.2 | CA as step-ca parallel (TLS/OpenVPN/WG) | ✅ except PGP | v1 (PGP in §15.12) |
| §15.3 | External Intermediate CA tier | ✅ | v1 |
| §15.4 | Replaceable mssh-passkey broker | ✅ | v1 (per-ceremony binding reconciles in Phase 1) |
| §15.5 | Passkey RP for external tools | ✅ | v1 |
| §15.6 | OpenSSH AKC integration | ✅ | v1 |
| §15.7 | Operator's existing sshd reuse | ✅ | v1 (depends on §5.3.3 gated mode) |
| §15.8 | apache2 TLS terminator | ✅ | v1 (LXC test gap) |
| §15.9 | systemd integration | ✅ | v1 |
| §15.10 | LXC / pyinfra integration for testing | 🟡 | **v2** (Phase A in progress; not a v1 release gate) |
| §15.11 | What 3rd parties CANNOT replace | ✅ | v1 (doc-only) |
| **§15.12** | **PGP user key management** | 🚧 | **v1** (user prioritized) |
| **§15.13** | **OpenVPN server-side registration** | 🚧 | **v1** (small extension; symmetry with client-side) |
| **§15.14** | **WireGuard server-side registration** | 🚧 | **v1** (symmetric) |
| **§15.15** | **Webhook / event subscription** | 🚧 | **v2** |
| **§15.16** | **HSM / external Root key custody** | 🚧 | **v3** (already noted in §18.3) |
| **§15.17** | **Dedicated `code-mint` intermediate** | 🚧 | **v0.6+** — §15.23 (v0.5.0) cert-kind markers now provide the same type-separation guarantee at the marker layer; §15.17 intermediate-pinning may be redundant. Reconsider after marker enforcement on renew lands. |
| **§15.18** | **CSR-based code-signing issuance** | 🟡 | **v0.5.0 infra shipped** — `mssh.ca.csr` (used by §15.19 external-use) is reusable for code-sign; a thin wrapper is the remaining work. ~30 LOC + tests. |
| **§15.22** | **Per-Root rotation + revocation + admin-web visibility** | 🚧 | **v0.6+** — v0.5.0 shipped the storage + load + mint flow. Rotation of a non-primary Root, per-Root CRL issuance, and admin-web Root listing are the v0.6 follow-up. ~200 LOC + tests. |
| **§15.23** | **Renew-side kind-drift enforcement** | 🚧 | **v0.6+** — v0.5.0 emits kind markers on every mint but the renew path still infers kind from EKU rather than validating against the inbound cert's marker. Needs a graceful legacy bypass for v0.4.x certs without markers. ~80 LOC + tests. |

### Other items reviewed

| Item | Decision | Notes |
|------|----------|-------|
| `mscp` (PGP-encrypted file transfer) | **v2 idea** (no v1 §) | User: "not so much." Stays in §18.2 / future-ideas.md |
| LDAP / OIDC / SAML user enrollment | **out of v1 scope** | Capture as v3 idea if interest emerges |
| Prometheus metrics endpoint | **out of v1 scope** | Audit log is the v1 telemetry surface |
| ACME for auxiliary certs | **dropped in v0.1.6** | Replaced by `/v1/cert/renew` |

---

## v1 ship blockers (must land before release)

| ref      | title                                              | priority | status | branch | notes |
|----------|----------------------------------------------------|----------|--------|--------|-------|
| §1.4.2   | gated mode (msshd outer mTLS + CA + operator sshd) | P2       | 🚧     |        | also §5.3.3; estimate ~300-500 LOC + 20 tests |
| §5.3.3   | gated handler (msshd implementation of §1.4.2)     | P2       | 🚧     |        | composes with operator's existing sshd at port-22 |
| §6.3.5   | mssh `-L` local-port forwarding                    | P3       | 🚧     |        | dependency for §11.3.5 admin-web tunneling; ~150 LOC |
| §8.3.7   | mssh-passkey hardening v2 (anti-compromised-broker) | P2      | 🚧     |        | §13.9.1 hardening member; unconditional v1 blocker |
| §11.3.3  | mssh-admin-web mutating CRUD                       | P3       | 🚧     |        | matches CLI permission model |
| §11.3.5  | admin-web via mssh-tunneled localhost              | P3       | 🚧     |        | depends on §6.3.5 |
| §12.4.2  | mssh-mcp audit tagging (`origin: mcp`)             | P3       | 🚧     |        | §13.9.2 hardening member |
| §12.4.3  | mssh-mcp capability allow-list (CA-side defense-in-depth) | P3       | 🟡     |        | §13.9.2; MCP-side enforcement landed; CA-side refusal of `origin: mcp` on non-allowed actions pending |
| §13.9.6  | audit log tamper-resistance posture                | P2       | 🚧     |        | hash chain or signed checkpoints; retention policy |
| §13.9.7  | default-deny on missing config                     | P2       | 🟡     |        | `validate()` exists in each `config.py`; verification pass to confirm every security-relevant field has a fail-closed default |
| §13.9.8  | cert OID + marker enforcement                      | P2       | 🚧     |        | every validating site checks §14.5 markers explicitly |
| §17.6    | code-↔-design cross-reference matrix               | P1       | 🟡     |        | initial pass populated §17.6 in the design; full coverage matrix pending |
| §17.7    | test-↔-design cross-reference matrix               | P1       | 🟡     |        | initial pass in progress (4 batch agents); see also §17.7 in design |
| §17.8    | coverage gap list → TESTS-TODO.md                  | P1       | 🚧     |        | drives missing-test work; populated after §17.7 |

### Discrepancies surfaced by initial verification pass (2026-05-22)

| ref | finding | priority | notes |
|-----|---------|----------|-------|
| §3.6 + §15.4 | `views_broker.py` doesn't enforce per-ceremony "owning RP == caller CN" — only the CN-allowlist gate (`_auth_or_401`) applies. Design claims per-ceremony binding. | P2 | reconcile before FREEZE: either tighten views_broker.py or relax §3.6/§15.4 claim |
| §14.5 | OID block in `cert_minter.py` exists; bit-for-bit equivalence with §14.5 table not yet verified | P2 | manual audit + test_cert_minter.py expansion |
| §14.7 | Typed framing encoder/decoder lives in `mssh/client.py::_pump_framed`; design sketches a shared module in `mssh-common`. Final canonical location not yet settled. | P3 | refactor to mssh-common OR update design to acknowledge client-local |
| §11.3.3 | `api_user_pki` is a 501 stub today | P3 | implement per §11.3.3 |

## v1 ship blockers (partial — needs completion)

| ref      | title                                              | priority | status | branch | notes |
|----------|----------------------------------------------------|----------|--------|--------|-------|
| §4.3.11  | auxiliary issuance — PGP                           | P4       | 🟡     |        | X.509/OpenVPN/WireGuard ✅; PGP open per design (post-v1 candidate, demote if needed) |
| §10      | debug_sshd                                         | P4       | 🟡     |        | core ✅; §10.4 in-situ swap-in still 🚧 |
| §11      | mssh-admin-web                                     | P3       | 🟡     |        | read-only views ✅; §11.3.3 + §11.3.5 open |
| §12      | mssh-mcp                                           | P3       | 🟡     |        | read-only surface 🟡; hardening §12.4.2/3 open |
| §13.7    | auxiliary certificate issuance (cross-cutting)     | P4       | 🟡     |        | PGP open |
| §15.2    | CA as step-ca parallel — auxiliary issuance        | P4       | 🟡     |        | PGP open |
| §15.10   | LXC / pyinfra integration for testing              | P3       | 🟡     |        | Phase A still in progress |

## Post-v1 (does NOT block release — see §18)

(Move rows here once §1–§17 are all ✅.)

### External change requests (pending triage — no §-ref yet)

- **PENDING — dual-stack (IPv6) WireGuard peers.** Requested by totaldns
  (design §29 IPv6-first). Add an optional `network_v6` `/64` to
  `POST /v1/admin/wireguard/server`; assign + register a per-peer v6 host
  address (same host-number as v4 when both families present) into the
  **server-side** `[Peer] AllowedIPs` (cryptokey-routing requires it), and
  surface `address_v6`. Full spec + Option-A decision: [`ipv6_ask.md`](ipv6_ask.md).
  Needs a §-ref carved into the design before it becomes a tracked row.
  **Status: pending** (totaldns parks §29.2 VPN-v6 until this lands).

---

Refresh: re-run the §0.5 verification pass after every commit that
adds, drops, or changes a §-ref. The verification pass repopulates
§17.6, §17.7, §17.8 and downgrades any ✅ that loses its tests or
implementation.
