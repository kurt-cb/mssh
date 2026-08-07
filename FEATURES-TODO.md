# mssh — FEATURES-TODO

Companion to [design/mssh_design_v1.md](design/mssh_design_v1.md) §0.4.
Every row carries a §-ref into the design. New rows added only when
the design admits a new §-reference.

Columns: `ref` (§ from design), `title`, `priority` (P1–P9), `status`
(⚪ not started / 🚧 in progress / ✅ done), `branch` (working branch,
blank if none), `notes`.

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

### Phase 1 — Audit + reconcile design vs. code drift ✅ COMPLETE

**Status:** ✅ closed by v0.5.1 (2026-06-14). R-1..R-10 + R-8 supplement
all landed; `test_design_xref.py` green; §14 wire/disk contracts are
the v1 baseline.

Audit findings (originally logged in §17.6) reconciled via **Path Z**:
Code→Design where the design's interface is meaningfully better;
Design→Code where the design is just renamed differently; DROP where
the design over-spec'd unbuilt features. Per-commit detail in
[FEATURES-COMPLETE.md](FEATURES-COMPLETE.md) release notes
(v0.4.0 = R-1..R-9, v0.5.1 = R-10 + R-8 supplement).

**Recon outcome ledger** (one line per R-row):

- ✅ R-1 — §14.5 + §14.8 cert-profile fixes (v0.4.0). OID table normalized, `OID_CA_BYPASS` NULL encoding, `OID_FORCE_COMMAND` / `OID_ENVIRONMENT` `critical=True`.
- ✅ R-2 — §14.8 authz/bypass extension completion (v0.4.0). KU/EKU/CRLDP/SAN/SKI on both authz + bypass certs; bypass-mint intermediate pinning.
- ✅ R-3 — §14.1 response envelope normalization (v0.4.0). `result`/`request_id`/`ca_server_id`/`issued_at`/`denied_reason` shape; shim consumers updated.
- ✅ R-4 — §14.1 admin path catalog (v0.4.0). WireGuard `peer` routes, passkey path normalization, 2FA-gated intermediate ops, action-name underscore normalization.
- ✅ R-5 — §3.6 + §15.4 broker per-ceremony binding (v0.4.0). `views_broker.py` enforces `ceremony.created_by == X-Client-CN`; 404 for cross-tool access.
- ✅ R-6 — §14.6 audit.jsonl key normalization (v0.4.0). Canonical keys (`ts`/`request_id`/`actor`/`action`/`target`/`result`/`detail`/`origin`); empty-default `origin` wired.
- ✅ R-7 — §14.6 + §14.4 on-disk state shape (v0.4.0). `last_used_at` tracking, `intermediates:` enrollment key, `require_2fa: null` migration.
- ✅ R-8 — §14.3.1 + §14.3.2 + §14.3.4 schema rewrites (v0.4.0 main body, v0.5.1 supplement). v0.5.1 added the deferred "land NEW parsing" piece: `mcp:` + `audit.rotation` + `audit.integrity` + `ratelimits.*` + `templates.builtin_dir` now parse into typed dataclasses on `CAConfig`.
- ✅ R-9 — §13.9.7 default-deny verification (v0.4.0). `CAConfig.validate()` + msshd `validate()` + mssh-passkey fail-closed paths; parametrized test matrix in `test_ca_config.py`.
- ✅ R-10 — §14.3.3 + §14.3.5 + §14.3.6 (v0.4.0 §14.3.3 client; v0.5.1 §14.3.5 admin-web YAML loader + §14.3.6 MCP allow-list from CA config). Admin-web supports both flat-legacy and structured YAML; MCP gating reads from `ca-config.yaml::mcp.capability_allow_list` with the v0.4.0 frozenset as the fallback default.

**Exit criteria met:** `test_design_xref.py` is green; every §14
section has a passing static-equivalence test. Design and code agree
at the wire/disk surface. (§0 status still "FROZEN BASELINE — pending
verification" because §1–§16 *features* aren't all ✅ yet — Phase 2
remaining.)

### Phase 2 — Interface-shaping ship blockers (mostly landed)

Goal: land every 🚧 that *adds* to §14, so the contract is finalized
before test-writing.

**TIER 2A — base infrastructure**
- ✅ §5.3.3 gated mode — v0.4.0
- ✅ §13.9.6 audit log tamper-resistance — v0.4.0
- ✅ §12.4.2 + §12.4.3 MCP hardening — v0.4.0 (origin tagging + CA-side enforcement); v0.5.1 makes the allow-list operator-tunable
- 🚧 §8.3.7 broker hardening v2 — callback hardening landed in v0.4.0; broader anti-compromised-broker posture (caller-bound ceremony state, replay caps) pending; v1 blocker

**TIER 2B — PKI surface completion**
- ⚪ §7.3.4 `mssh-admin pki` subcommand — `scripts/mint-user-pki.py` still standalone
- ⚪ §15.12 PGP user key management (~400 LOC + 15 tests)
- ⚪ §15.13 OpenVPN server-side registration (~80 LOC + 4 tests)
- ✅ §15.14 WireGuard server-side registration — v0.4.0 (`POST /v1/admin/wireguard/server`) + v0.4.0 dual-stack (§15.14 IPv6)
- ✅ §15.19 external-use cert kind — v0.5.0
- ✅ §15.20/.21/.22/.23 mint-external profiles + custom OIDs + new-Root + kind markers — v0.5.0

**TIER 2C — UX additions**
- ⚪ §6.3.5 mssh `-L` (~150 LOC + 8 tests)
- ⚪ §11.3.3 admin-web mutating CRUD + api_user_pki — `api_user_pki` is still a 501 stub; depends on §7.3.4
- ⚪ §11.3.5 admin-web tunneled localhost — depends on §6.3.5

**Exit:** §14 is bit-for-bit final. §0 status moves from "FROZEN
BASELINE — pending verification" → "FROZEN BASELINE."

### Phase 3 — Hardening sweep ✅ COMPLETE (folded into v0.4.0 / v0.5.0)

- ✅ §13.9.7 default-deny on missing config (v0.4.0 R-9; parametrized matrix in `test_ca_config.py`)
- 🚧 §13.9.8 cert OID + marker enforcement — v0.5.0 §15.23 stamps cert-kind markers on every leaf + intermediate-purpose markers on §15.20 intermediates; remaining work is wiring every *validating* site (msshd authz, renew path) to require the marker rather than infer purpose from EKU

### Phase 4 — Verification-pass tooling ✅ COMPLETE (v0.4.0)

`python/tests/test_design_xref.py` shipped in v0.4.0 and is enforced
on every commit. It checks:
- ✅ every `.py` under `python/packages/<pkg>/src/` has a `Design: §X.Y` ref
- ✅ every test file under `python/tests/` has a `Tests: §X.Y` ref
- ✅ every `§X.Y.Z` referenced in code/tests resolves to an actual section
- ✅ §17.6 / §17.7 / §17.8 coverage gates

(Verification gate is now automated; no additional work in this phase.)

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
| §15.10 | LXC / pyinfra integration for testing | 🚧 | **v2** (incus/lxc auto-detect + firewalld preflight in v0.4.0; Ubuntu+Fedora deployment-validation suite green; not a v1 release gate) |
| §15.11 | What 3rd parties CANNOT replace | ✅ | v1 (doc-only) |
| §15.12 | PGP user key management | ⚪ | **v1** (user prioritized) |
| §15.13 | OpenVPN server-side registration | ⚪ | **v1** (small extension; symmetry with client-side) |
| §15.14 | WireGuard server-side registration | ✅ | **v0.4.0** (dual-stack IPv6 v0.4.0) |
| §15.15 | Webhook / event subscription | ⚪ | **v2** |
| §15.16 | HSM / external Root key custody | ⚪ | **v3** (already noted in §18.3) |
| §15.17 | Dedicated `code-mint` intermediate | ⚪ | **v0.6+** — §15.23 (v0.5.0) cert-kind markers now provide the same type-separation guarantee at the marker layer; §15.17 intermediate-pinning may be redundant. Reconsider after marker enforcement on renew lands. |
| §15.18 | CSR-based code-signing issuance | 🚧 | **v0.5.0 infra shipped** — `mssh.ca.csr` (used by §15.19 external-use) is reusable for code-sign; a thin wrapper is the remaining work. ~30 LOC + tests. |
| §15.19 | External-use certificate kind | ✅ | **v0.5.0** |
| §15.20 | `mint-external --profile <name>` | ✅ | **v0.5.0** |
| §15.21 | Operator-allowlist custom OIDs | ✅ | **v0.5.0** |
| §15.22 | Per-Root rotation + revocation + admin-web visibility | 🚧 | **v0.6+** — v0.5.0 shipped the storage + load + mint flow. Rotation of a non-primary Root, per-Root CRL issuance, and admin-web Root listing are the v0.6 follow-up. ~200 LOC + tests. |
| §15.23 | Cert-kind markers + per-kind validity | ✅ | **v0.5.0** (markers); renew-side kind-drift enforcement deferred to v0.6+ — needs legacy bypass for v0.4.x certs without markers. ~80 LOC + tests. |

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
| §6.3.5   | mssh `-L` local-port forwarding                    | P3       | ⚪     |        | dependency for §11.3.5 admin-web tunneling; ~150 LOC |
| §8.3.7   | mssh-passkey hardening v2 (anti-compromised-broker) | P2      | 🚧     |        | §13.9.1 callback hardening landed in `mssh-passkey/callback.py`; broader posture (caller-bound ceremony state, replay caps) pending; v1 blocker |
| §11.3.3  | mssh-admin-web mutating CRUD                       | P3       | ⚪     |        | `api_user_pki` is a 501 stub; depends on operator-facing user-PKI ceremony (§7.3.4) |
| §11.3.5  | admin-web via mssh-tunneled localhost              | P3       | ⚪     |        | depends on §6.3.5 |
| §13.9.8  | cert OID + marker enforcement (validating sites)   | P2       | 🚧     |        | v0.5.0 stamps cert-kind markers on every leaf (§15.23) + intermediate-purpose markers on §15.20 intermediates; remaining work is wiring every *validating* site (msshd authz, renew path) to require the marker rather than infer purpose from EKU |
| §17.8    | coverage gap list → TESTS-TODO.md                  | P1       | 🚧     |        | drives missing-test work; precursors §17.6/.7 closed in v0.4.0; needs a pass to populate gaps |

**Recently completed v1 ship blockers** (full audit trail in
[FEATURES-COMPLETE.md](FEATURES-COMPLETE.md)):

- ✅ §1.4.2 / §5.3.3 gated mode — v0.4.0
- ✅ §12.4.2 mssh-mcp `origin: mcp` audit tagging — v0.4.0
- ✅ §12.4.3 mssh-mcp capability allow-list — v0.4.0 (CA-side refusal in `admin.py::_check`); operator-tunable from `ca-config.yaml::mcp` since v0.5.1
- ✅ §13.9.6 audit log tamper-resistance — v0.4.0 (per-entry `prev_hash` + `AuditLog.verify_chain()`)
- ✅ §13.9.7 default-deny on missing config — v0.4.0 (R-9)
- ✅ §17.6 code-↔-design cross-reference matrix — v0.4.0 (`test_design_xref.py`)
- ✅ §17.7 test-↔-design cross-reference matrix — v0.4.0 (same suite)

### Discrepancies surfaced by initial verification pass (2026-05-22)

| ref | finding | priority | status | notes |
|-----|---------|----------|--------|-------|
| §14.7 | Typed framing encoder/decoder lives in `mssh/client.py::_pump_framed`; design sketches a shared module in `mssh-common`. Final canonical location not yet settled. | P3 | ⚪ | refactor to mssh-common OR update design to acknowledge client-local |
| §11.3.3 | `api_user_pki` is a 501 stub today | P3 | ⚪ | implement per §11.3.3 (also tracked above in v1 ship blockers) |

**Resolved discrepancies:**

- ✅ §3.6 + §15.4 broker per-ceremony binding — v0.4.0 ([views_broker.py:101, :125](python/packages/mssh-passkey/src/mssh_passkey/views_broker.py#L101))
- ✅ §14.5 OID block equivalence — v0.4.0 (`test_design_xref.py` + `test_cert_minter.py`)

## v1 partial-completion rollup (multi-§ chapters)

| ref      | title                                              | priority | status | branch | notes |
|----------|----------------------------------------------------|----------|--------|--------|-------|
| §4.3.11  | auxiliary issuance — PGP                           | P4       | 🚧     |        | X.509 / OpenVPN / WireGuard (v0.4.0 dual-stack) / external-use (v0.5.0) ✅; PGP only piece left (post-v1 candidate, demote if needed) |
| §10      | debug_sshd                                         | P4       | 🚧     |        | core ✅; §10.4 in-situ swap-in still ⚪ |
| §11      | mssh-admin-web                                     | P3       | 🚧     |        | read-only views ✅; §14.3.5 YAML loader landed v0.5.1; §11.3.3 + §11.3.5 still ⚪ |
| §12      | mssh-mcp                                           | P3       | ✅     |        | read-only surface + CA-side enforcement landed v0.4.0 (§12.4.2/3); operator-tunable allow-list landed v0.5.1; catalog covered by `test_mcp_ca_side.py` + `test_r8_r10_config_parsers.py` |
| §13.7    | auxiliary certificate issuance (cross-cutting)     | P4       | 🚧     |        | PGP open; X.509 / WireGuard / external-use shipped |
| §15.2    | CA as step-ca parallel — auxiliary issuance        | P4       | 🚧     |        | PGP open; v0.5.0 added the external-use kind (§15.19) to the parallel-CA surface |
| §15.10   | LXC / pyinfra integration for testing              | P3       | 🚧     |        | incus/lxc auto-detect + firewalld preflight landed v0.4.0; Ubuntu+Fedora deployment-validation suite green; pyinfra integration ⚪ |

## Post-v1 (does NOT block release — see §18)

(Move rows here once §1–§17 are all ✅.)

---

Refresh: re-run the §0.5 verification pass after every commit that
adds, drops, or changes a §-ref. The verification pass repopulates
§17.6, §17.7, §17.8 and downgrades any ✅ that loses its tests or
implementation.
