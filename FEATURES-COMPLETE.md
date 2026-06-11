# mssh — FEATURES-COMPLETE

Companion to [design/mssh_design_v1.md](design/mssh_design_v1.md) §0.4.
Rows populated when a feature ships. `notes` includes commit hash +
verification step (§ from the design) that passed.

Columns: `ref`, `title`, `landed-in`, `commit`, `notes`.

---

## Release notes — v0.4.0 (2026-06-07)

Substantial release covering the Phase 1–5 work + WireGuard dual-stack.

**Headline features:**
- **§15.14 WireGuard dual-stack** — `network_v6` + `address_v6` family-agnostic
  "next free host number" allocator (option A). Server-side cryptokey-routing
  `[Peer] AllowedIPs` carries both `…/32` + `…/128`. v6-only servers also
  supported. Backward compat: v4-only catalogs load byte-identical.
- **§5.3.3 gated mode (MVP)** — middle rung of the adoption journey;
  mTLS + CA approval, proxy to operator's existing sshd.
- **§13.9.6 audit log hash chain** — `prev_hash` per entry +
  `AuditLog.verify_chain()`; tamper-evident.
- **§12.4.2 + §12.4.3 MCP CA-side enforcement** — `X-MSSH-Origin: mcp`
  header propagated; `MCP_ALLOWED_ACTIONS` allow-list enforced at the
  CA regardless of admin role; bypass-cert mint unreachable from MCP.
- **§13.9.7 default-deny CA validate** — `CAConfig.validate()` fail-closes
  on missing security-critical paths.
- **R-1..R-10 §14 reconciliation** — `OID_CA_BYPASS` NULL encoding,
  `KeyUsage`/`EKU`/`CRLDP`/`SAN`/`SKI` on authz + bypass certs, response
  envelope normalization, audit canonical keys, `last_used_at` tracking,
  schema design rewrites.
- **Phase 3 hardening matrices** — parametrized §13.9.7/.8 verification.
- **Phase 4 verification tooling** — `test_design_xref.py` automated
  §0.5 gate (every `.py` has `Design:`, every test has `Tests:`,
  every `§X.Y.Z` resolves).
- **LXC test infrastructure** — incus / lxc CLI auto-detect, ubuntu
  image probe (`images:ubuntu/22.04` first), firewalld DHCP preflight
  with Fedora-specific remediation banner.

**Code-signing TODOs added (v1.x):**
- §15.17 dedicated `code-mint` intermediate
- §15.18 CSR-based code-signing issuance

**Console-script audit fixes:**
- **§14.2.7** binary renamed `msshd-admin-web` → `mssh-admin-web`
  (canonical). The tool is operator-facing for `mssh-ca`'s admin API,
  not for `msshd`; the `msshd-` prefix mis-implied scope.
  `msshd-admin-web` kept as deprecated alias for one release — remove
  in v0.5.
- **§14.2.8** added to the design to register the `mssh-mcp` binary
  that already shipped in v0.2.x (was missing from §14.2 catalog).

**Test coverage:** 731 unit tests pass (up from baseline 656). 4/4 LXC
deployment-validation tests pass on Fedora + incus.

**To tag this release:**
```
git tag v0.4.0
# wheels will then build as 0.4.0 via setuptools_scm.
```

---

## §1 System overview

| ref      | title                                              | landed-in | commit  | notes |
|----------|----------------------------------------------------|-----------|---------|-------|
| §1.1     | defining property                                  | pre-v0.1  | —       | architectural — not a code artifact |
| §1.2     | component diagram + module list                    | pre-v0.1  | —       | architectural |
| §1.3     | glossary                                           | v0.3.x    | —       | populate during §17.6 verification pass |
| §1.4.1   | fallback mode                                      | v0.1.0    | —       | LXC-tested |
| §1.4.3   | enforce mode                                       | v0.1.0    | —       | LXC-tested |
| §1.4.4   | mode-selector semantics                            | v0.1.0    | —       | `msshd.yaml` `mode:` field |

## §2 Trust model + PKI hierarchy

| ref      | title                                              | landed-in | commit    | notes |
|----------|----------------------------------------------------|-----------|-----------|-------|
| §2.1     | two-hierarchy rationale                            | pre-v0.1  | —         | architectural |
| §2.2     | Root + named intermediates                         | v0.2.1    | —         | `bootstrap_ca` refactor |
| §2.3     | validation pinning rule (load-bearing)             | v0.2.3    | —         | `auth_trust_root` + `bypass_trust_root` |
| §2.4     | cert profiles + custom OIDs                        | pre-v0.1  | —         | extension table in §14.5 |
| §2.5     | rotation + revocation semantics                    | v0.2.4    | —         | `mssh-admin intermediate rotate` |
| §2.6     | External Intermediate CA tier                      | v0.2.5    | 2b5ef6d   | `intermediate mint-external` |

## §3 Wire protocols

| ref      | title                                              | landed-in | commit  | notes |
|----------|----------------------------------------------------|-----------|---------|-------|
| §3.1     | mssh ↔ msshd outer protocol (typed framing v1.1)   | v0.1.1    | —       | §21 typed framing |
| §3.2     | msshd ↔ CA                                         | v0.1.0    | —       | |
| §3.3     | mssh-admin ↔ CA                                    | v0.1.0    | —       | |
| §3.4     | msshd ↔ inner sshd                                 | v0.1.0    | —       | |
| §3.5     | external-tool ↔ CA                                 | v0.1.5    | —       | passkey ecosystem |
| §3.6     | broker ↔ CA / broker ↔ browser                     | v0.1.5    | —       | passkey ecosystem |

## §4–§9 modules — pre-populated stubs

(populate during §17.6 verification pass — for each §X.Y.Z marked ✅
in the design, find the implementing commit and add a row here.)

| ref      | title                                              | landed-in | commit  | notes |
|----------|----------------------------------------------------|-----------|---------|-------|
| §4       | mssh-ca                                            | v0.1.0+   | various | per-feature rows below |
| §5       | msshd                                              | v0.1.0+   | various | per-feature rows below |
| §6       | mssh (client)                                      | v0.1.0+   | various | per-feature rows below |
| §7       | mssh-admin                                         | v0.1.0+   | various | per-feature rows below |
| §8       | mssh-passkey (broker)                              | v0.1.5    | —       | broker module shipped |
| §9       | mssh-common                                        | v0.1.0+   | various | shim + akc_shim |
| §10      | debug_sshd                                         | v0.1.0    | —       | core; §10.4 still 🚧 |
| §11      | mssh-admin-web                                     | v0.1.3    | —       | read-only views; §11.3.3/5 still 🚧 |
| §12      | mssh-mcp                                           | v0.2.x    | —       | read-only surface 🟡; hardening 🚧 |

## §13 cross-cutting

| ref      | title                                              | landed-in | commit  | notes |
|----------|----------------------------------------------------|-----------|---------|-------|
| §13.1    | authz cache lifecycle                              | v0.2.x    | —       | (notes-bypass-cache.md amendment 2026-05-18) |
| §13.2    | CA-bypass cert (offline mint + later inject)       | v0.2.x    | —       | |
| §13.3    | CRL revocation channel (per-issuer)                | v0.2.2    | —       | |
| §13.4    | cert auto-renewal                                  | v0.1.6    | —       | `POST /v1/cert/renew` |
| §13.5    | admin 2FA (passkey) flow                           | v0.1.5/8  | —       | 4 handlers gated in v0.1.8 |
| §13.6    | external-tool RP flow                              | v0.1.5    | —       | |
| §13.8    | adoption journey                                   | pre-v0.1  | —       | architectural |

---

Refresh: append a row here when each §-numbered subsystem ships and
clears its verification step. `commit` is the merge SHA. `notes`
mentions which test(s) covered the verification.
