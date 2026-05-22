# mssh — todo status (quick reference)

Snapshot of open work after v0.1.7 tag. Regenerate by re-scanning
`design/future-ideas.md`, `design/openbugs/`, and in-code `TODO`
markers. Last updated: 2026-05-21 (post wrapper-rename).

For full context on any row, follow the link to its
`design/future-ideas.md` section.

Status icons used throughout this doc, matching
[ca-integration.md](ca-integration.md):

  - **✅ implemented** — stable CLI / API surface; operators can use it
  - **🟡 partial** — primitives or scaffolding land; full
    operator-facing path still incomplete
  - **🚧 design only** — captured in design docs, no code yet

## Open bugs

None. All historical bugs in [archive/closedbugs/](../archive/closedbugs/)
(12 files, including 5 closed by v0.1.1's §21 typed framing).

---

## Passkey ecosystem — v0.1.5 state

Three pieces, two flows. The broker module is its own deployment
target; mssh-ca consumes it for both the admin-2FA flow (mssh-ca
challenges its own admins) and the external-tool RP flow (mssh-ca
acts as a WebAuthn RP for separate apps).

Design docs:

  - [mssh-passkey-module.md](mssh-passkey-module.md) — broker internals
  - [admin-2fa.md](admin-2fa.md) — admin-2FA flow design
  - [ca-integration.md § Passkey RP service for external tools](ca-integration.md#passkey-rp-service-for-external-tools-) — external-tool flow design
  - [docs/operations.md § Require passkey 2FA](../docs/operations.md#require-passkey-2fa-for-high-privilege-admin-operations-) — operator playbook
  - [passkey-design-document.md](passkey-design-document.md) — original 4-option evaluation

### mssh-passkey broker module

| Piece | Status | Notes |
|---|---|---|
| Storage (SQLite ceremonies table) | ✅ | Single table; broker holds no keys + no per-user state |
| Flask app + dual-listener (apache / dev) | ✅ | `front_end: apache` for prod (TLS at apache2); `front_end: dev` for in-process TLS in the lab |
| Broker API (`POST/GET/DELETE /broker/ceremony[/<id>]`) | ✅ | mTLS-gated via `X-Client-CN` header |
| Public browser pages (`/register/<id>`, `/approve/<id>`) | ✅ | Bootstrap 5 + vanilla JS WebAuthn driver |
| Callback delivery worker | ✅ | Exponential retry: immediate, +5s, +30s, +2m, +10m |
| TTL expiry sweeper | ✅ | 30s tick; marks expired ceremonies + schedules callback |
| Adhoc-lab container provisioning | ✅ | `scripts/setup-adhoc-passkey.sh` mints lab PKI, installs, starts the broker |
| Apache2 reverse-proxy production deployment | 🚧 | Config sketch in `mssh-passkey-module.md § 8`; not lab-tested |
| Hardening v2 — defenses against compromised broker | 🚧 | Injection / DoS / bogus-callback handling on the mssh-ca callback receiver; **2FA fail-state** mode. Section in `mssh-passkey-module.md`; nothing implemented yet |
| Real-phone smoke test in adhoc lab | 🚧 | Helper script runs; operator hasn't tapped a real authenticator against the lab broker yet |

### mssh-admin 2FA flow (challenging mssh-ca's own admins)

| Piece | Status | Notes |
|---|---|---|
| Enrollment schema (PasskeyCredential under Admin records) | ✅ | `enrollment.py` |
| WebAuthn RP adapters (`webauthn` PyPI lib integration) | ✅ | `passkey.py` — register/auth options + verification + AAGUID allowlist |
| PasskeyBrokerClient (mTLS HTTPS client) | ✅ | `passkey_broker.py` |
| Admin handlers: enroll-begin / list / revoke / callback / poll | ✅ | `admin.py` |
| Policy DSL: `require_2fa: passkey` + `twofa_within_seconds` | ✅ | Validated at policy-add time; refuses unknown values |
| Per-admin 2FA cache (in-memory, TTL) | ✅ | `AdminContext.passkey_2fa_cache`; revoke invalidates |
| `mssh-admin user passkey {enroll,list,revoke}` CLI | ✅ | Plus `mssh-admin policy add --require-2fa passkey --2fa-within-seconds N` |
| 2FA enforcement helper (`passkey_check_2fa`) | ✅ | Returns 202 challenge / None / 503 / 403 |
| **Wire enforcement into protected handlers** (admin.add, user.remove, cert.revoke, …) | ✅ | Per-action gating via `admin_2fa.protected_actions` in ca-config.yaml. Four handlers wired in v0.1.8: admin.add, admin.remove, user.remove, cert.revoke. Operator widens the list to gate more actions. |
| **mssh-admin CLI polling loop on 202 Accepted** | ✅ | `_handle_2fa_call` in mssh-admin/main.py prints the URL, polls `/v1/admin/passkey/ceremony/<id>`, retries on approval. Used by the 4 gated commands. QR rendering deferred to v1.x. |
| Audit log entries for register-complete / 2fa-success / failed / rejected | ✅ | All flow → `ctx.audit.write` |

### External-tool RP flow (mssh-ca challenges users of separate apps)

| Piece | Status | Notes |
|---|---|---|
| ExternalTool enrollment schema | ✅ | Per-tool `user_credentials` namespace |
| Tool CRUD: `mssh-admin external-tool {add,list,remove}` | ✅ | `add` mints mTLS cert tool presents to `/v1/external/passkey/*` |
| Tool-mTLS endpoints: enroll-begin / challenge / ceremony / revoke | ✅ | `/v1/external/passkey/*` — CN-gated to enrolled tools |
| `outcome_url_prefix` enforcement | ✅ | Prevents compromised tool cert from delivering outcomes to arbitrary URLs |
| Cross-tool isolation | ✅ | Tool A cannot poll Tool B's ceremonies |
| Two-hop callback delivery (broker → ca → tool) | ✅ | `_maybe_post_external_outcome` with reuse of broker mTLS material |
| Per-tool AAGUID allowlist (override CA-global) | 🚧 | v1 inherits CA-global; per-tool override is v2 |
| Per-tool rate limits | 🚧 | Config flag at `external-tool add` time; v1 has no rate limiting |
| Tool cert rotation runbook | 🚧 | Same shape as admin cert rotation; needs explicit operator doc |

---

## PKI hierarchy (Root + named intermediates) — **v1.0 BLOCKER**

Roadmap from [notes-pki-hierarchy.md](notes-pki-hierarchy.md) +
[security.md § Chain of trust](security.md#chain-of-trust-v2-multi-intermediate-model).

**Scope decision (2026-05-21):** moved from "v2 future" to "v1.0
blocker" — shipping v1 on the legacy single-signer and then
immediately rolling out a fundamental trust-model change would
invalidate the CA model right after release. The trust-model
amendment (validation pins to a specific intermediate, NOT the root)
is load-bearing. Version bumped to v0.2.x to signal the shift.

Until these commits land, the v0.1.4 §5 work signs every leaf through
the legacy single-signer — acceptable for experimental deployments,
explicitly not the production end-state.

| Phase | Title | Status | Notes |
|---|---|---|---|
| [Commit 1](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | Foundation: `Intermediate` dataclass + helpers | ✅ | Landed pre-v0.1.1 |
| [Commit 2](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | `bootstrap_ca` refactor: Root + 4 intermediates on disk | ✅ | Landed v0.2.1. New `ca_dir/{root-cert.pem,intermediates/<role>/{cert,key}.pem}` layout; legacy `signing-*.pem` + `tls-ca-*.pem` aliases preserved for callers that haven't migrated |
| [Commit 3](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | Per-issuer CRL | ✅ | Landed v0.2.2. `CRLRegistry` wraps per-intermediate `CRLStore`s; `/v1/crl?issuer=X` + `/v1/crl.pem?issuer=X`; authorize response carries `current_crl_seqs` map; legacy single-file CRL auto-migrates on startup |
| [Commit 4](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | msshd chain validation + per-issuer cache state | ✅ | Landed v0.2.3. `AuthzCache.last_crl_seqs: dict[str, int]` (legacy `last_crl_seq` is a user-mint alias). `CRLSync` iterates per-issuer. Strict-mode gate sums per-issuer gaps. |
| [Commit 4b](security.md#chain-of-trust-v2-multi-intermediate-model) | **Validation pins to intermediate, not Root** (load-bearing rule) | ✅ | Landed v0.2.3. `msshd.yaml ca.bypass_trust_root` pins bypass-cert verification to the bypass-mint intermediate (separate from user-mint authz signing). Falls back to `auth_trust_root` only for v0.2.0 single-signer compat. |
| [Commit 5](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | `mssh-admin intermediate ...` CLI | ✅ | Landed v0.2.4. `mssh-admin intermediate list / rotate <role> --force`; `mssh-admin cert revoke --issuer <name>`; `mssh-admin crl list --issuer <name>`. Rotation archives the old keypair with a timestamp suffix and keeps legacy aliases in sync. |
| [Commit 5b](notes-pki-hierarchy.md#amendment-2026-05-20-validation-rule--external-intermediate-ca) | **External Intermediate CA tier** (per §25) | ✅ | Landed v0.2.5. `mssh-admin intermediate mint-external --name X --path-length N`; CA stores only the public cert (key returned once + handed to external entity OOB). Trust-store-exclusion verified by tests: an external-X-signed bypass cert fails msshd's bypass-mint pin. |
| [Commit 6](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | Backfill tests | ✅ | Landed v0.2.6. Chain validation + strict-mode gate + per-issuer CRL covered across `test_pki_v023_pinning.py`, `test_crl_registry.py`, `test_intermediate_cli.py`, `test_external_intermediate.py`. Tests: 607 green. |
| [Commit 7](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | Doc consolidation | ✅ | Landed v0.2.6. `design/security.md § Chain of trust v2` gained a status table for v0.2.1–v0.2.5 + operator action checklist. `docs/operations.md § Manage intermediate CAs` covers list/rotate/mint-external. CLAUDE.md amendments preserved as historical record. |
| (separate) | Root key offline / HSM | 🚧 | Production wants HSM or offline machine. v3+ |

The full v2 hierarchy is ~1500–2000 LOC across CA + msshd + admin
+ tests. Phasing keeps tests green at each commit boundary.

---

## Future-ideas — active / pickable

| ID | Title | Status | Depends on | Notes |
|---|---|---|---|---|
| [§24](future-ideas.md#24-multi-server-group-lab-coverage) | Multi-server group lab coverage | 🚧 | [pyinfra-adhoc Phase A](../python/tests/pyinfra-adhoc/adhoc-pyinfra-transition.md) | 2-row matrix.py edit + policy assertions once Phase A lands |
| [§25](future-ideas.md#25-mssh-admin-pki--first-class-user-facing-pki-ceremony) | `mssh-admin pki` CLI (user-PKI ceremony + External CA tier) | 🟡 | (none) | Cert auto-renewal piece landed in v0.1.6 (`mssh-admin cert renew` + systemd template). Still open: promote [scripts/mint-user-pki.py](../scripts/mint-user-pki.py) to a subcommand (~120 LOC) + External CA tier per the trust-model amendment |
| [§8](future-ideas.md#8-centralized-client-config--mssh-replaces-ssh) | Centralized client config (`~/.mssh/`) v2 | 🟡 | (none, if pull-only) | v1 file layout landed; v2 = msshd-mediated `--sync` writes CA-rendered config. ~200 LOC |
| [§26](future-ideas.md#26-admin-web-portal-via-mssh-tunneled-localhost) | Admin web portal via mssh-tunneled localhost | 🟡 | mssh `-L` flag (~150 LOC) for the tunnel half | Server side at [mssh.admin.web](../python/packages/mssh-admin/src/mssh/admin/web/); read-only views + mTLS re-issue. Mutating CRUD and the `-L` client flag still open |
| [§5 remainder](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) | CA mints credentials — PGP | 🟡 | (none) | X.509 + OpenVPN + WireGuard + CRLDP landed in v0.1.4. ACME was dropped in v0.1.6 (auto-renewal absorbed into §25 `cert renew`). Still open: PGP (~700 LOC, composes with §27) |
| [§27](future-ideas.md#27-mscp--pgp-encrypted-file-transfer-using-the-ca-as-key-directory) | `mscp` — PGP-encrypted file transfer via CA-as-directory | 🚧 | (none for v1 BYO keys; §5 PGP backend for v2 CA-minted) | ~560 LOC for v1. CA stores PGP pubkey per user; mscp encrypts/decrypts via local gpg |
| [§11](future-ideas.md#11-in-situ-debug_sshd-swap-in-for-troubleshooting-sideband-ca-audit) | In-situ debug_sshd swap-in | 🟡 | (none) | Diagnostics affordance; remaining work documented in-section |
| [§23](future-ideas.md#23-sshd_config-template-unification) | sshd_config template unification | 🟡 | (none) | Equivalence test landed; full unification deferred |

## Future-ideas — pending design

| ID | Title | Status | Notes |
|---|---|---|---|
| [§22](future-ideas.md#22-push-channel-for-revocation--live-session-kill) | Push channel for revocation + live-session kill | 🚧 | Design pending |
| [§13](future-ideas.md#13-legacy-config-migration-with-dual-enforce--shadow-mode) | Legacy-config migration / dual-enforce / shadow mode | 🚧 | Composes with §20 |
| [§4](future-ideas.md#4-msshd-supports-protocols-beyond-ssh--https--tcp-proxy) | Protocols beyond SSH (HTTPS/TCP proxy) | 🚧 | Needs analysis |

(§6 + §7 2FA / WebAuthn — **mostly landed in v0.1.5**. See the
Passkey ecosystem section at the top of this doc.)

## Future-ideas — substantial / deferred

| ID | Title | Status | Notes |
|---|---|---|---|
| [§20](future-ideas.md#20-end-to-end-migration-test-with-auto-generated-playbook) | E2E migration test + auto-generated playbook | 🚧 | Depends on pyinfra-adhoc Phase A + Phase-1/2 msshd port. ~800 LOC after that |
| [pyinfra-adhoc Phase A](../python/tests/pyinfra-adhoc/adhoc-pyinfra-transition.md) | Matrix-driven cross-distro spinup | 🚧 | Prereq for §20 and §24. Unblocks both |
| [§19](future-ideas.md#19-bash-auto-completion-scripts-for-mssh-commands) | Bash auto-completion | 🚧 | Defer until v1 release |
| [§16](future-ideas.md#16-distro-packaging-path-deb--rpm--apk) | Distro packaging (`.deb` / `.rpm` / `.apk`) | 🚧 | Roadmap item |
| Full integration of mssh-passkey into the test_setup_only_msshd.py journey | 🚧 | Currently `scripts/setup-adhoc-passkey.sh` is a separate provisioning helper. Folding into the standard journey gives 6-container labs that include the broker from setup_adhoc.sh's first run |

## Future-ideas — capture-only (no commitment yet)

🚧 [§2](future-ideas.md#2-smart-card-piv--pkcs11-support) PIV/PKCS#11 ·
🚧 [§10](future-ideas.md#10-browser-based-ssh-terminal-xtermjs-over-https-mtls-authenticated) Browser SSH terminal ·
🚧 [§18](future-ideas.md#18-self-service-why-was-i-denied-report) "Why was I denied?" self-service

## In-code TODOs

| Location | Description |
|---|---|
| ~~[enforce_listener.py:487](../python/packages/msshd/src/mssh/msshd/enforce_listener.py#L487)~~ | ~~Bypass-cert chain-to-trust-root verification~~ — closed in v0.1.9 via new `ca.auth_trust_root` config field. Operators MUST point it at the CA's `signing-cert.pem`; bypass injection refuses if unset (fail-closed). |
| [authz_cache.py:26](../python/packages/msshd/src/mssh/msshd/authz_cache.py#L26) | Unbounded growth on long-lived bypass certs (documented in CLAUDE.md amendment c) |

## Drift / housekeeping

| Item | Notes |
|---|---|
| (nothing currently open) | `make pkg` dist-cleanup fixed in v0.1.7 polish pass |

## Recently landed (since v0.1.0)

- **v0.1.7** — `wrapper` terminology fully eliminated from active
  sources. Rename touches ~60 files, ~400 occurrences:
  - File paths: `wrapper.yaml{,.example}` → `msshd.yaml{,.example}`;
    `wrapper-{server,mtls,user-ca,audit}` → `msshd-*`; OS user
    `_msshwrapper` → `_msshd`.
  - Identifiers: `WrapperConfig`/`WrapperCAClient` →
    `MsshdConfig`/`MsshdCAClient`; `DEFAULT_WRAPPER_PORT` →
    `DEFAULT_MSSHD_PORT`; `SSH_RT_AUTH_WRAPPER_STATE_DIR` →
    `MSSHD_STATE_DIR`; stale `ssh-rt-wrapper-admin` →
    `msshd-admin`.
  - Tests: 8 `test_wrapper_*.py` → `test_msshd_*.py` via `git mv`
    (history preserved).
  - Docs / installer / systemd / openssh-patches: all prose
    "wrapper" → "msshd" / "gateway"; CLAUDE.md style rule updated.
  - Archive (`archive/`) retains the old terminology by design
    (frozen historical content).
  - 525 tests still green; entry points (`mssh`, `msshd`,
    `msshd-admin`, `mssh-admin`) re-verified.
- **v0.1.6** — cert auto-renewal + ACME drop (3 commits, ~620 LOC):
  - **Dropped ACME** from §5 scope. Auto-renewing TLS across the
    fleet is the only operational goal that justified ACME (~2000
    LOC of RFC 8555 compliance); it's better served by a tiny
    mTLS-authenticated `cert renew` endpoint that reuses the
    existing `cert_minter` helpers.
  - **CA**: `POST /v1/cert/renew` (NOT under `/v1/admin/` — cert IS
    the credential, no admin-role bearer). Validates chain + CRL,
    enforces 30-day renewable window + 7-day past-grace cutoff,
    preserves CN/SANs/EKU/validity, optional `revoke_predecessor`.
    Returns 200 with `status='too_early'` when out-of-window.
  - **Admin CLI**: `mssh-admin cert renew --cert … --key … --out-cert
    … --out-key … --threshold-days N --revoke-old --on-renew CMD`.
    Skips silently if local cert is > threshold days from expiry
    (cheap to run daily on every host). Atomic file writes; key
    file mode 0600.
  - **systemd**: `cert-renew@<service>.{service,timer}` template
    drives daily renewal. `OnCalendar=daily`, `RandomizedDelaySec=30m`
    so 1000 services don't all hit mssh-ca at 00:00.
  - 19 new tests (12 CA handler + 7 CLI). 525 total green.
- **v0.1.5** — passkey ecosystem (11 commits, ~7400 LOC):
  - [`mssh-passkey`](../python/packages/mssh-passkey/) broker module — public-facing WebAuthn ceremony broker (HTTPS for browsers; mTLS for back-end clients). Single SQLite ceremonies table; no key material; relay-only.
  - [admin-2FA flow](admin-2fa.md) — `mssh-admin user passkey {enroll,list,revoke}` + `policy add --require-2fa passkey --2fa-within-seconds N`. Per-admin 2FA cache. `webauthn` PyPI integration. AAGUID allowlist enforcement.
  - [External-tool RP service](ca-integration.md#passkey-rp-service-for-external-tools-) — `mssh-admin external-tool {add,list,remove}` + `/v1/external/passkey/*` tool-mTLS endpoints. Two-hop callback (broker → CA → tool). Cross-tool isolation. outcome_url_prefix enforcement.
  - [`scripts/setup-adhoc-passkey.sh`](../scripts/setup-adhoc-passkey.sh) — provisions a passkey LXC container alongside a running lab; mints lab PKI; starts the broker.
  - 59 new tests (storage, broker API, admin handlers, external-tool flow). 506 total green.
- **v0.1.4** — §5 X.509 family + WireGuard + CRLDP — `mssh-admin {cert mint, openvpn issue, wireguard ...}`; X.509 CRL endpoint
- **v0.1.3** — admin web portal `msshd-admin-web` (Flask + Bootstrap5; read-only views + mTLS re-issue)
- **v0.1.1** — §21 typed framing protocol + §17 banner delivery + bugs #1-#11 closed
- **v0.1.0** — 5-package wheel layout
- [scripts/mint-user-pki.py](../scripts/mint-user-pki.py) helper for the user-facing PKI hierarchy
- [TUTORIAL_USER_MANAGEMENT.md](../docs/TUTORIAL_USER_MANAGEMENT.md) + [TUTORIAL_MIGRATION.md](../docs/TUTORIAL_MIGRATION.md) end-to-end verified
- [pyinfra-adhoc/](../python/tests/pyinfra-adhoc/) native-pyinfra inventory (precondition for §20 / §24)
