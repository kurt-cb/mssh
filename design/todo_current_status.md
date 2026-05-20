# mssh — todo status (quick reference)

Snapshot of open work after v0.1.1 tag. Regenerate by re-scanning
`design/future-ideas.md`, `design/openbugs/`, and in-code `TODO`
markers. Last updated: 2026-05-20 (post-trust-model docs).

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

## mssh-passkey module (separate deployment target)

A **new module, not part of mssh or mssh-ca.** Public-facing
WebAuthn relying party + transaction broker. mssh-ca consumes it
via mTLS for 2FA on high-privilege operations; future consumers
(§26 admin portal, kiosk login, internal apps) can share it.

Architectural decision in
[passkey-design-document.md](passkey-design-document.md)
(Option 2 — browser-native WebAuthn). Operator-facing CA-side
consumer integration in
[ca-integration.md § mssh-passkey integration](ca-integration.md#mssh-passkey-integration-for-2fa-on-ca-operations-).

| Piece | Status | Notes |
|---|---|---|
| mssh-passkey HTTP service skeleton | 🚧 | New Python package, separate from mssh/mssh-ca. HTTPS-only, WebAuthn library (`webauthn` PyPI), small DB for users + credentials + transactions. |
| Registration contract (mssh-ca → broker → user) | 🚧 | Open — proposed shape in ca-integration.md. AAGUID allowlist enforcement + multi-device + recovery flows all need to be pinned down. |
| Public broker API (transaction push + callback) | 🚧 | Open — proposed shape in ca-integration.md. Push vs poll for the outcome, replay defense, denied/expired surfacing, audit-across-services all to be solidified. |
| mTLS contract: mssh-ca ↔ mssh-passkey | 🚧 | Full cert validation both ways. Operator-managed trust hierarchy for both directions. Cert distribution at deploy time. |
| WebAuthn RP implementation | 🚧 | Challenge generation + attestation verification + assertion verification + counter tracking. AAGUID allowlist applied at registration per [browser.md](browser.md#webauthn-with-hardware-only-authenticators--the-cleaner-path). |
| Browser UI for registration + approval | 🚧 | Minimal HTML pages: registration ceremony (`navigator.credentials.create()`), approval ceremony (display transaction description + `navigator.credentials.get()`). |
| mssh-ca client integration | 🚧 | Config block in `ca-config.yaml`; CLI: `mssh-admin user passkey enroll / list / revoke`; policy DSL: `--require-2fa passkey`. |
| Layered (Option 4) upgrade path | 🚧 | Optional — adds an encrypted vault layer for high-security applications. Reserved per [passkey-design-document.md](passkey-design-document.md). |

The whole thing lives in a separate repo / package, not in
python/packages/. Deployment is independent; mssh-ca operators can
opt in to passkey 2FA per policy without changing anything about
mssh-ca itself if they're not using it.

---

## v2 PKI hierarchy (Root + named intermediates)

Roadmap from [notes-pki-hierarchy.md](notes-pki-hierarchy.md) +
[security.md § Chain of trust](security.md#chain-of-trust-v2-multi-intermediate-model).
Until this lands, the v0.1.4 §5 work signs every leaf through the
legacy single-signer — acceptable for experimental deployments,
explicitly not the production end-state.

| Phase | Title | Status | Notes |
|---|---|---|---|
| [Commit 1](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | Foundation: `Intermediate` dataclass + helpers | ✅ | Landed pre-v0.1.1. `cert_minter._self_signed_root`, `_issue_intermediate`, `compute_pubkey_fp16`, `load_intermediates`. `path_length=0` baked into the 4 internal intermediates. |
| [Commit 2](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | `bootstrap_ca` refactor: Root + 4 intermediates on disk | 🚧 | Write the new ca_dir/intermediates/{user-mint,host-mint,auth,bypass-mint}/ layout. Keep legacy alias files as symlinks during the transition. |
| [Commit 3](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | Per-issuer CRL | 🚧 | `CRLStore` → `CRLRegistry` of per-issuer stores. `/v1/crl?issuer=X`. Authorize response carries `current_crl_seqs` map (one entry per intermediate). |
| [Commit 4](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | msshd chain validation + per-issuer cache state | 🚧 | msshd loads Root + intermediates; `_handle_bypass_injection` validates chain to the pinned intermediate, not Root. `AuthzCache.last_crl_seqs: dict[str, int]`. |
| [Commit 4b](security.md#chain-of-trust-v2-multi-intermediate-model) | **Validation pins to intermediate, not Root** (load-bearing rule) | 🚧 | Wire each validator's trust store to the SPECIFIC intermediate cert: msshd user-mTLS → `auth`, msshd authz → `user-mint`, mssh → `host-mint`, etc. Without this, §5 leaves can impersonate users. |
| [Commit 5](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | `mssh-admin intermediate ...` CLI | 🚧 | `intermediate list / rotate <role>`; `cert revoke --issuer <id\|name>`. |
| [Commit 5b](notes-pki-hierarchy.md#amendment-2026-05-20-validation-rule--external-intermediate-ca) | **External Intermediate CA tier** (per §25) | 🚧 | `mssh-admin pki external mint --name <entity> --path-length N`. Root signs; mssh trust stores actively EXCLUDE it. Revoke via CRL on the external-X cert itself. |
| [Commit 6](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | Backfill tests for prior commits | 🚧 | Unit tests for chain validation, strict-mode gate, prefetched-header tests. |
| [Commit 7](notes-pki-hierarchy.md#implementation-plan-commit-boundaries) | Doc consolidation | 🚧 | Fold CLAUDE.md amendments into security.md / architecture.md / api.md; docs/operations.md gets the rotation procedure. |
| (separate) | Root key offline / HSM | 🚧 | Today Root sits on disk. Production wants it in an HSM or on an offline machine. Plumbing is v3+ per notes. |

The full v2 hierarchy is ~1500–2000 LOC across CA + msshd + admin
+ tests. Phasing keeps tests green at each commit boundary; see
notes-pki-hierarchy.md "Why we're shipping this in phases".

---

## Future-ideas — active / pickable

| ID | Title | Status | Depends on | Notes |
|---|---|---|---|---|
| [§24](future-ideas.md#24-multi-server-group-lab-coverage) | Multi-server group lab coverage | 🚧 | [pyinfra-adhoc Phase A](../python/tests/pyinfra-adhoc/adhoc-pyinfra-transition.md) | Becomes a 2-row matrix.py edit + policy assertions once Phase A lands |
| [§25](future-ideas.md#25-mssh-admin-pki--first-class-user-facing-pki-ceremony) | `mssh-admin pki` CLI (user-facing PKI + External CA tier) | 🚧 | (none) | Today the helper is [scripts/mint-user-pki.py](../scripts/mint-user-pki.py); promote to subcommand. External CA tier is a NEW scope per the 2026-05-20 trust-model amendment. ~120 LOC user-PKI + more for External CA |
| [§8](future-ideas.md#8-centralized-client-config--mssh-replaces-ssh) | Centralized client config (`~/.mssh/`) v2 | 🟡 | (none, if pull-only) | v1 file layout landed; v2 = msshd-mediated `--sync` writes CA-rendered config. ~200 LOC |
| [§26](future-ideas.md#26-admin-web-portal-via-mssh-tunneled-localhost) | Admin web portal via mssh-tunneled localhost | 🟡 | mssh `-L` flag (~150 LOC) for the tunnel half | Server side at [mssh.admin.web](../python/packages/mssh-admin/src/mssh/admin/web/); read-only views + mTLS re-issue. Mutating CRUD and the `-L` client flag still open |
| [§5 remainder](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) | CA mints credentials — ACME + PGP | 🟡 | (none) | X.509 + OpenVPN + WireGuard + CRLDP landed in v0.1.4. Still open: ACME (~2000+ LOC, deserves library-eval pass), PGP (~700 LOC, composes with §27) |
| [§27](future-ideas.md#27-mscp--pgp-encrypted-file-transfer-using-the-ca-as-key-directory) | `mscp` — PGP-encrypted file transfer via CA-as-directory | 🚧 | (none for v1 BYO keys; §5 PGP backend for v2 CA-minted) | ~560 LOC for v1. CA stores PGP pubkey per user; mscp encrypts/decrypts via local gpg |
| [§11](future-ideas.md#11-in-situ-debug_sshd-swap-in-for-troubleshooting-sideband-ca-audit) | In-situ debug_sshd swap-in | 🟡 | (none) | Diagnostics affordance; remaining work documented in-section |
| [§23](future-ideas.md#23-sshd_config-template-unification) | sshd_config template unification | 🟡 | (none) | Equivalence test landed; full unification deferred |

## Future-ideas — pending design

| ID | Title | Status | Notes |
|---|---|---|---|
| [§22](future-ideas.md#22-push-channel-for-revocation--live-session-kill) | Push channel for revocation + live-session kill | 🚧 | Design pending |
| [§13](future-ideas.md#13-legacy-config-migration-with-dual-enforce--shadow-mode) | Legacy-config migration / dual-enforce / shadow mode | 🚧 | Composes with §20 |
| [§6 2FA + mssh-passkey integration](ca-integration.md#mssh-passkey-integration-for-2fa-on-ca-operations-) | 2FA for high-privilege CA operations via separate mssh-passkey broker | 🚧 | Architecture chosen ([passkey-design-document.md](passkey-design-document.md) Option 2); CA-side consumer integration designed in [ca-integration.md](ca-integration.md#mssh-passkey-integration-for-2fa-on-ca-operations-). Two API contracts (registration + public broker) still open. **mssh-passkey module itself is a separate work item — see top of this doc.** TOTP / push factors still unspecified. |
| [§4](future-ideas.md#4-wrapper-supports-protocols-beyond-ssh--https--tcp-proxy) | Protocols beyond SSH (HTTPS/TCP proxy) | 🚧 | Needs analysis |

## Future-ideas — substantial / deferred

| ID | Title | Status | Notes |
|---|---|---|---|
| [§20](future-ideas.md#20-end-to-end-migration-test-with-auto-generated-playbook) | E2E migration test + auto-generated playbook | 🚧 | Depends on pyinfra-adhoc Phase A + Phase-1/2 msshd port. ~800 LOC after that |
| [pyinfra-adhoc Phase A](../python/tests/pyinfra-adhoc/adhoc-pyinfra-transition.md) | Matrix-driven cross-distro spinup | 🚧 | Prereq for §20 and §24. Unblocks both |
| [§19](future-ideas.md#19-bash-auto-completion-scripts-for-mssh-commands) | Bash auto-completion | 🚧 | Defer until v1 release |
| [§16](future-ideas.md#16-distro-packaging-path-deb--rpm--apk) | Distro packaging (`.deb` / `.rpm` / `.apk`) | 🚧 | Roadmap item |

## Future-ideas — capture-only (no commitment yet)

🚧 [§2](future-ideas.md#2-smart-card-piv--pkcs11-support) PIV/PKCS#11 ·
🚧 [§10](future-ideas.md#10-browser-based-ssh-terminal-xtermjs-over-https-mtls-authenticated) Browser SSH terminal ·
🚧 [§18](future-ideas.md#18-self-service-why-was-i-denied-report) "Why was I denied?" self-service

(§7 WebAuthn moved to "pending design" — now consolidated with §6 in
[ca-integration.md § Passkey / WebAuthn at the CA](ca-integration.md#passkey--webauthn-at-the-ca-).)

## In-code TODOs

| Location | Description |
|---|---|
| [enforce_listener.py:487](../python/packages/msshd/src/mssh/msshd/enforce_listener.py#L487) | Bypass-cert chain-to-trust-root verification (v1 relies on marker only) |
| [authz_cache.py:26](../python/packages/msshd/src/mssh/msshd/authz_cache.py#L26) | Unbounded growth on long-lived bypass certs (documented in CLAUDE.md amendment c) |

## Drift / housekeeping

| Item | Notes |
|---|---|
| `make pkg` doesn't clean `dist/` | Bit setup_adhoc.sh during the 2026-05-19 tutorial walk; multi-version wheels confuse pip. Add `make clean-pkg` target or clean inside `pkg:` |

## Recently landed (since v0.1.0)

- [§5 WireGuard + CRLDP](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) — `mssh-admin wireguard server-init / issue / server-show / revoke`; Curve25519 keypair generation, sequential IP allocation, wg-quick config emission, persistent JSON catalog. CRL Distribution Point embedded in issued X.509 leaves; new `GET /v1/crl.pem` endpoint signs the JSON CRL log as a real X.509 CRL.
- [§5 X.509 family](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) — `mssh-admin cert mint --type {tls-server, https-user, code-sign}` and `mssh-admin openvpn issue` first-class commands; new `/v1/admin/cert/mint` + `/v1/admin/openvpn/issue` endpoints; `.p12` packaging built into CLI for HTTPS user, `.ovpn` bundle assembly for OpenVPN
- [§26 server-side portal v1](../python/packages/mssh-admin/src/mssh/admin/web/) — Flask + Bootstrap5 admin portal with sortable/expandable users/groups/hosts/audit views + mTLS re-issue per server. Console script `msshd-admin-web`. Client-side `-L` flag still open
- [§21](future-ideas.md#21-protocol-v11--typed-framing-for-the-post-ack-stream) typed framing protocol — closed bugs #1, #2, #3, #4, #11
- [§17](future-ideas.md#17-per-session-banner-with-variable-substitution) banner v1 + BANNER-frame delivery to mssh client (stretch per-session `{user}` substitution noted in-section but not blocking)
- [bug #6](../archive/closedbugs/bug-06-no-connect-timeout.md) — 5s connect timeout in mssh client
- [bug #7](../archive/closedbugs/bug-07-docs-cli-drift.md) — docs/CLI alignment
- [TUTORIAL_USER_MANAGEMENT.md](../docs/TUTORIAL_USER_MANAGEMENT.md) + [TUTORIAL_MIGRATION.md](../docs/TUTORIAL_MIGRATION.md) end-to-end verified
- [scripts/mint-user-pki.py](../scripts/mint-user-pki.py) helper for the user-facing PKI hierarchy
- [pyinfra-adhoc/](../python/tests/pyinfra-adhoc/) native-pyinfra inventory (precondition for §20 / §24)
