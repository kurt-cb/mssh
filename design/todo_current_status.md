# mssh — todo status (quick reference)

Snapshot of open work after v0.1.1 tag. Regenerate by re-scanning
`design/future-ideas.md`, `design/openbugs/`, and in-code `TODO`
markers. Last updated: 2026-05-20.

For full context on any row, follow the link to its
`design/future-ideas.md` section.

## Open bugs

None. All historical bugs in [archive/closedbugs/](../archive/closedbugs/)
(12 files, including 5 closed by v0.1.1's §21 typed framing).

## Future-ideas — active / pickable

| ID | Title | Status | Depends on | Notes |
|---|---|---|---|---|
| [§24](future-ideas.md#24-multi-server-group-lab-coverage) | Multi-server group lab coverage | Test gap | [pyinfra-adhoc Phase A](../python/tests/pyinfra-adhoc/adhoc-pyinfra-transition.md) | Becomes a 2-row matrix.py edit + policy assertions once Phase A lands |
| [§25](future-ideas.md#25-mssh-admin-pki--first-class-user-facing-pki-ceremony) | `mssh-admin pki` CLI | CLI gap | (none) | Today the helper is [scripts/mint-user-pki.py](../scripts/mint-user-pki.py); promote to subcommand. ~120 LOC |
| [§8](future-ideas.md#8-centralized-client-config--mssh-replaces-ssh) | Centralized client config (`~/.mssh/`) v2 | Partial | (none, if pull-only) | v1 file layout landed; v2 = msshd-mediated `--sync` writes CA-rendered config. ~200 LOC |
| [§26](future-ideas.md#26-admin-web-portal-via-mssh-tunneled-localhost) | Admin web portal via mssh-tunneled localhost | Design proposal | mssh `-L` flag (~150 LOC) | Supersedes browser.md's MDM-pinned portal path. ~780 LOC for read-only v1, ~1600 for full CRUD |
| [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) | CA mints credentials for other apps | Expanded scope | (none) | X.509 expansion (TLS server, HTTPS user, OpenVPN, code-sign) ~800 LOC; WireGuard +400; PGP +700; ACME +500 |
| [§11](future-ideas.md#11-in-situ-debug_sshd-swap-in-for-troubleshooting-sideband-ca-audit) | In-situ debug_sshd swap-in | Partial | (none) | Diagnostics affordance; remaining work documented in-section |
| [§23](future-ideas.md#23-sshd_config-template-unification) | sshd_config template unification | Partial | (none) | Equivalence test landed; full unification deferred |

## Future-ideas — pending design

| ID | Title | Notes |
|---|---|---|
| [§22](future-ideas.md#22-push-channel-for-revocation--live-session-kill) | Push channel for revocation + live-session kill | Design pending |
| [§13](future-ideas.md#13-legacy-config-migration-with-dual-enforce--shadow-mode) | Legacy-config migration / dual-enforce / shadow mode | Composes with §20 |
| [§6](future-ideas.md#6-require-2fa-for-high-privilege-roles-with-air-gap-fallback) | 2FA for high-privilege roles | Design needed; non-trivial |
| [§4](future-ideas.md#4-wrapper-supports-protocols-beyond-ssh--https--tcp-proxy) | Protocols beyond SSH (HTTPS/TCP proxy) | Needs analysis |

## Future-ideas — substantial / deferred

| ID | Title | Notes |
|---|---|---|
| [§20](future-ideas.md#20-end-to-end-migration-test-with-auto-generated-playbook) | E2E migration test + auto-generated playbook | Depends on pyinfra-adhoc Phase A + Phase-1/2 msshd port. ~800 LOC after that |
| [pyinfra-adhoc Phase A](../python/tests/pyinfra-adhoc/adhoc-pyinfra-transition.md) | Matrix-driven cross-distro spinup | Prereq for §20 and §24. Unblocks both |
| [§19](future-ideas.md#19-bash-auto-completion-scripts-for-mssh-commands) | Bash auto-completion | Defer until v1 release |
| [§16](future-ideas.md#16-distro-packaging-path-deb--rpm--apk) | Distro packaging (`.deb` / `.rpm` / `.apk`) | Roadmap item |

## Future-ideas — capture-only (no commitment yet)

[§2](future-ideas.md#2-smart-card-piv--pkcs11-support) PIV/PKCS#11 ·
[§7](future-ideas.md#7-passkey--webauthn-support) WebAuthn ·
[§10](future-ideas.md#10-browser-based-ssh-terminal-xtermjs-over-https-mtls-authenticated) Browser SSH terminal ·
[§18](future-ideas.md#18-self-service-why-was-i-denied-report) "Why was I denied?" self-service

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

- [§21](future-ideas.md#21-protocol-v11--typed-framing-for-the-post-ack-stream) typed framing protocol — closed bugs #1, #2, #3, #4, #11
- [§17](future-ideas.md#17-per-session-banner-with-variable-substitution) banner v1 + BANNER-frame delivery to mssh client (stretch per-session `{user}` substitution noted in-section but not blocking)
- [bug #6](../archive/closedbugs/bug-06-no-connect-timeout.md) — 5s connect timeout in mssh client
- [bug #7](../archive/closedbugs/bug-07-docs-cli-drift.md) — docs/CLI alignment
- [TUTORIAL_USER_MANAGEMENT.md](../docs/TUTORIAL_USER_MANAGEMENT.md) + [TUTORIAL_MIGRATION.md](../docs/TUTORIAL_MIGRATION.md) end-to-end verified
- [scripts/mint-user-pki.py](../scripts/mint-user-pki.py) helper for the user-facing PKI hierarchy
- [pyinfra-adhoc/](../python/tests/pyinfra-adhoc/) native-pyinfra inventory (precondition for §20 / §24)
