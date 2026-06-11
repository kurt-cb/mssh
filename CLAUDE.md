# mssh

Runtime, CA-mediated SSH authorization. SSH client identity unchanged;
authorization moves out of the client into a network-restricted CA the
server contacts at every connection.

The defining property: **a stolen client credential is useless if the
attacker can't reach the CA.** Put the CA on a private network;
stolen keys can't authorize from outside that network.

## Canonical sources

| Topic | Source | Notes |
|-------|--------|-------|
| **Design (FROZEN BASELINE)** | [design/mssh_design_v1.md](design/mssh_design_v1.md) | §-numbered. Immutable once verification (§0.5) passes. |
| Open work tracker | [FEATURES-TODO.md](FEATURES-TODO.md) | Every row has a §-ref. |
| Shipped features | [FEATURES-COMPLETE.md](FEATURES-COMPLETE.md) | |
| Tests needed | [TESTS-TODO.md](TESTS-TODO.md) | Gap list from the verification pass. |
| Operator docs | [docs/](docs/) | `docs/N-<module>.md` mirrors design chapter §N. |
| Future ideas (post-v1) | [design/future-ideas.md](design/future-ideas.md) | Trimmed to ideas-only; implemented items pulled up into the design. |
| Historical reference | [archive/design_reorg/](archive/design_reorg/) | Pre-v1 design docs + HANDOFF + old CLAUDE.md. Don't write here. |

## Working discipline (load-bearing)

These are not preferences — they're the conditions that keep the
design and code aligned.

- **Every commit / PR / code comment carries a `§X.Y.Z` reference** to
  the relevant design section. Code without a design reference is
  treated as a bug (per [design §0.2](design/mssh_design_v1.md#02-code-cross-reference-rule)).
- **Every test declares the §s it covers** in its docstring as either
  `Tests: §X.Y, §X.Y.Z` (module-level) or `Verifies §X.Y.Z — <line>`
  (per-test). Per [design §0.3](design/mssh_design_v1.md#03-test-cross-reference-rule).
- **No changes to v1 design content** while the doc is FROZEN.
  Additions go at the end (new §-numbers). Supersedes leave the
  original §-number RESERVED with a pointer to the replacement.
- **All network errors fail-closed** (deny access).
- **Banned in active sources:** the word "wrapper" (use "msshd" /
  "gateway"). The Phase / Tier / PoC framing is also retired.
  These survive in `archive/` by design.

## Style

- Author: Kurt Godwin (github.com/kurt-cb)
- Keep code simple and readable.
- Comments explain why, not what.
- Error messages should be specific and actionable.

## Quick layout reference

```
mssh/
├── CLAUDE.md                       # this file
├── README.md
├── INSTALLATION.md
├── FEATURES-TODO.md                # ← open work, §-indexed
├── FEATURES-COMPLETE.md            # ← shipped features
├── TESTS-TODO.md                   # ← test gaps
├── design/
│   ├── mssh_design_v1.md          # ← THE FROZEN BASELINE
│   └── future-ideas.md            # post-v1 ideas only
├── docs/                           # operator-facing: docs/N-<module>.md
├── archive/
│   ├── design_reorg/              # pre-v1 design docs + HANDOFF
│   └── closedbugs/                # historical bugs
├── python/
│   └── packages/                  # 6-package layout
│       ├── mssh/                  # client → src/mssh/client.py
│       ├── msshd/                 # gateway daemon
│       ├── mssh-ca/               # CA service
│       ├── mssh-admin/            # operator CLI + admin-web + mcp
│       ├── mssh-common/           # shim + akc_shim
│       └── mssh-passkey/          # WebAuthn broker
├── openssh-patches/
├── config/
├── scripts/
└── systemd/
```

## When you're picking up work

1. Read [design/mssh_design_v1.md](design/mssh_design_v1.md) §0 first
   (status, numbering, verification gate).
2. Pick a row from [FEATURES-TODO.md](FEATURES-TODO.md).
3. The `ref` column points at the §-section in the design with the
   purpose / interconnections / implementation detail you need.
4. Implementation **must** add a `Design: §X.Y` line to the module
   docstring and a `# §X.Y.Z` comment at load-bearing sites.
5. Tests **must** declare `Tests: §X.Y.Z` in their docstrings.
6. Once the work lands, move the row to
   [FEATURES-COMPLETE.md](FEATURES-COMPLETE.md) and remove from
   FEATURES-TODO (and from TESTS-TODO if tests were also covered).
7. Re-run the verification pass (§0.5) — it repopulates §17.6 / §17.7
   / §17.8 and surfaces any new gaps.

## Dependencies

```
asyncssh>=2.14
cryptography>=41.0
flask>=3.0
pyyaml>=6.0
click>=8.0
requests>=2.31
webauthn>=2.0
```

## Hardening posture (v1 ship blocker — §13.9)

mssh-hardening is a v1 deliverable. The hardened posture must ship
**regardless of which optional modules are enabled** — enabling an
optional module later must not require a follow-up release.
Members: §8.3.7 (broker), §12.4.2/3 (MCP), §5.3.6 (cache eviction),
§5.3.9 (CRL strict-mode), §5.3.7 (bypass validation), §13.9.6 (audit
integrity), §13.9.7 (default-deny on missing config), §13.9.8 (cert
OID enforcement).
