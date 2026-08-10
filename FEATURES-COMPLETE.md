# mssh — FEATURES-COMPLETE

Companion to [design/mssh_design_v1.md](design/mssh_design_v1.md) §0.4.
Rows populated when a feature ships. `notes` includes commit hash +
verification step (§ from the design) that passed.

Columns: `ref`, `title`, `landed-in`, `commit`, `notes`.

---

## Release notes — v0.5.7 (2026-08-10)

**Root CN is now mandatory config on `mssh-admin init`.**

v0.5.6 introduced a `<hostname> Root CA` default. That was still too
easy to accept silently — an operator running `mssh-admin init`
without thinking about the CA identity ended up with `fedora Root CA`
or similar in every trust store, and later couldn't easily tell one
CA from another.

**v0.5.7 makes `--root-cn` REQUIRED** on the CLI. Attempting to run
init without it fails with `Missing option '--root-cn'` from click.
The help text steers operators toward concrete names ("ACME Root CA",
"internal.example.com Root", etc.).

The programmatic `bootstrap_ca()` Python API still accepts a
`root_cn=None` default for tests + embedded uses, but the fallback CN
is now **`Unspecified cert from host <hostname>`** — deliberately
placeholder-looking so anyone finding it in a real trust store knows
the required config step was skipped. Pre-v0.5.7: `mssh-root` (bad —
looks legit) → `<hostname> Root CA` (still too legit) → **`Unspecified
cert from host <hostname>`** (obviously placeholder).

**Test coverage:** 918 unit tests pass (up from 916 at v0.5.6; +2
tests in `test_root_cn_and_cn_validation.py` covering the CLI
required-flag error path and the happy-path with an operator CN.
Existing test that checked the v0.5.6 hostname default updated for
the new placeholder wording).

**To tag this release:**
```
git tag v0.5.7
git push mssh v0.5.7
```

---

## Release notes — v0.5.6 (2026-08-08)

Two operator-facing improvements. Both non-breaking.

**1. Root CA CN is now configurable / hostname-derived.**

Pre-v0.5.6 every mssh CA got the identical hard-coded Root CN
`mssh-root`, which made it hard to distinguish one CA's Root from
another in a trust-store listing or an audit log. New defaults:

- `bootstrap_ca(root_cn=None)` — defaults to `<hostname> Root CA`
  (from `socket.gethostname()`). Operator-supplied `root_cn`
  overrides.
- `mssh-admin init --root-cn "ACME Root CA"` — CLI flag surfaces
  it. Without the flag, `<hostname> Root CA` is used.

The Root cert's Organization stays `mssh` (unchanged; still useful
to identify the emitting software).

**2. CN + SAN validation with warnings.**

`cert_mint` now validates the CN and each SAN against RFC 1035
hostname rules. Two failure modes:

- **Hard errors (400 bad_request):** empty CN, control chars in CN,
  CN over 64 bytes, invalid SAN characters, wildcard in a non-
  leftmost SAN label.
- **Warnings (mint succeeds, warning surfaced in response +
  echoed by CLI):**
  - Single-label DNS name (like `kg-di-dev`) — modern browsers
    reject bare hostnames in SANs with `ERR_CERT_COMMON_NAME_INVALID`.
    Add the domain suffix (`kg-di-dev.local`) or use an IP SAN.
  - `tls-server` mint with no DNS SAN at all — same failure mode;
    modern browsers ignore CN entirely.
  - Non-DNS CN on a `tls-server` mint.

Warnings surface in the mint response's new `warnings: [...]` field
and the `mssh-admin cert mint` CLI echoes each one to stderr with a
`WARNING:` prefix. Non-DNS-shaped CNs on non-TLS kinds (`code-sign`,
`openvpn`) get no complaint — the CN is a free-form identifier
there.

**About the `ERR_CERT_COMMON_NAME_INVALID` a real operator hit:**

Chrome and Firefox stopped honoring the CN as a hostname source
around 2017. They require the URL hostname to match a `DNS:` entry
in the SubjectAltName extension (per RFC 6125 §6.4.4). For a bare
hostname like `kg-di-dev` — even with the exact same value in the
CN and a SAN — Chromium's cert verifier requires the SAN's DNS name
to look like an FQDN (labels separated by at least one dot). This
is not something the CA can fix — it's a browser policy — but v0.5.6
now warns at mint time so operators aren't debugging TLS handshakes
after deploy.

**Test coverage:** 916 unit tests pass (up from 881 at v0.5.5;
+35 new tests in `test_root_cn_and_cn_validation.py` covering
`_default_root_cn`, `bootstrap_ca(root_cn=...)`, RFC 1035 label +
name validation happy + sad paths, wildcard placement, SAN
normalization, CN validation per cert kind, and end-to-end
warning surfacing).

**To tag this release:**
```
git tag v0.5.6
git push mssh v0.5.6
```

---

## Release notes — v0.5.5 (2026-08-08)

**Backward-compat correction to v0.5.4.**

v0.5.4 changed the default behavior of `IssuedClientCert.cert_pem`
from leaf-only (legacy) to leaf+intermediate. That was a breaking
default change — any operator script that concatenated `cert_pem +
ca_cert_pem` to build a fullchain suddenly got a duplicated
intermediate. v0.5.5 reverts the default and makes fullchain
strictly opt-in.

**Changes:**

- `IssuedClientCert.cert_pem` — reverted to v0.5.3 semantics
  (leaf-only in the legacy positional signing path — which is every
  admin.py callsite in production).
- `IssuedClientCert.full_chain_pem` — new field, always populated
  with the leaf + issuing intermediate. Reach for this when you know
  you need a TLS-handshake-ready fullchain and don't want to concat.
- `IssuedClientCert.leaf_only_pem` — the field added in v0.5.4 is
  gone. `cert_pem` IS the leaf-only in the legacy path, so a
  separate field would be redundant.
- Admin responses' `credentials` dict now carries both `cert_pem`
  (v0.5.3 shape) and `full_chain_pem` (new).
- CLI `cert mint` gains `--fullchain` flag. Without it, the v0.5.3
  file layout is preserved byte-identical: `OUT-cert.pem` = leaf,
  `OUT-ca.pem` = intermediate, `OUT-key.pem` = key. With
  `--fullchain`, `OUT-cert.pem` = leaf + intermediate — no need to
  `cat OUT-cert.pem OUT-ca.pem > fullchain.pem` afterward.
- No `OUT-leaf.pem` file (v0.5.4 added it, v0.5.5 drops it — the
  default `OUT-cert.pem` IS the leaf).

**Operator recipe for a TLS web cert (v0.5.5):**

```bash
mssh-admin cert mint --type tls-server \
    --cn web.example.com --csr web.csr \
    --fullchain --out web
# → wrote web-cert.pem (fullchain), web-ca.pem — no key file
```

**Operator recipe preserving v0.5.3 workflow (no code change needed):**

```bash
mssh-admin cert mint --type tls-server --cn web.example.com \
    --san DNS:web.example.com --out web
cat web-cert.pem web-ca.pem > web-fullchain.pem   # unchanged concat
```

**Test coverage:** 881 unit tests pass (up 1 from v0.5.4; +10 revamped
tests in `test_fullchain_output.py` for the opt-in semantics: default
leaf-only, --fullchain switches to chain, full_chain_pem field
invariants, per-handler surfacing, CLI help text).

**To tag this release:**
```
git tag v0.5.5
git push mssh v0.5.5
```

---

## Release notes — v0.5.4 (2026-08-08)

**Systemic bugfix: emitted certs now carry the fullchain.**

Before this release, every issue-cert path in the CA (`cert mint` for
tls-server / https-user / code-sign, `server add`, `admin add`,
`openvpn issue`, `cert renew`, `external-tool add`) returned `cert_pem`
as **leaf-only** whenever it took the legacy positional signing path
in `admin.py` — which was every call site in production. A TLS server
handed the resulting `cert.pem` presented only its leaf in the
handshake; clients that trusted just the root failed the handshake
with a "bad certificate" alert, when the actual problem was missing
intermediate — precisely the kind of misdirection that ate two days
of debugging for a real operator.

**Fix:** `IssuedClientCert.cert_pem` is now **always** the leaf +
issuing intermediate (fullchain, TLS-handshake-ready). A new
`leaf_only_pem` field carries the leaf on its own for callers that
need it (openssl inspection, PKCS#12 wrap, custom chain assembly).

**CLI output layout matches `cert external-use`:**

```
mssh-admin cert mint --type tls-server --cn web.example.com \
    --san DNS:web.example.com --out web
# → wrote web-cert.pem (fullchain), web-leaf.pem (leaf),
#   web-ca.pem (ca), web-key.pem (key, mode 0600)
```

With `--csr`, `web-key.pem` is omitted (private key stays on target
host).

Response body change (API): all admin handlers that build
`credentials` from an `IssuedClientCert` bundle now include a
`leaf_only_pem` field. Existing consumers reading `cert_pem` see the
fullchain instead of leaf-only — which is what TLS servers actually
need in the handshake.

Backwards compat: any operator scripts that concatenated
`cert_pem + ca_cert_pem` to build a fullchain now get a duplicated
intermediate; drop the concat step (or switch to `leaf_only_pem`
if leaf-only is what they wanted). PKCS#12 (`.p12`) export uses
the new `leaf_only_pem` internally — PKCS#12's schema expects one
cert entry for the leaf and `cas=` for the chain.

**Test coverage:** 880 unit tests pass (up from 871 at v0.5.3;
+9 new tests in `test_fullchain_output.py` covering dataclass shape,
signature-verifies-against-issuer, ca_cert_pem = 2nd cert in fullchain
invariant, per-handler leaf_only_pem presence, and CLI four-file
layout for both CA-generated-key and CSR-based paths).

**To tag this release:**
```
git tag v0.5.4
git push mssh v0.5.4
```

---

## Release notes — v0.5.3 (2026-06-14)

Three fixes / additions that make the CSR + external-use flows actually
usable end-to-end for real operators.

**Headline:**

- **CSR-based `cert mint` for tls-server / https-user / code-sign
  (§15.18 v0.5.3)** — the CA now accepts an optional PKCS#10 CSR on
  every `cert mint` call. When set: CA uses the CSR's public key +
  merges its SANs with body-supplied SANs (de-duped) + returns the
  signed cert with an EMPTY `key_pem`. Operator's private key never
  traverses the network. This is the correct posture for TLS server
  certs. CLI: `--csr <path>`; client: `csr_pem=` kwarg. When `--csr`
  is set the CLI omits `OUT-key.pem` from the output prefix.

- **CSR-loader bugfix** — v0.5.2's CSR validator rejected SANs (`OID
  2.5.29.17`), which every openssl-generated CSR carries. Now accepts
  SANs (they're needed anyway for the mint path); still rejects
  KeyUsage / EKU / BasicConstraints / other operator-escalation
  attempts.

- **CA-retain intermediate key on non-generic `--profile` (§15.20
  v0.5.3)** — `mssh-admin intermediate mint-external --profile
  device-identity` now automatically persists a copy of the
  intermediate key at `<ca_dir>/external/<name>/key.pem` (mode 0600).
  The CA needs this key to sign external-use leaves under the
  intermediate, and the v0.5.2 workflow required an operator to
  hand-place it via `install -m 600` — friction + error-prone.
  Preserves v0.4.x §2.6 delegation semantics for `--profile generic`
  (still no retention). New `--no-retain-key` flag opts out even on
  device-identity profiles for operators who want to hand off to
  an external entity.

**End-to-end SSL web cert flow (v0.5.3)** — the private key stays
on the target host:

```bash
# On the target host:
openssl ecparam -name prime256v1 -genkey -noout -out web.key
openssl req -new -key web.key -subj "/CN=web.example.com" \
    -addext "subjectAltName=DNS:web.example.com,DNS:www.example.com" \
    -out web.csr

# Submit CSR to CA:
mssh-admin cert mint --type tls-server \
    --cn web.example.com --csr web.csr \
    --validity-days 365 --out web
# → wrote web-cert.pem, web-ca.pem  (no web-key.pem — stayed on host)
```

**Test coverage:** 871 unit tests pass (up from 859 at v0.5.2; +12 new
tests in `test_csr_cert_mint.py` covering CSR-based mint for all three
kinds, SAN merging with de-dup, kind-marker preservation, CA-generates
regression, corrupt-signature handling, and intermediate-key retention).

**To tag this release:**
```
git tag v0.5.3
git push mssh v0.5.3
```

---

## Release notes — v0.5.2 (2026-06-14)

Wire-up the CLI + REST plumbing for the v0.5.0 external-use / new-Root
/ profile features that landed at the admin-handler level but were
never exposed to operators.

**Headline:**

- **CLI: `mssh-admin cert external-use`** — new subcommand that
  submits a CSR to the CA for signing. Flags: `--cn`, `--csr <path>`,
  `--issuer-intermediate <name>`, `--validity-days N` |
  `--never-expires`, `--custom-oid NAME=VALUE` (repeatable), `--out
  <prefix>`. Writes `<prefix>-cert.pem` (leaf+chain), `<prefix>-leaf.pem`
  (leaf only), `<prefix>-ca.pem` (issuer intermediate). No key file —
  operator's CSR-supplied key stays on-device.

- **CLI: `mssh-admin intermediate mint-external`** grew three v0.5.0
  flags that were shipped in the admin handler but not the CLI:
  `--profile {generic|device-identity}`, `--new-root`, `--root <name>`.
  Composable — e.g. `--profile device-identity --new-root --root
  mfg-pki` creates a fresh Root + a device-identity intermediate under
  it in one shot.

- **REST**: `POST /v1/admin/cert/external-use` registered in
  `server.py`. Body matches the admin handler contract from v0.5.0.

- **Client**: `CAClient.cert_external_use_mint(cn, csr_pem,
  issuer_intermediate, ...)` + `CAClient.intermediate_mint_external`
  now accepts `profile`, `new_root`, `root_name`.

- **GitHub Actions release workflow** (`.github/workflows/release.yml`)
  — cuts a GitHub Release with the six wheels attached on every
  `v*.*.*` tag push. `scripts/install-from-github.sh` operator wrapper
  for `pip install`-ing wheels straight from a GitHub Release.

**Fixes the gap:** in v0.5.1, an operator could not actually mint an
external-use leaf without hitting the Python API directly — no CLI
verb, no REST route, no client method. v0.5.2 closes that.

**Test coverage:** 859 unit tests pass (up from 851 at v0.5.1; +8 new
tests in `test_external_use_cli.py` covering the client method + CLI
flag surface + REST route registration).

**To tag this release:**
```
git tag v0.5.2
git push mssh v0.5.2   # triggers the release workflow
```

---

## Release notes — v0.5.1 (2026-06-14)

Phase 1 reconciliation closure — landed the R-8 supplement + R-10 §14.3.5
+ R-10 §14.3.6 pieces that were deferred from v0.4.0. Phase 1 is now
fully closed.

**Headline:**

- **R-10 §14.3.5 mssh-admin-web YAML config loader** — `WebConfig.load()`
  now supports both the flat `key: value` legacy form (shared with the
  CLI) and the structured YAML form with `ca:` / `flask:` /
  `apache_integration:` blocks. New fields:
  - `flask.secret_key_file` — bytes installed as Flask `SECRET_KEY` (for
    §11.3.3 mutating-CRUD forward-compat).
  - `apache_integration.trusted_client_cn_header` — when set, the
    operator-CN identity is read from this header instead of relying on
    the mssh-mediated tunnel marker. `caller_cn_from_request()` helper
    threads through `flask.current_app.config['CALLER_CN_HEADER']`.

- **R-10 §14.3.6 MCP capability allow-list from `ca-config.yaml`** —
  `MCP_ALLOWED_ACTIONS` in `mssh.ca.admin` is now backed by
  `DEFAULT_MCP_ALLOWED_ACTIONS` in `mssh.ca.config` and replaced at
  server boot when the operator sets `mcp.capability_allow_list` in
  ca-config. `set_mcp_allow_list(frozenset | None)` API lets tests
  + the boot path install or reset the active list. The v0.4.0
  default behavior is preserved byte-identical when the YAML has no
  `mcp:` block.

- **R-8 supplement — new ca-config.yaml sections parsed:**
  - `mcp:` block — `enabled` flag + `capability_allow_list` (composes
    with R-10 §14.3.6).
  - `audit.rotation` — `max_bytes` + `keep_files` (plumbing; enforcement
    is a v0.6+ follow-up at the AuditLog writer).
  - `audit.integrity` — `signed_checkpoints` + `checkpoint_interval_seconds`
    (plumbing for the v0.6+ signed-checkpoint extension of the §13.9.6
    hash chain; the chain itself is always-on).
  - `ratelimits.*` — per-endpoint `{calls_per_minute}` dict (plumbing;
    Flask-route enforcement is a v0.6+ follow-up).
  - `templates.builtin_dir` — operator-tunable path override for the
    built-in template set.

  All five new sections are optional and absent-section default-deny
  behavior matches v0.4.x byte-identical.

- **Phase 1 reconciliation: ✅ closed.** Every §14 wire/disk contract
  is the v1 baseline. `test_design_xref.py` enforces it on every
  commit. FEATURES-TODO's R-1..R-10 plan collapsed to a one-line
  outcome ledger.

**Test coverage:** 851 unit tests pass (up from 835 at v0.5.0; +16 new
tests in `test_r8_r10_config_parsers.py`).

**Other:**

- FEATURES-TODO.md normalized to a three-state convention
  (⚪ not started / 🚧 in progress / ✅ done) and rid of stale rows
  for items that shipped in v0.4.0 / v0.5.0.

**To tag this release:**
```
git tag v0.5.1
# wheels will then build as 0.5.1 via setuptools_scm.
```

---

## Release notes — v0.5.0 (2026-06-14)

General-purpose CA features for non-SSH use cases — device identity,
operator-defined cert kinds, cert-kind markers, and operator-configurable
per-kind validity policy.

**Headline features:**

- **§15.19 External-use certificate kind** — new CSR-based generic
  cert kind for uses outside mssh's own runtime (IDevID per IEEE
  802.1AR, ROM-burned firmware identity, BMC certs, IoT shadow certs).
  Default 20yr validity (operator-tunable), `never_expires: true`
  opts into the RFC 5280 §4.1.2.5 `notAfter = 99991231235959Z`
  sentinel for ROM-burned identifiers. The CA never sees the private
  key — operator's TPM/secure-element key stays on-device. REST:
  `POST /v1/admin/cert/external-use`.

- **§15.20 `mint-external --profile <name>`** — extends §2.6
  external-intermediate flow with operator-named profiles. Built-in
  `device-identity` profile bumps validity to 30yr and stamps the
  §15.23 intermediate-purpose marker so external-use leaves can pin
  to it. Profile name persisted to `<ca_dir>/external/<name>/profile.json`.

- **§15.21 Operator-allowlist custom OIDs** — strict allowlist in
  ca-config.yaml's `custom_oids:` section. OID-arc split:
  `1.3.6.1.4.1.55555.[1-4999].*` is mssh-reserved (hard-rejected
  even if allowlisted; CA refuses to start), `1.3.6.1.4.1.55555.[5000-65535].*`
  is the mssh-assigned operator sub-arc (no IANA PEN registration
  needed). Five encodings supported: utf8, octet, integer, null,
  printable. Wires into both leaf-mint and intermediate-mint.

- **§15.22 `--new-root` separate-Root option** — opt-in
  `mssh-admin intermediate mint-external --new-root <name>` creates
  a fresh Root + intermediate together, persisted under
  `<ca_dir>/roots/<name>/{cert,key}.pem`. New `mssh.ca.roots`
  module loads all Roots at startup. v0.5.0 scope: storage + load
  + mint flow. Per-Root rotation/revocation deferred to v0.6+
  (FEATURES-TODO).

- **§15.23 Cert-kind markers** — every leaf the CA emits now carries
  a non-critical NULL marker OID under `1.3.6.1.4.1.55555.3.*`
  identifying its kind (9 OIDs covering authz-user/authz-bypass/
  server-tls/admin-mtls/client-mtls/https-user/code-sign/openvpn/
  external-use). Marker is non-critical so legacy verifiers ignore
  it per RFC 5280 §4.2. Provable cert-kind = downstream consumers
  can do type-based enforcement.

- **§15.23 Per-kind validity policy** — `cert_kinds:` section in
  ca-config.yaml moves validity defaults + caps from hardcoded
  globals into operator config. Per-kind lookup falls through
  per-kind → section-level default → built-in baseline. v0.4.x
  configs without `cert_kinds:` get baseline values byte-identical
  to v0.4.x.

- **CSR loading infrastructure** (`mssh.ca.csr`) — `load_and_verify_csr()`
  + `extract_public_key()` shared by §15.19 external-use and the
  pre-existing §15.18 code-signing CSR TODO. Rejects CSRs that
  smuggle extensions (CA owns KU/EKU/SAN).

- **Bootstrap config writer** (`mssh-admin init`) emits documented
  `cert_kinds:` + `custom_oids:` sections with the reserved-arc
  reference table inline so operators discover the conventions
  in-file.

- **`msshd-admin-web` alias removal** — the v0.4.0 deprecated alias
  is gone. Operators must now use `mssh-admin-web` (the canonical
  name per §14.2.7).

**Test coverage:** 835 unit tests pass (up from 731 at v0.4.0;
+104 new tests across 6 new files: test_csr.py,
test_custom_oid_allowlist.py, test_external_use_cert.py,
test_kind_markers.py, test_ca_config_cert_kinds.py,
test_bootstrap_init_emits_cert_kinds.py, test_new_root.py).

**Deferred to v0.6+ (FEATURES-TODO):**

- §15.22 per-Root rotation, per-Root revocation, admin-web Root visibility.
- §15.23 renew-side kind-drift detection (v0.5.0 ships markers but
  the renew validator still infers kind from EKU rather than from
  the marker — added when v0.4.x certs naturally age out).
- §15.17 dedicated code-mint intermediate (now arguably redundant
  with §15.23 markers; reconsider once §15.23 enforcement lands).

**To tag this release:**
```
git tag v0.5.0
# wheels will then build as 0.5.0 via setuptools_scm.
```

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
