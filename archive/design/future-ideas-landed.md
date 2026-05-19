<!-- Items from design/future-ideas.md that have LANDED. -->
<!-- Moved here per "archive holds completed work, design holds open work". -->

# Landed future-ideas (archive)

Items below were originally tracked as future-ideas in
`design/future-ideas.md`. They are now landed in code/docs and have
been moved here for the historical record. Original section numbering
preserved so external references continue to make sense.

| § | Title | Landed as |
|---|---|---|
| 1 | Per-connection ephemeral inner sshd | `mssh.msshd.inner.PerConnectionInnerSshd` + `inner.mode: per-connection` config |
| 3 | Client / server split | v0.1.0 5-package split (`mssh-common`, `mssh`, `msshd`, `mssh-ca`, `mssh-admin`) |
| 9 | Migration story doc | [docs/MIGRATION.md](../../docs/MIGRATION.md) |
| 12 | MCP interface to CA | v1 read-only as `mssh-mcp` (mssh-admin wheel, `[mcp]` extra) |
| 14 | Tutorial / walkthrough doc | [docs/TUTORIAL.md](../../docs/TUTORIAL.md) |
| 15 | `install_mssh` installer | [scripts/install_mssh.sh](../../scripts/install_mssh.sh) (217 LOC) |

Items still in `design/future-ideas.md`:
  - PARTIAL: §8 (`~/.mssh/`), §11 (debug_sshd swap-in), §17 (banner)
  - NOT STARTED: §2, §4, §5, §6, §7, §10, §13, §16, §18, §19, §20, §21, §22, §23, §24

---

## 1. Per-connection ephemeral inner sshd

**Status:** **Landed.** Per-host `inner.mode: long-lived | per-connection`
ships in msshd today; CA-side config rendering with `{LOCAL_*}` /
`{FROMCA_*}` marker grammar; emergency-template recovery path for
CA-unreachable break-glass; protocol-version handshake on every
authorize call. Default for new installs is `long-lived` and will
flip to `per-connection` after one stable release cycle. Tracked
as design now in [`design/architecture.md` § Hermetic inner sshd](architecture.md#hermetic-inner-sshd)
and [`design/ca.md`](ca.md) (CA-side template store + render
contract). Original plan archived at
[`archive/design/mssh-per-connection-inner-sshd-plan.md`](../archive/design/mssh-per-connection-inner-sshd-plan.md).

Notes preserved below for design-rationale value.

### Idea

Today msshd runs **one** long-lived inner sshd whose config is
hermetic and identical for every session. Policy that OpenSSH config
could natively express (force-command, environment, channel-allow,
etc.) is either disabled globally in the hermetic config or
re-enforced by msshd at the application layer.

Per-connection sshd inverts this: spawn a **fresh sshd-on-pipes per
session**, with a config rendered from the CA's authorization cert.
Each cert extension becomes a directive in that session's sshd_config.

```
Outer mTLS accept
  │
  ├── CA call → authz cert with policy extensions
  ├── Mint inner OpenSSH user cert (unchanged)
  ├── Render per-session sshd_config from the cert's policy:
  │     mssh-force-command       → ForceCommand
  │     mssh-environment         → SetEnv (multiple)
  │     mssh-channel-policy      → AllowTcpForwarding / X11Forwarding / etc.
  │     mssh-max-session         → ClientAliveCountMax + ClientAliveInterval
  │   …plus the hermetic-config bones (crypto floor, no PAM, etc.)
  ├── Open pipe pair (or socketpair)
  ├── Spawn  sshd -i -f /tmp/session-XXX.conf  with pipes as stdin/stdout
  └── Proxy bytes between outer TLS and the pipe
       Connection close → sshd exits.
```

OpenSSH's `-i` (inetd) mode is the key: sshd handles a single
connection on stdin/stdout and exits. No port allocation, no listener
thread, no monitor process for us to manage.

### Wins

- **Native enforcement of every policy extension OpenSSH can express.**
  `mssh.msshd.policy.translate_to_inner_cert_kwargs()` shrinks to
  one line (or disappears). The "what does msshd enforce vs
  what does OpenSSH enforce" boundary moves entirely into OpenSSH.
- **Per-session resource isolation.** A bug in one ForceCommand, a
  buggy sftp-server, a leaked file descriptor — none of it affects
  other sessions.
- **No port management.** Pipe pair instead of `49152-65535`.
- **Mental model is clean.** "sshd is the session-implementation
  engine msshd hands a config and a connection to."

### Cons / open questions

| Concern | Estimate | Mitigation                               |
|---|---|---|
| Memory per session | ~5–7 MB (sshd + sshd-session) | Fine for servers, costly for embedded. Document the cap as ops guidance; expose a `max_concurrent_sessions` limit. |
| Startup latency | ~50–100 ms | Imperceptible for interactive shells; could matter for burst exec / sftp-of-many-small-files workloads. Acceptable for v1 of the change. |
| Process tracking | Medium | `asyncio.create_subprocess_exec` + a registry of children + reap-on-exit. ~50 LOC. |
| `/run/sshd` & host keys | Shared across all instances | No change needed beyond what we already do. |
| Config file lifecycle | Tempfile per session | Render, spawn, unlink after sshd's open. ~10 LOC. |
| Per-version sshd_config validity | Same as today — hermetic template must work for the running OpenSSH version | Per-version hash table in [detailed-wrapper.md §5.3](architecture.md) becomes "validate the TEMPLATE against an embedded known-good; the rendered output varies per-session and isn't hash-verifiable directly." |

### What this does NOT solve

- **CVE-response responsibility is unchanged.** Per-connection still
  uses the distro's sshd binary. The wrapper picks up CVE fixes
  faster (next *connection* rather than next wrapper *restart*), but
  it's still the distro's responsibility, not ours.
- **Version drift across the fleet** is the same as today — each
  wrapper host runs whatever sshd the distro installed.

### Migration plan when this gets built

1. Add `inner.mode: long-lived | per-connection` to `wrapper.yaml`.
   Default keeps the current model.
2. Phase 1 of the change: implement `per-connection` mode; existing
   `long-lived` keeps working. Test both side-by-side.
3. After at least one release cycle of stable `per-connection` use,
   default it on for new installs (existing installs keep the long-
   lived default until explicit migration).
4. Eventually deprecate `long-lived` mode? Possibly never — it has a
   legitimate place for high-frequency-connection workloads where
   the 50–100 ms startup is unacceptable.

### LOC estimate

~300 LOC in msshd: pipe handoff, per-session config renderer,
process registry, lifecycle hooks. Reuses everything we have today
for cert minting / outer protocol / CA call.

---

## 3. Client / server split — **mostly done; common-protocol piece remains**

**Status:** Substantially superseded by the 2026-05-15 project reorg.
The top-level language directories (`python/`, `go/`, `c/`) replaced
the original `wrapper/<lang>/` shape. Each language tree now owns the
full client+server+CA implementation. The remaining piece is the
**shared protocol module** described below.

### What's done

The reorg established:

- `python/src/mssh/msshd/` — wrapper server (Python).
- `python/src/mssh/mssh.py` — wrapper client (Python).
- `python/src/mssh/ca/`, `admin/`, `shim/` — supporting Python pieces.
- `go/` and `c/` skeleton directories with READMEs documenting the
  same layout per language.

Operators can already package and update client and server independently
within Python (the client is a single module, the server is a
sub-package). The client doesn't pull in server dependencies at
runtime because `mssh` doesn't import from `msshd/`.

### What still remains: a shared protocol module

The v1 outer-protocol frame format (JSON header + raw bytes) is
implemented twice today:

- `python/src/mssh/mssh.py:build_header()` / `parse_ack()`
- `python/src/mssh/msshd/ssh_proxy.py:_read_header_line()` / `_write_ack()`

These two implementations have to stay byte-for-byte compatible
forever. A drift-detection bug between them would silently break
authentication. Today the test suite catches it because both are
exercised end-to-end, but with more variants (Go client + Python
server, C client + Go server, etc.) the combinatorics get ugly.

**Proposed:** consolidate the frame definitions into a per-language
`common/` module:

```
python/src/mssh/common/
├── __init__.py
└── protocol.py     # PROTOCOL_VERSION, build_header, parse_header,
                    # build_ack, parse_ack
```

Both `mssh.py` and `msshd/ssh_proxy.py` import from
`mssh.common.protocol`. Drift becomes impossible because there's
one implementation.

Mirror for `go/` and `c/` when they exist:

- `go/internal/protocol/` — Go package, same frame format.
- `c/common/protocol.c` — C functions, same frame format.

Cross-language wire compatibility comes from **a single source of
truth in a spec doc** ([detailed-wrapper.md §3](architecture.md))
plus per-language unit tests that round-trip canonical encodings.
Consider adding a `protocol/conformance.json` with golden vectors
that every language's tests must produce identical output for.

### LOC estimate

~half a day for Python (extract two ~30-LOC helpers into a shared
module, update two import sites, add a unit test). Negligible for
future language ports — they just import from their own
`common/protocol`.

### Why this isn't urgent

Today there are only two implementations (both Python) and they're
small. The drift risk is real but the cost is also real. Wait until
either (a) the Go port starts, or (b) the protocol gains a new
revision that has to land in both sides.

---

## 9. Incremental SSH→mssh migration story (operational doc)

**Status:** **Landed** as [docs/MIGRATION.md](../docs/MIGRATION.md).
Remaining work captured under [[end-to-end-migration-test]] (§20) —
auto-generating the playbook from a real test run, so the runbook
never drifts from the implementation.

### Idea

The technical pieces for incremental migration already exist:

- Server side: [scripts/upgrade.sh](../scripts/upgrade.sh)
  runs msshd in fallback mode alongside system sshd, then
  graduates to enforce mode, then cuts over port 22.
- Client side: item 8 above puts the new config in `~/.mssh/`
  without touching `~/.ssh/`. Users keep `ssh` working until they
  flip.

What's missing is a **single operator-facing runbook** that ties both
sides together:

```
Day 0:  Install wrapper on the server. wrapper.yaml = fallback mode.
        ssh keeps working as before.

Day 1:  Enrol the test user at the CA. Install mssh on the test
        user's laptop. Verify mssh access works.

Day 7:  Enrol more users. Flip wrapper to enforce mode for one role.
        ssh still works for non-enforced roles via fallback.

Day 30: All users have validated mssh access. Cut wrapper port to
        22. Stop system sshd. Notify users to retire ~/.ssh/.

Day 60: Validate; cleanup any holdouts.
```

### What this doc would contain

- Pre-flight checklist (CA running, wrapper installed, etc.).
- Per-user onboarding script: enroll, mint their mTLS cert, push
  `~/.mssh/` material, smoke-test their access.
- Per-server upgrade script (already exists as upgrade.sh).
- Per-role enforce-toggling: flip one role at a time, validate, move
  on. Roll back per-role if a problem surfaces.
- Final cleanup: stopping system sshd, advising users to rm
  `~/.ssh/`, retention policy on old SSH server logs.

### LOC estimate

Zero code, ~1500 lines of operator-facing markdown. Should live as
`docs/MIGRATION.md` (peer to `INSTALLATION.md`) when it's written.

---

## 12. MCP interface to the CA — natural-language diagnostics + config

**Status:** v1 (read-only) is **landed** as `mssh-mcp`
(install via `pip install -e '.[mcp]'`). Exposes six tools:
`status`, `server_list`, `user_list`, `user_inspect`,
`audit_search`, `admin_list`. Wraps the existing `mssh-admin`
admin-client config — the same `~/.mssh-admin/config` that the
CLI uses. See [docs/operations.md § MCP interface](../docs/operations.md)
for setup.

What's not done: the `trusted_write` mode (server_add, user_add,
policy_add, key-rotate, …). Write tools carry a trust delegation
that needs its own design conversation — multi-person bootstrap,
per-admin opt-in flags in enrollment, audit annotation
(`actor: mcp:<admin_subject>`), optional interactive approval
flow on the admin's terminal. Not v1.

### Idea

Expose the CA over an [MCP](https://modelcontextprotocol.io)
(Model Context Protocol) server so that an AI assistant (Claude,
or any other MCP-compatible agent) can:

  - **Read-only diagnostics:** "why was alice denied last Tuesday?",
    "show me every policy that grants access to srv-acct",
    "what's the most-recently-rotated server cert", "summarize the
    audit log for the last hour" — answered in natural language by
    querying the CA's enrollment + audit data through MCP tools.
  - **Trusted-AI configuration:** with an admin-grade mTLS cert and
    explicit grant from the operator, the assistant can also enroll
    users, attach policies, or rotate certs — every change goes
    through the same admin API + audit log as a human admin's
    actions.

The CA already has the structured data (enrollment YAML + JSON-Lines
audit). MCP just exposes it as typed tools an LLM can call.

### Composition

Two MCP server modes, served from the same daemon:

  - `read_only`: enrollment-list, policy-explain, audit-search,
    cert-info. Available to any admin cert with `auditor` role.
  - `trusted_write`: above + server-add, user-add, policy-add,
    key-rotate. Requires admin cert with explicit `mcp_writable: yes`
    flag in enrollment. Every call audit-logged as
    `actor: mcp:<admin_subject>`.

### Wins

  - The CA's data model is the source of truth for "who can do what
    where." A natural-language interface to that data lowers the
    operational ceiling significantly.
  - Forensic queries on the audit log become trivial.
  - Bootstrapping a new CA / re-enrolling after a disaster becomes
    "describe the policy in English, AI translates and applies"
    rather than YAML-by-hand.

### Cons / open questions

  - Trusted-AI writes are a meaningful trust-delegation step.
    Probably opt-in per-admin and per-CA, never on by default.
    Should the operator be able to require an interactive approval
    step (CA prompts the admin's terminal for each `apply`?)
  - Audit-log volume going through MCP could be large; want pagination
    + query primitives, not just dump-everything.
  - Read-only mode is the obvious starting point. Write mode is a
    second milestone.

### LOC estimate

  - MCP server skeleton + tool definitions: ~400 lines.
  - Read-only adapters over enrollment/audit: ~200 lines.
  - Write adapters + role gating: ~300 lines.
  - Operator docs + per-tool descriptions for the LLM: small markdown
    investment.

---

## 14. Tutorial / walkthrough doc for the adhoc lab

**Status:** **Landed** as [docs/TUTORIAL.md](../docs/TUTORIAL.md).
Sections for unimplemented features (gated mode §6.5.1,
debug_sshd swap-in §11, legacy capture §13) are noted as "not yet"
in the tutorial; add exercises for each when those features land.

### Idea

The adhoc msshd lab already provisions Phase 0 → 1 → 2 with operator
flip scripts and a per-user README. Promote it to a **published
walkthrough** that demonstrates every mssh feature: the CA call, the
ephemeral inner cert, channel policy, source-CIDR, audit, the flip
scripts, debug_sshd swap-in (once §11 lands), the gated mode (once
§6.5.1 lands), the legacy-capture+dual-enforce (once §13 lands).

This is mostly an **operational doc effort**, not new code:
`docs/TUTORIAL.md` (or similar), walking the reader through running
the lab, observing each behavior, and explaining what the operator
would do at the equivalent step in a real adoption. Cross-link from
the README so newcomers have a guided entry point.

The tutorial reuses the adhoc lab as its sandbox — no separate
infrastructure needed. The lab's `ADHOC_TEST_ENV.md` is the seed
content for the tutorial's "Setup" section; the rest is per-feature
exercises.

### LOC estimate

  - ~2000 lines of operator-facing markdown.
  - Zero code, **assuming** the features it demonstrates (gated,
    legacy capture, sideband audit, MCP) are already implemented.
    Otherwise the tutorial's scope shrinks to whatever's available.

---

## 15. `install_mssh` — distro-style installer + BYO-container adhoc lab

### Idea

Replace the adhoc lab's LXC-specific source-push with a portable
**install script** that simulates `apt install mssh msshd` as if it
were a real distro package. The script does:

  - Install Python + venv on the target machine
  - Install the mssh + msshd packages (from a pre-built tarball)
  - Lay down systemd units for `msshd` (and the CA, where relevant)
  - **Does NOT enable** anything — leaves the operator to configure
    `wrapper.yaml`, enroll at the CA, and `systemctl enable msshd`
    when they're ready.

The adhoc lab becomes provisioner-agnostic. The test author spins
up containers however they want (LXC, Docker, VirtualBox, k8s, a
fleet of bare VMs, an SBC cluster on the desk), runs `install_mssh`
on each, and the rest of the lab (enroll, configure, flip modes)
proceeds over ssh exactly as it would in production.

### Composition

  - Single tarball: `mssh-<version>.tar.gz` containing the Python
    source, install script, systemd units, default config templates.
  - `install_mssh.sh <tarball>`: idempotent. Verifies prereqs
    (python3, openssl, openssh-server), creates a system user
    (`msshd`), installs into `/opt/mssh/`, drops systemd units in
    `/etc/systemd/system/` (disabled). Outputs the post-install
    checklist (enroll at CA, edit wrapper.yaml, enable).
  - Per-distro shims for `apt-get install` vs `apk add` of system
    deps (openssh-server, python3, openssl) wrapped behind a small
    detection step at the top of `install_mssh.sh`.

### Wins

  - **Adhoc lab is no longer LXC-specific.** Bring any container or
    VM; run the install script; join it to the CA.
  - **Documents the production install path.** The install script
    IS what `apt install mssh msshd` will eventually run. Operators
    who don't want a package can run it directly.
  - **Tutorial story improves.** "Here's a clean Ubuntu VM. Run
    `install_mssh`. Now enroll it at the CA. Now ssh as alice."
  - **Test surface contracts.** The lab's setup code stops being
    100+ lines of LXC-specific provisioning + `lxc file push` and
    becomes "spin up containers (your choice), then run the install
    script over ssh."

### Cons / open questions

  - The install script needs to handle distro variation gracefully.
    Ubuntu/Debian (`apt`), Alpine (`apk`), RHEL/Fedora (`dnf`),
    Arch (`pacman`). Start with Ubuntu + Alpine since those are the
    PoC's targets; extend later.
  - Versioning: the tarball needs a clear semver and the install
    script needs to refuse downgrades or warn on cross-version
    mismatch with the CA.
  - In the adhoc lab, who builds the tarball? Probably a small
    `make tarball` step at lab-startup time so the lab uses the
    in-tree source.

### Composes with

  - §11 (debug_sshd swap-in) — the install script lays down
    `debug_sshd` alongside the hermetic OpenSSH; the admin
    enables either as needed.
  - §13 (legacy capture + dual-enforce) — `install_mssh.sh`
    optionally runs `mssh-admin import` on the target before
    enrollment, so the CA starts with a migrated copy of the
    existing sshd policy.
  - §14 (tutorial doc) — the install script is the tutorial's
    onboarding step; the rest of the tutorial demonstrates what
    you do after `install_mssh` finishes.

### LOC estimate

  - `install_mssh.sh`: ~300 lines of bash with distro-detection.
  - Tarball assembly: ~50-line `make tarball` rule.
  - Adhoc-lab refactor to use the install script over ssh instead
    of `lxc file push`: ~200 lines net (mostly deletions).

---
