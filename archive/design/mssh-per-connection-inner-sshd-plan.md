# Implementation plan: per-connection ephemeral inner sshd (future-ideas §1)

**Archived implementation plan.** This document captured the design + plan
that drove the implementation of per-connection inner sshd, per-session CA
rendering, and the emergency-template recovery path. It is preserved here
for traceability of design decisions; the **canonical current spec** lives
in:

  - `design/architecture.md` — the architectural model
  - `design/ca.md` — the reference CA + messaging schema
  - `design/api.md` — wire protocol contracts
  - `design/security.md` — threat model

If you're implementing or re-implementing the system (e.g., the Go or Rust
port), use those files. This plan is history.

---

## Context

Today, `msshd` in enforce mode runs **one long-lived inner `sshd` subprocess** that handles every authorized session. The hermetic `sshd_config` is rendered once at msshd startup; per-session policy that OpenSSH could natively express (`ForceCommand`, `SetEnv`, `AllowTcpForwarding`, banners with user / server context, etc.) is either disabled globally or re-enforced at the wrapper application layer via [`python/src/mssh/msshd/policy.py`](../../python/src/mssh/msshd/policy.py).

This design has three real costs:

1. The application-layer policy translator is a moving target — every policy extension means new code in `policy.py`.
2. The per-user banner (future-ideas §17 v2) is structurally blocked — a long-lived sshd shares one Banner file across all sessions.
3. The "hash-validate the rendered config against per-OpenSSH-version baselines" framing inherited from the PoC era doesn't fit the clean-room mssh design. It's documented in [`design/architecture.md`](../../design/architecture.md) and `config/sshd_config.template`'s header, but **the validation is not implemented** ([`python/src/mssh/msshd/inner.py:215-225`](../../python/src/mssh/msshd/inner.py#L215-L225) does plain string substitution, no hashing). Adding the hash baseline would be solving the wrong problem.

Per-connection inner sshd inverts the model: msshd spawns a fresh `sshd -i` (inetd mode) per session, with a config rendered for that exact session's policy. OpenSSH enforces policy natively; the translator collapses; per-user banner becomes trivial.

The architectural insight that shaped this plan: the **CA should produce the rendered `sshd_config`**, not msshd. msshd becomes a substitution engine for its own local paths (~10 LOC of substitution) and the process-lifecycle owner. Policy translation moves to the CA. Cross-implementation (dropbear) becomes natural — the CA emits whatever syntax matches the inner sshd kind. msshd has zero opinion about the config content.

## Locked-in architectural decisions

(From the discussion before writing this plan.)

| Aspect | Decision |
|---|---|
| **Rendering** | CA-side, end-to-end. The CA's authz response carries a fully-rendered `inner_sshd_config` string. |
| **Templates** | Stored at the CA. Precedence: per-server > per-server-group > fleet-default > built-in shipped default. |
| **Operator template UX** | `mssh-admin template show/edit/set/unset/diff` against the CA store. `$EDITOR` integration. No local override on msshd hosts — per-host special cases go through CA-side per-server templates. |
| **msshd's only render work** | Substitute `{LOCAL_*}` markers (port, host-key path, banner-file path, user-CA pubkey path) — paths msshd already knows. ~10 LOC. |
| **Integrity** | (a) msshd runs `sshd -t -f config` as a sanity check before the real spawn; (b) CA-side property tests on its renderer; (c) protocol-version handshake on the authz call. No per-OpenSSH-version hash baseline. |
| **`policy.py`** | Shrinks. The X.509-extensions-to-cert-critical-options translation moves to the CA. msshd's `policy.py` becomes ~30 LOC of "deserialize the authz response into the renderer's input." |
| **Inner-sshd kind + version** | Sent in every authz request. CA uses them to pick the right template variant and refuse to emit unsupported directives. |
| **Per-host mode (`long-lived` vs `per-connection`)** | A per-server enrollment field at the CA. msshd reads it at startup. Local wrapper.yaml can override for CA-unreachable bootstrap. |
| **Default for first release** | `long-lived` on new installs. Operators opt into `per-connection` per server via `mssh-admin server set --inner-mode per-connection`. Flip default after one stable release cycle. |
| **Cross-implementation (dropbear, etc.)** | CA stores per-`inner_sshd_kind` templates. Out of v1 scope; the data model accommodates. |
| **`{EVERYTHING_FROM_CA}` catch-all marker** | Moot — the CA emits the whole file. No catch-all needed at the marker layer. |
| **Logging** | sshd stderr captured by msshd, re-emitted to msshd's log/journal with `[session=<id>]` prefix. |
| **Tempfile visibility** | Keep `state_dir/sessions/<id>/sshd_config` until sshd exits, then `rmtree`. Mode 0700 on dir, 0600 on file. Cleanup at msshd startup catches any leak from crashes. |
| **Connection handoff** | `socketpair()` + `sshd -i`. No TCP localhost / port allocation. |
| **Backpressure** | Refuse new mTLS connections at the cap (`performance.max_concurrent_sessions`, default 200). Cleaner audit story than CA-authorize-then-fail. |
| **Versioning** | Protocol version in every authz request/response. `mssh-admin status` and `next` surface CA + msshd + inner-sshd versions per host. |
| **v1 scope** | Full vertical slice — CA template store, mssh-admin commands, authz API field, msshd per-connection path, sanity check, versioning, status integration. |

## Recovery when the CA is unavailable

A CA-renders-the-config model has an obvious hole: if the CA is unreachable, where does msshd get a config? **Recovery cannot depend on the CA being up, and therefore cannot depend on a CA-supplied template.** Two recovery layers, distinct mechanisms:

### Layer 1 — `mode: fallback` (the existing escape hatch, unchanged)

This is the operator's primary "the CA is broken, I need access" path. msshd flips from `enforce` → `fallback` via a single line in `wrapper.yaml`, becomes a transparent TCP proxy to the operator's system `sshd` on port 22, and the system sshd handles auth via `authorized_keys`. **No inner sshd is involved in fallback mode**, so there is no config-rendering question at all.

This mode is unchanged by this design. It remains the recommended first-line recovery: trip the wrapper.yaml flag, system sshd takes over.

### Layer 2 — the **emergency template** (new, paired with the existing emergency cert)

For deployments where falling back to system sshd on port 22 isn't viable (port 22 blocked at the firewall, system sshd intentionally disabled, etc.), the existing **emergency cert** mechanism ([`design/security.md` § emergency cert](../../design/security.md#emergency-cert)) provides a long-lived offline-minted authz cert that msshd can use without calling the CA. Today this is provisioned + advertised but inactive in the per-connection redesign because the rendered config comes from the CA. This plan adds a paired artifact:

- **`/usr/share/mssh/sshd_config.emergency.template`** (shipped with mssh, never modified at the CA): a self-contained, hardcoded-safe-defaults template with **no `{FROMCA_*}` markers** — only `{LOCAL_*}` paths msshd substitutes locally. Lockdown defaults: `ForceCommand none`, all forwarding `no`, `PermitRootLogin no`, etc. Identical safety posture to today's hermetic config.
- **`/etc/mssh/sshd_config.emergency.template`** (optional local override): the operator can drop a customized emergency template here if they want stricter or looser defaults for break-glass. Validated at msshd startup (parse + `sshd -t`); refuse to start on syntax error.

The decision logic in `enforce_listener` per session:

```
1. Try CA authorize via mTLS.
2a. CA responds with inner_sshd_config → use it.
2b. CA unreachable + emergency cert valid + emergency mode opted-in:
        → load emergency template
        → substitute {LOCAL_*}
        → use the emergency cert's principals + extensions as the inner OpenSSH cert
        → rate-limit the emergency path (per security.md: minutes per use)
        → audit the emergency-mode session prominently
2c. CA unreachable + no emergency cert (or opt-out) → deny session. Operator's path: flip wrapper.yaml to mode: fallback or fix the CA.
```

The emergency template is the **only** local template artifact in the design. The "regular" per-session template stays at the CA. They're distinct files with distinct purposes:

| Template | Location | Used when | Substitutions |
|---|---|---|---|
| Regular | CA enrollment store | CA reachable, session being authorized normally | `{FROMCA_*}` (CA) + `{LOCAL_*}` (msshd) |
| Emergency | `/usr/share/mssh/` + optional `/etc/mssh/` override | CA unreachable + emergency cert valid | `{LOCAL_*}` only |

This preserves the user's "templates live at the CA" principle for the normal path while giving operators a real recovery story.

### What the emergency template ships with

```
# /usr/share/mssh/sshd_config.emergency.template
# Shipped with mssh. Safe-by-default; used only when CA is unreachable
# and an emergency cert has been provisioned. Operator may override at
# /etc/mssh/sshd_config.emergency.template — but the override must
# pass `sshd -t` at msshd startup or msshd refuses to start.

Port              {LOCAL_PORT}
HostKey           {LOCAL_HOST_KEY}
TrustedUserCAKeys {LOCAL_USER_CA_PUBKEY}
Banner            {LOCAL_BANNER_FILE}

# Authentication — pinned, identical to today's hermetic config.
PermitRootLogin              no
PasswordAuthentication       no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
GSSAPIAuthentication         no
HostbasedAuthentication      no
PermitEmptyPasswords         no
UsePAM                       no
AuthenticationMethods        publickey
PubkeyAuthentication         yes
AuthorizedKeysFile           none
AuthorizedKeysCommand        none
AuthorizedPrincipalsFile     none

# Conservative defaults — no per-session policy in emergency mode.
ForceCommand              none
AllowTcpForwarding        no
X11Forwarding             no
AllowAgentForwarding      no
PermitUserEnvironment     no
PermitTunnel              no
AllowStreamLocalForwarding no
GatewayPorts              no

# Crypto floor — same as today.
KexAlgorithms             curve25519-sha256,curve25519-sha256@libssh.org
Ciphers                   chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs                      hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms         ssh-ed25519
PubkeyAcceptedAlgorithms  ssh-ed25519

LogLevel       VERBOSE
SyslogFacility AUTH
```

`mssh-admin status` surfaces emergency-mode state per host (last-used timestamp, count this hour, etc.) so operators always know whether they're in degraded mode.

### Verification additions

The verification section gains:

- **Emergency-path integration test**: provision an emergency cert in the lab, simulate CA unreachable (firewall the CA's port at the LXC level), establish an mssh session, verify it goes through the emergency template + emergency cert path, verify the audit log records the degraded session.
- **Emergency template `sshd -t` gate**: write a deliberately broken local emergency template at `/etc/mssh/sshd_config.emergency.template`, verify msshd refuses to start with a clear error pointing at the broken file.
- **Rate-limit honored**: fire 10 emergency sessions in a second, verify only the rate-limit allows go through; the rest are denied with a clear "emergency rate limit" reason.

## Implementation plan

### Phase 1 — CA-side template store + renderer

**Files: new + modified**

| Path | Change |
|---|---|
| `python/src/mssh/ca/templates.py` *(new)* | Template store: `get_effective_template(server, group, kind, version)`. CRUD for fleet-default / per-server-group / per-server. Persists to a new section in `enrollment.yaml`. |
| `python/src/mssh/ca/render.py` *(new)* | The renderer. Takes (template, policy, local_paths_placeholders, inner_sshd_kind, inner_sshd_version). Emits final string. Property-test it. |
| `python/src/mssh/ca/enrollment.py` *(modify)* | Schema additions: `inner_mode`, `inner_sshd_kind` (per-server); `template` (per-server / per-group / default). |
| `python/src/mssh/ca/authorize.py` *(modify)* | Append `inner_sshd_config`, `banner`, `protocol_version` to the authz response. Accept `inner_sshd_kind`, `inner_sshd_version`, `msshd_version`, `protocol_version` on the request. |
| `python/src/mssh/admin/main.py` *(modify)* | Add `template` Click group with `show`, `edit` ($EDITOR), `set`, `unset`, `diff` subcommands at fleet / server-group / server scope. |
| `python/src/mssh/admin/client.py` *(modify)* | Methods for the new template endpoints. |
| `python/src/mssh/admin/state.py` *(modify)* | `status` walks the template-validation state per server (calls the CA's validator), surfaces version mismatches. |
| `config/sshd_config.template` *(modify)* | Convert to the new marker form. This file moves to being the CA's *shipped fleet-default template*, not the file msshd reads at runtime. |
| `python/tests/test_ca_render.py` *(new)* | Property tests over `render()`: every policy field combination, injection-defense (`\n` / `\r` rejected), unknown markers reported, OpenSSH version compatibility per directive. |
| `python/tests/test_admin_templates.py` *(new)* | CRUD + diff + show/edit flow tests. |

### Phase 2 — msshd per-connection mode

**Files: new + modified**

| Path | Change |
|---|---|
| `python/src/mssh/msshd/inner.py` *(major rewrite)* | Two paths: `long_lived` (today's class, refactored / minimal change) and `per_connection`. The latter exposes `start_session(session_id, rendered_config, banner_text, socketpair_fd) -> SessionProc`. Sanity-check via `sshd -t -f config` before spawn. Manages process registry + reaper + cleanup. |
| `python/src/mssh/msshd/config.py` *(modify)* | Add `inner.mode: long-lived | per-connection`. Default `long-lived`. Validation. |
| `python/src/mssh/msshd/msshd.py` *(modify)* | At startup: pull per-server inner-mode from the CA enrollment (override `inner.mode` with whatever the CA says, fall back to wrapper.yaml). Pass `inner_sshd_kind`, `inner_sshd_version` (detected once via `sshd -V`), `msshd_version`, `protocol_version` on every authz call. |
| `python/src/mssh/msshd/enforce_listener.py` *(modify)* | On accept: open socketpair, call CA authorize. **On success**: get `inner_sshd_config` + `banner` from response, substitute `{LOCAL_*}` markers, write per-session tempdir, `sshd -t` sanity check, spawn `sshd -i`, proxy. **On CA unreachable**: if emergency cert valid + emergency-mode opted-in, fall through to `emergency.py`. Otherwise deny. On session close: reap, rmtree the tempdir. Backpressure at the cap. |
| `python/src/mssh/msshd/emergency.py` *(new)* | The emergency-path renderer. Loads `/etc/mssh/sshd_config.emergency.template` if present, else the shipped `/usr/share/mssh/sshd_config.emergency.template`. Substitutes `{LOCAL_*}` only. Validates via `sshd -t -f config` at msshd startup (refuses to start on syntax error). Per-session: hands the rendered config to `enforce_listener` together with the emergency cert's principals. Rate-limit + prominent audit per [security.md § emergency cert](../../design/security.md#emergency-cert). |
| `config/sshd_config.emergency.template` *(new)* | The shipped fallback template (content shown in "Recovery" section above). Installed to `/usr/share/mssh/` by `install_mssh.sh`. |
| `python/src/mssh/msshd/policy.py` *(strip)* | Most of the X.509-extension parsing collapses to "deserialize the authz response's `inner_sshd_config` and `banner` strings." ~200 LOC → ~30 LOC. |
| `python/src/mssh/msshd/inner_logging.py` *(new)* | sshd stderr capture + session-id-tagged re-emission to msshd's log. |
| `python/tests/test_msshd_per_connection.py` *(new)* | Integration tests: spawn 10 concurrent sessions, verify isolated tempdirs / configs / banners; one session crash doesn't affect others; reaper handles SIGCHLD; cleanup-on-startup wipes leaked dirs from a previous crash; backpressure refuses at the cap. |
| `python/tests/test_msshd_emergency.py` *(new)* | Emergency-path tests: emergency template renders correctly with `{LOCAL_*}` substituted; broken local override at `/etc/mssh/sshd_config.emergency.template` causes msshd startup to fail loudly; rate-limit honored; emergency sessions get the expected audit annotation. |

### Phase 3 — versioning + status surface

| Path | Change |
|---|---|
| `python/src/mssh/__init__.py` *(modify)* | `__version__` stays; add `PROTOCOL_VERSION = '1.1'` constant exported. |
| `python/src/mssh/admin/state.py` *(modify)* | Status checks include "every msshd reachable at protocol ≥ CA's minimum." Pulls per-msshd version from the CA's `last_seen` audit data. |
| `python/src/mssh/ca/server.py` *(modify)* | New endpoint `GET /v1/admin/msshd/versions` returning the last-seen `{kind, version, protocol_version}` per enrolled server. |
| `python/src/mssh/ca/audit.py` *(modify)* | Record `inner_sshd_kind`, `inner_sshd_version`, `protocol_version` on every authorize entry. |

### Phase 4 — LXC adhoc lab + tutorial updates

| Path | Change |
|---|---|
| `python/tests/lxc/test_setup_only_msshd.py` *(modify)* | After the existing phases, add a Phase 2.5 that flips one server (e.g. `srv-acct`) to `inner.mode: per-connection`. Verify a session works with per-user banner substitution. Pull diagnostics in both modes. |
| `docs/TUTORIAL.md` *(modify)* | Add an exercise: flip a server to per-connection, observe the per-session sshd_config in `state_dir/sessions/`, see per-user banner. |
| `docs/operations.md` *(modify)* | New subsection: per-host inner-mode policy. `mssh-admin server set --inner-mode per-connection`. |
| `design/future-ideas.md` *(modify)* | Mark §1 landed. Mark §17 v2 (per-user banner) unblocked. Note `policy.py` simplification. |

## Verification

End-to-end:

1. **Unit tests**: `pytest --ignore=tests/lxc` passes; the new `test_ca_render.py`, `test_admin_templates.py`, `test_msshd_per_connection.py` all pass; existing 175+ tests unbroken.
2. **Property tests on the renderer**: 1000+ generated (policy, kind, version) tuples through `render()`; no injection escapes; unknown markers reported; rejected on `\n`/`\r` in directive slots.
3. **`sshd -t` sanity check**: synthesize a deliberately broken config, verify msshd refuses to spawn the real sshd and surfaces the syntax-check failure.
4. **Lifecycle integration test**: spawn 10 concurrent sessions in per-connection mode, kill 1 with SIGKILL, verify the other 9 keep working and the killed session's tempdir gets cleaned up; verify no zombies in `ps`.
5. **Backpressure test**: configure max_concurrent_sessions=3, fire 5 connections, verify connections 4 and 5 get refused at the TLS layer with a clear "max sessions reached" log.
6. **LXC adhoc lab**: `pytest tests/lxc/test_setup_only_msshd.py -v -m setup_only_msshd` passes in both `long-lived` and `per-connection` modes (matrix the test on inner mode).
7. **Performance gate**: a benchmark script that establishes 100 sequential connections in per-connection mode, asserts p99 ≤ 300ms (interactive-shell-class gate; tighter gates are per-policy at the CA).
8. **`mssh-admin status` against the running lab**: shows CA version, every msshd's version, inner_sshd kind/version. All green when fleet is consistent; flagged when out-of-sync.
9. **Banner substitution**: in per-connection mode, configure a per-server banner with `{user}` and `{server}` markers; verify alice sees "alice on srv-acct" and bob sees "bob on srv-acct".

## Risks + open questions

- **CA-side rendering load**: every authorize call now does template substitution + injection-defense + a possible dry-render check. ~1ms per call extra. Acceptable but worth measuring at scale.
- **Migration story for existing operators**: a fleet running today's `long-lived` mode keeps working unchanged when upgrading to the release that adds per-connection support. The new wrapper.yaml field has a safe default. No flag-day.
- **CA template store schema migration**: `enrollment.yaml` grows new sections. Existing CAs need a one-time migration on first start under the new code. The migration is idempotent and additive; existing fields stay.
- **inner_sshd_kind: openssh only in v1**. dropbear and others stay out of scope until there's a concrete consumer ask. The CA's template store accepts the field but emits an error if a non-openssh value is set.
- **What happens if the CA is at a newer protocol than msshd?** msshd refuses the session with `protocol_too_old`. Operator upgrades msshd. Documented in operations.md.

## Estimated effort

| Phase | LOC (code + tests) | Time |
|---|---|---|
| 1 — CA-side renderer + template store + admin CLI | ~600 | 5–7 days |
| 2 — msshd per-connection path | ~450 | 4–6 days |
| 3 — versioning + status surface | ~150 | 1–2 days |
| 4 — LXC tests + docs | ~250 | 2–3 days |
| **Total** | **~1450** | **2–3 weeks focused** |

Roughly 1 dev for ~3 weeks, or 2 devs splitting CA-side (phase 1) and msshd-side (phase 2) in parallel for ~1.5 weeks.
