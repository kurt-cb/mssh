# test-scenarios.md

Catalog of test scenarios derived from a walk of every design + ops
doc. The input both to manual adhoc-testing rounds and to the
[static-test-plan.md](static-test-plan.md) Tier-2 layer.

Each scenario has:
- **ID** — stable handle for cross-reference
- **Description** — what the user/admin does
- **Expected** — what should happen
- **Source** — doc that describes this behavior
- **Status** — `untested`, `lab-verified`, `unit-covered`, or `broken`
- **Suggested tier** — where the regression test belongs

Status as of 2026-05-19 reflects round-1 findings (design/openbugs/ + archive/closedbugs/).

---

## A. User-side scenarios

These are what an end-user does on the mssh client side. They form
the bulk of regression risk: they're what users see, and they have
the highest blast radius if they regress.

### A1 — happy path: authorized mssh

| | |
|---|---|
| **Description** | `mssh user@server -- whoami` where user is policy-allowed for that server |
| **Expected** | exit 0, stdout `user`, <1s round trip with cached authz |
| **Source** | docs/operations.md § The adoption journey (Phase 3) |
| **Status** | lab-verified |
| **Suggested tier** | Tier 2 (regression) + Tier 3 (real lab smoke) |

### A2 — denied path: unauthorized mssh

| | |
|---|---|
| **Description** | `mssh user@server -- whoami` where user has no policy for that server |
| **Expected** | nonzero exit, stderr contains a clear "denied" message + reason category |
| **Source** | docs/operations.md § Common operator tasks (denied) |
| **Status** | **broken** — Bug #1 (currently prints "server closed before sending ack") |
| **Suggested tier** | Tier 2 (the fix lives in protocol + client renderer) |

### A3 — interactive PTY session

| | |
|---|---|
| **Description** | `mssh user@server` with no command; lands in a shell |
| **Expected** | TTY allocated; arrow keys / ctrl-C / signals work; `exit` ends session |
| **Source** | design/architecture.md § Wire protocols (`interactive: true` in header) |
| **Status** | untested (round-1 ran headless) |
| **Suggested tier** | Tier 3 (needs real PTY); may be approximable in Tier 2 via `pty` module |

### A4 — explicit force-tty / no-tty flags

| | |
|---|---|
| **Description** | `mssh -t user@server -- htop`, `mssh -T user@server` |
| **Expected** | `-t` forces PTY even when stdin isn't a TTY; `-T` suppresses PTY |
| **Source** | mssh --help, client.py:399-403 |
| **Status** | untested |
| **Suggested tier** | Tier 2 |

### A5 — long-running session

| | |
|---|---|
| **Description** | `mssh user@server -- 'sleep 30; echo done'` |
| **Expected** | command runs to completion, output arrives, no premature timeout |
| **Source** | implicit |
| **Status** | lab-verified at 5s (round-1) |
| **Suggested tier** | Tier 2 (parameterize over 1s/30s/60s) |

### A6 — large stdout (text)

| | |
|---|---|
| **Description** | `mssh user@server -- 'head -c 10M /dev/zero' \| wc -c` |
| **Expected** | exactly 10485760 bytes received |
| **Source** | implicit; failure mode is buffering |
| **Status** | lab-verified at 5MB (round-1) |
| **Suggested tier** | Tier 2 |

### A7 — large stdout (binary)

| | |
|---|---|
| **Description** | `mssh user@server -- 'head -c 1M /dev/urandom' \| sha256sum` cross-checked against local |
| **Expected** | byte-for-byte identical |
| **Source** | implicit; this was the Bug #5 finding |
| **Status** | broken-then-fixed — lab-verified after `encoding=None` fix |
| **Suggested tier** | Tier 2 (highest priority — regression smoking gun) |

### A8 — stdin pipe (text)

| | |
|---|---|
| **Description** | `echo hello \| mssh user@server -- cat` |
| **Expected** | remote `cat` echoes "hello", mssh exits 0 |
| **Source** | implicit; standard SSH-style usage |
| **Status** | **partially broken** — Bug #3, data flows after #5 fix, but stdin EOF doesn't propagate so the client hangs |
| **Suggested tier** | Tier 2 (xfail until protocol gets typed EOF) |

### A9 — stdin pipe (binary)

| | |
|---|---|
| **Description** | `cat /bin/ls \| mssh user@server -- 'wc -c'` |
| **Expected** | byte count matches `wc -c < /bin/ls` |
| **Source** | implicit |
| **Status** | broken — see Bug #3, Bug #5 fixed the data path but stdin EOF still hangs |
| **Suggested tier** | Tier 2 |

### A10 — remote exit code propagation

| | |
|---|---|
| **Description** | `mssh user@server -- false ; echo $?` |
| **Expected** | $? is 1 |
| **Source** | implicit; standard SSH semantics |
| **Status** | **broken** — Bug #2 (always 0) |
| **Suggested tier** | Tier 2 (xfail until protocol gets exit frame) |

### A11 — stdout / stderr separation

| | |
|---|---|
| **Description** | `mssh user@server -- 'echo o; echo e >&2' 2>/dev/null` should print only "o" |
| **Expected** | shells route stderr separately |
| **Source** | implicit; current docstring says merged |
| **Status** | **merged** — Bug #4 (acknowledged design) |
| **Suggested tier** | Tier 2 (codify current behavior to detect surprise changes) |

### A12 — concurrent sessions from same user

| | |
|---|---|
| **Description** | Three parallel `mssh user@server -- whoami` |
| **Expected** | all three complete cleanly, no serialization, no resource exhaustion |
| **Source** | architecture.md § hermetic inner sshd |
| **Status** | lab-verified (round-1) |
| **Suggested tier** | Tier 2 |

### A13 — repeat connection (cache hit)

| | |
|---|---|
| **Description** | Two sequential `mssh user@server -- whoami` |
| **Expected** | second is faster (cache hit; no CA call); CA audit log shows only one authorize call |
| **Source** | CLAUDE.md amendment 2026-05-18 (authz cache) |
| **Status** | lab-verified — ~200ms per call (round-1) |
| **Suggested tier** | Tier 2 (assert cache observable via CA log) |

### A14 — connect to unreachable IP

| | |
|---|---|
| **Description** | `mssh user@192.0.2.1:2200 -- whoami` (RFC 5737 docs prefix) |
| **Expected** | fails within 5–10 seconds with a "connect timed out" message |
| **Source** | implicit (UX); architecture.md § failure model |
| **Status** | **broken** — Bug #6 (hangs until kernel TCP timeout) |
| **Suggested tier** | Tier 2 |

### A15 — connect to wrong port

| | |
|---|---|
| **Description** | `mssh user@server:9999 -- whoami` (no listener) |
| **Expected** | clear "Connection refused" error |
| **Source** | implicit |
| **Status** | lab-verified (round-1) — message is good |
| **Suggested tier** | Tier 2 |

### A16 — wrong cert / cert mismatch

| | |
|---|---|
| **Description** | Present user A's cert while claiming username B |
| **Expected** | server denies with "identity mismatch" or equivalent; not a generic protocol error |
| **Source** | security.md § stolen mssh credential; architecture.md § JSON header |
| **Status** | round-1 saw the same "server closed before sending ack" — Bug #1 again |
| **Suggested tier** | Tier 2 |

### A17 — missing cert files

| | |
|---|---|
| **Description** | `mssh user@server` with `MSSH_CERT` pointing nowhere |
| **Expected** | clear error: "mssh: cert not found at <path>. Set MSSH_CERT=…" |
| **Source** | implicit (UX) |
| **Status** | lab-verified (round-1) — message is good |
| **Suggested tier** | Tier 2 |

### A18 — insecure-mode keyfile

| | |
|---|---|
| **Description** | `mssh user@server` with key file at mode 0644 |
| **Expected** | clear error before connect: "key has insecure permissions (mode=644). Run: chmod 0600 <path>" |
| **Source** | client.py:152-156 |
| **Status** | untested; code is there |
| **Suggested tier** | Tier 1 (pure unit) + Tier 2 (subprocess) |

### A19 — config file precedence

| | |
|---|---|
| **Description** | `mssh --config /path/to/cfg user@server`; settings in cfg override env-vars override defaults |
| **Expected** | documented precedence holds; same command outcome with same config |
| **Source** | mssh --help, default `~/.mssh/config` |
| **Status** | untested |
| **Suggested tier** | Tier 1 (unit on the config loader) |

### A20 — bypass cert injection (user flow)

| | |
|---|---|
| **Description** | `mssh --inject-bypass-cert /path/to/bypass.crt user@server` |
| **Expected** | msshd accepts, stores in authz_cache, acks, closes; subsequent `mssh user@server` works even with CA down |
| **Source** | CLAUDE.md amendment 2026-05-18 § CA-bypass cert |
| **Status** | untested (admin-mint side also untested) |
| **Suggested tier** | Tier 3 (needs admin path) |

---

## B. Admin-side scenarios

Driven from a workstation against the CA via `mssh-admin`. Read +
write paths. These typically require admin-grade mTLS creds.

### B1 — `mssh-admin status`

| | |
|---|---|
| **Description** | `mssh-admin status` shows deployment health |
| **Expected** | all ✓ on a fresh Phase-2 lab |
| **Source** | operations.md § check deployment state |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### B2 — `mssh-admin next`

| | |
|---|---|
| **Description** | `mssh-admin next` prints next adoption step |
| **Expected** | on a Phase-2 lab, says everything is done or shows the next thing |
| **Source** | operations.md § next |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### B3 — enroll a new server

| | |
|---|---|
| **Description** | `mssh-admin server add srv-new --groups testing` |
| **Expected** | mTLS cert + key returned exactly once; subsequent `server show` lists it |
| **Source** | operations.md § enrol a server |
| **Status** | untested |
| **Suggested tier** | Tier 3 (mid) — admin-creds + CA process |

### B4 — enroll a new user end-to-end

| | |
|---|---|
| **Description** | `mssh-admin user add eve; user key add eve --kind ssh-pubkey --blob …; policy add eve --server-groups testing`; then `mssh-as eve testing` should succeed |
| **Expected** | full enrollment → user can connect to authorized server within seconds |
| **Source** | operations.md § enrol a user, common tasks |
| **Status** | untested |
| **Suggested tier** | Tier 3 (multi-step) |

### B5 — revoke a user

| | |
|---|---|
| **Description** | `mssh-admin user del alice` then `mssh-as alice acct` |
| **Expected** | new connections denied within the cache TTL (default 1 min) |
| **Source** | operations.md § revoke a user immediately |
| **Status** | untested |
| **Suggested tier** | Tier 3 (uses timing; cache invalidation logic critical) |

### B6 — `mssh-admin audit` filtering

| | |
|---|---|
| **Description** | `mssh-admin audit --since '1 hour ago' --result denied` |
| **Expected** | JSON-Lines of matching entries on stdout |
| **Source** | operations.md § search the audit log |
| **Status** | untested |
| **Suggested tier** | Tier 1 (unit on the filter) + Tier 3 (live data) |

### B7 — admin cert rotation

| | |
|---|---|
| **Description** | `mssh-admin admin add bob-2026; mssh-admin admin del bob` |
| **Expected** | bob-2026 can authenticate to CA; bob cannot (CRL); audit shows the change |
| **Source** | operations.md § rotate an admin's cert |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### B8 — mint a bypass cert

| | |
|---|---|
| **Description** | `mssh-admin bypass-cert mint alice --pubkey alice.pub --valid-days 90 --out alice-bypass.crt` |
| **Expected** | file emitted; `mssh-admin bypass-cert show` lists it; cert chain validates |
| **Source** | CLAUDE.md amendment 2026-05-18; api.md § bypass cert mint |
| **Status** | untested |
| **Suggested tier** | Tier 3 (superuser-only path) |

### B9 — revoke a cert (CRL append)

| | |
|---|---|
| **Description** | `mssh-admin cert revoke <serial> --reason 'key rotation'`; then `mssh-admin crl list` |
| **Expected** | new CRL entry; msshd's `last_crl_seq` advances; subsequent connect to revoked principal denied |
| **Source** | CLAUDE.md amendment 2026-05-18 (b); api.md § cert revoke |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### B10 — server group changes

| | |
|---|---|
| **Description** | `mssh-admin server groups srv-acct --add ops --remove accounting` |
| **Expected** | next authorize call applies the new group membership |
| **Source** | operations.md § add a server to a group |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### B11 — policy CIDR restrictions

| | |
|---|---|
| **Description** | `mssh-admin policy add alice --server-groups eng --source-cidrs 10.0.0.0/8`; mssh from 10.x.x.x: allowed, from 192.x.x.x: denied |
| **Expected** | source-CIDR check fires at the CA, audit records denied_reason=policy_source_cidr |
| **Source** | api.md § policy management; operations.md § Add a user |
| **Status** | untested |
| **Suggested tier** | Tier 3 (network-dependent) |

### B12 — template management (per-connection inner sshd)

| | |
|---|---|
| **Description** | `mssh-admin template set …` per server/group; flip to per-connection mode; verify rendered config matches template |
| **Expected** | rendered sshd_config has CA-supplied policy directives |
| **Source** | architecture.md § hermetic inner sshd (per-connection mode) |
| **Status** | untested; user reports `flip_to_per_connection` reverts |
| **Suggested tier** | Tier 3 — first investigate the existing flip failure |

---

## C. Unexpected event / failure scenarios

### C1 — CA process down: cold cache

| | |
|---|---|
| **Description** | Stop mssh-ca; new principal tries to connect |
| **Expected** | deny within timeout; clear error: "CA unreachable" |
| **Source** | architecture.md § failure model |
| **Status** | untested in round-1 |
| **Suggested tier** | Tier 3 |

### C2 — CA process down: warm cache

| | |
|---|---|
| **Description** | Stop mssh-ca after alice has connected once; alice reconnects |
| **Expected** | cache hit → connect succeeds (within TTL) |
| **Source** | CLAUDE.md amendment 2026-05-18 § authz cache |
| **Status** | untested |
| **Suggested tier** | Tier 3 (timing-sensitive) |

### C3 — CA returns deny mid-cache

| | |
|---|---|
| **Description** | CA up, alice cached. Revoke alice. alice reconnects. |
| **Expected** | the CA-driven deny invalidates the cache entry |
| **Source** | CLAUDE.md amendment 2026-05-18 § authz cache (invalidation) |
| **Status** | untested |
| **Suggested tier** | Tier 2 (cache logic in isolation) + Tier 3 (real flow) |

### C4 — bypass cert injection during CA outage

| | |
|---|---|
| **Description** | CA down; `mssh --inject-bypass-cert alice-bypass.crt user@server` then `mssh user@server` |
| **Expected** | first call populates cache; second call succeeds offline |
| **Source** | CLAUDE.md amendment 2026-05-18 § bypass cert flow |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### C5 — flip while sessions are active

| | |
|---|---|
| **Description** | Start a long-running mssh session; flip msshd to fallback; the active session — and new connects — behavior? |
| **Expected** | active session unaffected (already through inner sshd); new connects use fallback mode |
| **Source** | operations.md § rolling back |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### C6 — flip to per-connection

| | |
|---|---|
| **Description** | `flip_to_per_connection` from the lab helpers |
| **Expected** | all servers flip; verify succeeds; per-session inner sshds spawn |
| **Source** | architecture.md § per-connection lifecycle |
| **Status** | **broken** — user reported all 4 servers FAIL — reverting |
| **Suggested tier** | first investigate; likely Tier 3 with a probe of the rendered config |

### C7 — clock skew

| | |
|---|---|
| **Description** | Set msshd's clock 15 minutes ahead of CA; alice connects |
| **Expected** | CA rejects with clock-skew error; not silent failure |
| **Source** | security.md § clock skew |
| **Status** | untested |
| **Suggested tier** | Tier 3 (env manipulation) |

### C8 — emergency cert path

| | |
|---|---|
| **Description** | CA down; per-connection mode with emergency cert configured |
| **Expected** | msshd renders emergency template, spawns sshd, alice can connect |
| **Source** | architecture.md § recovery when the CA is unreachable |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### C9 — disk-full on msshd state dir

| | |
|---|---|
| **Description** | Fill /var/lib/mssh; attempt to write authz_cache.json |
| **Expected** | clean error; cache becomes in-memory-only OR connections deny |
| **Source** | implicit; failure model says deny |
| **Status** | untested |
| **Suggested tier** | Tier 3 (env injection) |

### C10 — msshd config corrupt

| | |
|---|---|
| **Description** | wrapper.yaml has invalid YAML; restart msshd |
| **Expected** | msshd refuses to start, logs the parse error; no half-started state |
| **Source** | operations.md § msshd won't start |
| **Status** | untested |
| **Suggested tier** | Tier 1 (unit on config loader) |

### C11 — inner sshd refuses ephemeral cert

| | |
|---|---|
| **Description** | Force a clock-skew between msshd's user-CA and inner sshd's view; or break the user-CA pubkey pin |
| **Expected** | connection closed by inner sshd; msshd logs the inner's complaint |
| **Source** | architecture.md § failure model; operations.md § client allowed but inner refuses |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### C12 — replay of captured authorize

| | |
|---|---|
| **Description** | Capture an authorize call; replay it after the cert expired |
| **Expected** | second call gets a fresh cert with new validity; replay against inner sshd fails (expired) |
| **Source** | security.md § replay |
| **Status** | untested |
| **Suggested tier** | Tier 2 (CA-side) |

### C13 — network blip mid-session

| | |
|---|---|
| **Description** | Interactive mssh session; bring eth0 down on the server briefly |
| **Expected** | session terminates cleanly with a useful error |
| **Source** | implicit |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### C14 — two msshd instances same identity

| | |
|---|---|
| **Description** | Run two msshd processes claiming the same enrollment cert |
| **Expected** | both authorize against the CA; the CA logs both source IPs; no global lock |
| **Source** | implicit |
| **Status** | untested |
| **Suggested tier** | Tier 3 |

### C15 — CRL sequence reset

| | |
|---|---|
| **Description** | The CA's CRL log is wiped (operator error); msshd's `last_crl_seq` > CA's `current_crl_seq` |
| **Expected** | msshd detects inversion; logs warning; doesn't crash; either resets or refuses to advance |
| **Source** | CLAUDE.md amendment 2026-05-18 (b); archive/design/notes-bypass-cache.md |
| **Status** | untested |
| **Suggested tier** | Tier 1 (unit on the sync logic) |

### C16 — CRL strict-mode gate fires

| | |
|---|---|
| **Description** | Force `(known_ca_seq - last_applied) > crl_strict_threshold`; mssh user@server |
| **Expected** | msshd refuses cache hits; forces live CA call; threshold reset after catch-up |
| **Source** | CLAUDE.md amendment 2026-05-18 (b) § strict-mode gate |
| **Status** | untested |
| **Suggested tier** | Tier 2 |

### C17 — authz cache eviction-on-capacity

| | |
|---|---|
| **Description** | Inject > `authz_cache_max_total` entries via repeated authorize calls |
| **Expected** | FIFO eviction by `injected_at`; warning logged per evicted entry |
| **Source** | CLAUDE.md amendment 2026-05-18 (c) |
| **Status** | untested |
| **Suggested tier** | Tier 2 |

---

## D. Scope summary

**Total scenarios cataloged:** 47 (A: 20, B: 12, C: 17).

**Tier breakdown:**

| Tier | Scenarios | Notes |
|------|-----------|-------|
| Tier 1 (unit) | ~5 | Pure-Python isolated logic (config load, key parse, CRL sync) |
| Tier 2 (in-process integration) | ~25 | The bulk; achievable without LXC; runs in <30s aggregate |
| Tier 3 (full LXC lab) | ~17 | Multi-host, real-distro, network, timing |

**Currently covered (any tier):** A1, A5, A6, A7 (post-fix), A12, A13, A15, A17 — eight scenarios. **40 out of 47 untested.**

**Highest-risk gaps (currently broken AND no test):** A2 (denial UX), A8/A9 (stdin EOF), A10 (exit code), A14 (connect timeout), C6 (per-connection flip).

---

## E. Ordering for round-2 manual testing

Run these in order; stop at the first session-rebooting blocker.
Each batch validates one design assumption.

1. **Re-verify round-1 fixes hold** in the new lab: A7, A8 data, A12.
2. **Admin baseline:** B1, B2 (status, next).
3. **Admin write paths:** B4 (full user enroll), B5 (revoke), B6 (audit query).
4. **Mode flip stability:** C5 (flip-during-session), C6 (per-connection — known broken; probe).
5. **Failure injection:** C1 (CA cold), C2 (CA warm-cache), C3 (revoke-cache invalidate).
6. **Bypass cert end-to-end:** B8 then A20 then C4.
7. **CRL flow:** B9 then C15.
8. **Banner customization:** operations.md § customize banner — render, restart, verify in connect.

Append findings to design/openbugs/ + archive/closedbugs/; append learnings to adhoc-learnings.md.
