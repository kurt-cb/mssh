# adhoc-bugs.md

Bugs found during adhoc user-simulation testing of the mssh lab. Each
entry records the user-side action that triggered it, what was expected,
what happened, and the disposition (fixed / flagged / open).

**Session prefix:** `claude-iuMW`
**Date:** 2026-05-19
**Tester:** Claude (autonomous-explorer mode, user-side flows)
**Lab state at start:** Phase 2 enforce, long-lived inner sshd

## Summary

| # | Bug | Severity | Disposition |
|---|-----|----------|-------------|
| 1 | Denials surface as "server closed before sending ack" — no reason, looks like a network error | UX | **Architectural** — needs deny-reason in protocol |
| 2 | mssh always returns exit 0; remote exit code not propagated | Correctness | **Architectural** — needs exit-status frame in protocol |
| 3 | Stdin data flows after Bug-#5 fix, but stdin EOF doesn't propagate → `echo x \| mssh ... cat` hangs | Correctness | **Architectural** — needs typed EOF or TLS half-close |
| 4 | stdout + stderr merged on the wire | Design | Acknowledged in protocol docstring |
| 5 | Binary data in remote stdout (any non-UTF-8 byte) truncates entire stream to 0 bytes | Correctness | **FIXED** — `encoding=None` on `create_session` |
| 6 | No connect-timeout; mssh hangs on unreachable IP until kernel TCP timeout | UX | Open — small bug, easy to fix |

**Bonus dead-code finding (not a runtime bug):** `python/setup_adhoc.sh:44`
runs `scp ansible-projecanst/test_*.yml ca_server:` — typo, wrong
filename pattern, undefined ssh alias. Already redundant with what
`_setup_ansible_on_ca()` does inside the pytest run. Should be deleted.

## Big-picture observation

Five of the six bugs (#1, #2, #3, #5, #6) live in the **mssh client ↔
msshd outer protocol** — the JSON-headered TLS byte pump. The unit
tests of the byte pump pass; the integration semantics break.

#5 was caught and fixed in one byte change (`encoding=None`). The
others (#1–#3) are protocol-level: they need a framed
post-ack stream (typed messages like `{stdin, stdout, stderr, exit,
deny}`) which would close every one of them at once. See discussion
under Bug #2.

This is the strongest possible argument for the
**Tier-2 static-test layer** (see static-test-plan.md): all of these
are reproducible in <5 seconds without LXC and without an LXC-lab
session reboot when something breaks mid-test.

---

## Bug #1 — Denial message is cryptic + sounds like a network error

**Severity:** UX, **architectural**.
**Triggered by:** any user → unauthorized server.

```
$ mssh_as alice sales whoami
mssh: server closed before sending ack
exit=6
```

**What user sees:** `server closed before sending ack` — reads like the
server crashed or is unreachable. User has no signal that they were
deliberately denied or what to do about it.

**What the CA actually knows** (`/var/log/mssh/audit.jsonl`):
```json
{"decision":"denied","reason":"no_matching_policy",
 "detail":"user 'alice' has no policy granting access to server 'srv-sales'",
 "identity":{"username":"alice"}, "server":{"canonical_name":"srv-sales"}}
```

The deny reason is structured and actionable at the CA. It just never
reaches the client.

**Root cause hypothesis:** v1 protocol probably has msshd close the
inner channel on deny without sending a structured reason. The mssh
client interprets the close as a generic protocol failure.

**Architectural — flagged, not fixed.** Belongs in the protocol
contract (extend v1 to v1.1 with a `deny_reason` field, or carry it in
a banner-like pre-close message). Connects to future-ideas §18
("self-service why was I denied"), which assumes the user can at least
ask — today they don't even know they were denied vs offline.

**Suggested patch shape (not applied):**
1. msshd reads CA response's `denied` branch, sends one final
   structured message to the mssh client before closing.
2. mssh client surfaces it as `mssh: access denied — <reason> (see
   admin or run mssh-admin auth-failures-report)`.

**Detection in static tests:** a unit-level test that asserts on the
exact stderr string of a denial would catch any regression in deny
formatting. We have unit tests of the CA's deny logic but not of the
mssh client's deny rendering.

---

## Bug #2 — Exit code from remote command is never propagated

**Severity:** correctness, **architectural**.
**Triggered by:** `mssh user@host -- <any command with nonzero exit>`.

```
$ ssh_as alice acct false ; echo $?
1
$ mssh_as alice acct false ; echo $?
0
$ ssh_as alice acct exit 7 ; echo $?
7
$ mssh_as alice acct exit 7 ; echo $?
0
```

mssh always returns 0. Breaks any script that uses
`mssh foo || handle_failure`.

**Root cause (confirmed by reading
[client.py:311-369](python/src/mssh/client.py#L311-L369)):**
The v1 protocol after the ack is raw bytes both directions, with
stdout+stderr merged. msshd proxies inner-sshd's SSH channel data as
raw bytes; the SSH channel-exit message gets eaten on msshd's side
(msshd does decode SSH protocol — the inner sshd speaks SSH, msshd
mediates — but doesn't relay the exit-status frame to the mssh
client). `_pump` returns 0 on clean server close, 8 on I/O error.
There is no "remote exit code" path through the protocol.

**Architectural — flagged, not fixed.** Two viable shapes:

- **(a) Add a v1.1 trailer frame.** After the byte stream, msshd sends
  one JSON line `{"v":1,"exit":<n>}` before closing. mssh client reads
  past EOF expecting the trailer, returns n. Backward-compat: old
  clients ignore the trailing line (they exit on EOF anyway).
- **(b) Promote the data channel to framed (length-prefixed)**, with
  message types `{stdin, stdout, stderr, exit, signal}`. Bigger
  protocol change but solves bug #4 (stdout/stderr separation)
  simultaneously and is shape-compatible with the future ideas around
  better error reporting.

**Detection in static tests:** a unit-level test that runs the mssh
client against a fake msshd, has the fake send back a server-close
with intended exit code, and asserts the client's return code matches.
We have unit tests of `_pump` but they don't test the protocol's
exit-code contract because no such contract exists.

---

## Bug #5 — Binary data in remote stdout truncates to zero bytes (FIXED)

**Severity:** correctness, simple bug.
**Triggered by:** any remote command emitting non-UTF-8 bytes:
`mssh user@host -- 'head -c 100 /dev/urandom'`.

**Symptom (before fix):**
```
$ mssh_as alice acct 'head -c 100 /dev/urandom' | wc -c
0
$ mssh_as alice acct 'head -c 100000 /dev/zero'  | wc -c   # text-safe
100000   # works
$ mssh_as alice acct 'head -c 100000 /dev/urandom' | wc -c # binary
0   # silently dropped
```

100 bytes of /dev/urandom fails the same way 5 MB does — it's not a
buffer-size threshold, it's content-dependent.

**Root cause:** [ssh_proxy.py:246-247](python/src/mssh/msshd/ssh_proxy.py#L246-L247)
called `conn.create_session(...)` without `encoding=`, so asyncssh
defaulted the SSH channel to `encoding='utf-8'`. Any byte sequence on
the wire that's not valid UTF-8 made asyncssh internally raise
`UnicodeDecodeError`, which aborts the channel before
`data_received` is ever called. Same default also makes
`chan.write(bytes_from_outer)` raise (str expected), which is Bug #3.

**Fix applied:** add `encoding=None` to `create_session`. Channel now
operates in pure byte-mode in both directions.
[ssh_proxy.py:246-251](python/src/mssh/msshd/ssh_proxy.py#L246-L251)

**Verified post-fix:**
```
$ mssh_as alice acct 'head -c 1048576 /dev/urandom' | wc -c
1048576
$ echo hello | mssh_as alice acct cat
hello
```

**Detection in static tests:** a unit-level test that proxies binary
data through a stub msshd → stub inner-sshd pair and asserts byte-for-
byte fidelity. No such test exists today. Strongly recommended for
the static-test-design phase: test with a payload like
`bytes(range(256))` to exercise every byte value.

---

## Bug #3 — stdin is not forwarded to the remote (PARTIALLY FIXED)

The data half is now fixed by Bug #5's `encoding=None` fix — chan.write
no longer raises on bytes input, so stdin bytes reach the remote and
the remote's response comes back. See verified post-fix output above.

**Still broken: stdin EOF doesn't propagate.** After the local echo
exits, the mssh client busy-spins because:

1. [client.py:339-342](python/src/mssh/client.py#L339-L342) — on
   stdin EOF the client falls into `pass` ("rely on close at exit").
2. select() keeps marking the EOF'd pipe as readable (level-triggered
   EOF), so the loop spins reading empty chunks forever.
3. msshd never sees a close-write signal, so the remote command
   (e.g. `cat`) keeps waiting for input.

**Architectural — flagged.** The fix needs a way to signal "stdin
half-closed" across the outer protocol. Three viable shapes:

- **(a) TLS-under-TCP half-close** — call `socket.shutdown(SHUT_WR)`
  on the underlying socket after stdin EOF. TLS 1.3 doesn't formally
  support half-close, so behavior is implementation-dependent. Likely
  fragile.
- **(b) Add a typed framing layer** to the post-ack stream, so we can
  send a `{type:"stdin_eof"}` message. This is the same protocol
  promotion that Bug #2 wants for exit-status. One shape solves both.
- **(c) Close the connection immediately on stdin EOF** and rely on
  msshd having buffered the response. Racy and breaks long-running
  pipelines.

I'd recommend (b). It's the same protocol work as Bug #2 — a single
framed layer carrying `{stdin, stdout, stderr, exit, signal}`
messages.

**Detection in static tests:** subprocess-level test piping stdin to
mssh client, then asserting the client exits within N seconds after
its stdin closes. Currently no such test.

---

## Bug #6 — mssh hangs on unreachable IP (no connect timeout)

**Severity:** UX, simple bug.
**Triggered by:** `mssh user@10.99.99.99:2200 -- whoami` (unreachable).

```
$ timeout 10 mssh ... 10.99.99.99:2200 -- whoami
(no output — killed by timeout 10s)
exit=124
```

mssh just blocks in connect() until the OS gives up (typically ~2
minutes). Users will assume the system is hung and ctrl-C.

**Root cause:** the mssh client opens its TLS socket without a
connect timeout. Some socket.settimeout / asyncio.wait_for around the
SSLContext.wrap + connect would bound this to e.g. 5 seconds with a
clear "mssh: connect timed out after 5s" message.

**Disposition:** **Open / simple.** ~15 lines in client.py. Not fixed
this session because we were focused on protocol-level bugs.

**Detection in static tests:** subprocess test invokes mssh against an
unrouted IP (e.g. `192.0.2.1/24` from RFC 5737), asserts it exits
within N seconds with a clear error. Currently no such test.

---

## Diagnostic dead-code finding (not a runtime bug)

`python/setup_adhoc.sh:44` runs:
```bash
scp ansible-projecanst/test_*.yml ca_server:
```

Three issues:
1. `ansible-projecanst` — typo of `ansible-project`
2. `test_*.yml` — no source files match that pattern (real files are
   `task_*.yml`, `site.yml`)
3. `ca_server:` — undefined ssh alias

This entire line is dead code; `_setup_ansible_on_ca()` (called
inside the pytest invocation) does the equivalent push correctly via
`lxc file push`. Should be deleted from setup_adhoc.sh.


---

# Round 2 — 2026-05-19 (lab prefix claude-t1Fx)

## Bug #7 — `mssh-admin audit --result` documented but doesn't exist

**Severity:** docs/UX, simple.
**Triggered by:** following [docs/operations.md:239](docs/operations.md#L239):

```
$ mssh-admin audit --since "1 hour ago" --result denied
```

The actual flag is `--decision`, not `--result`. There's also no
`--since` time-window flag — only `--limit`.

**Disposition:** **Open / simple.** Either fix the CLI to match docs
or fix the docs to match the CLI. The CLI's `--decision` name is
arguably better (it matches the audit-record field), so update the
doc.

**Bonus:** there is no `mssh-admin` binary installed on the CA
container in the adhoc lab. Operators following the docs hit
`mssh-admin: command not found`. Must invoke `python3 -m
mssh.admin.main` directly. The setup-only test framework uses
`mssh.admin.client.CAClient` instead, bypassing the CLI entirely.
**Suggested fix:** drop a wrapper at `/usr/local/bin/mssh-admin`
in the lab provisioning, same shape as `/usr/local/bin/mssh`.

**Detection in static tests:** Tier-2 test invoking each documented
admin command, asserting it doesn't fail with "no such option" or
"command not found." Currently no such test.

---

## Bug #8 — `flip_to_per_connection` reverts on every server (FIXED)

**Severity:** correctness, simple bug.
**Triggered by:** running `flip-to-per-connection.sh` from the CA.

```
$ flip_to_per_connection
Flipping all servers to: per-connection...
srv-acct     (10.26.244.178) ... FAILED — reverting
srv-sales    (10.26.244.209) ... FAILED — reverting
... (all 4 servers)
```

**Diagnostic trail:**

1. Long-lived enforce keeps working (so msshd ↔ inner-sshd auth works
   in long-lived mode).
2. journalctl on the server during the flip showed:
   ```
   asyncssh [INFO] [conn=0] Auth failed for user root-admin
   msshd.ssh_proxy [ERROR] inner SSH connect failed: Permission denied
   ```
3. Disabled the per-session-dir cleanup
   ([inner.py:478](python/src/mssh/msshd/inner.py#L478)) temporarily and
   ran the flip. Inspected the rendered `sshd_config` and the inner sshd's
   own log: **`userauth_pubkey: key type ssh-ed25519-cert-v01@openssh.com
   not in PubkeyAcceptedAlgorithms`**.

**Root cause:** The CA-side built-in template
([templates.py:79](python/src/mssh/ca/templates.py#L79)) had:
```
PubkeyAcceptedAlgorithms  ssh-ed25519
```
but the algorithm name for the ephemeral SSH user cert msshd mints is
`ssh-ed25519-cert-v01@openssh.com`. The long-lived template at
[config/sshd_config.template:56](config/sshd_config.template#L56)
correctly includes both. The CA's built-in only had the bare-key form
→ inner sshd rejects the cert.

**Fix applied:** include both algorithms in the built-in template.

```diff
-PubkeyAcceptedAlgorithms  ssh-ed25519
+PubkeyAcceptedAlgorithms  ssh-ed25519,ssh-ed25519-cert-v01@openssh.com
```

**Verified post-fix:**
```
$ flip_to_per_connection
srv-acct     ... OK (per-connection)
srv-sales    ... OK (per-connection)
srv-hr       ... OK (per-connection)
srv-eng      ... OK (per-connection)
$ flip_to_enforce             # flip back
... OK (enforce) × 4
```

**Deployment gotcha worth noting:** the first deploy of the fix didn't
take effect because of stale `__pycache__/` on the CA. `lxc file push`
+ `systemctl restart` is not enough. Need to `rm -rf
/app/src/__pycache__` (and recursive) before restart, OR the host
test framework's package-install path should set PYTHONDONTWRITEBYTECODE
to avoid the stale-bytecode hazard in dev. **Add to
adhoc-learnings.md.**

**Detection in static tests:** Tier-2 unit test of
`get_effective_template` plus an integration test that spawns a real
local sshd against a rendered config from the CA, with an ephemeral
SSH cert, and asserts the cert authenticates. This single test would
have caught Bug #8 in <5 seconds.


---

## Bug #9 — Revocation doesn't propagate when only denials are happening (FIXED — see #10)

**Severity:** correctness, **architectural-then-simple**.
**Triggered by:** revoke a user via `mssh-admin cert revoke <serial>`,
then have only-denial traffic flow through msshd.

Observed: alice's cert revoked on the CA (seq advanced to 1). Other
users continued to try and be denied by policy on the same msshd.
30 seconds, then 60 seconds — alice STILL connects (cache valid,
CRL sync never ran).

**Root cause:** see Bug #10. Fixed via #10.

---

## Bug #10 — CRL sync only triggers on grant responses, not denies (FIXED)

**Severity:** correctness, simple but cross-file.
**Triggered by:** any deployment where msshd's authz cache mostly hits
and most CA traffic is denials. Revocations sit indefinitely on
msshd until SOME grant happens.

**Root cause:**
1. CA's `_deny()` response body
   ([authorize.py:70](python/src/mssh/ca/authorize.py#L70)) didn't
   include `current_crl_seq`. Only the grant path emitted it.
2. msshd's `AuthorizationDeny` dataclass + parse path
   ([msshd/ca.py:49-52](python/src/mssh/msshd/ca.py#L49-L52),
   [msshd/ca.py:190-195](python/src/mssh/msshd/ca.py#L190-L195))
   didn't extract `current_crl_seq` from the deny body even if it
   were there.
3. msshd's enforce_listener
   ([enforce_listener.py:249-258](python/src/mssh/msshd/enforce_listener.py#L249-L258))
   `maybe_sync()`'d only on grants, not on denies.

So even with a busy CA-deny path, CRL revocations stalled until some
fresh grant came through. On small fleets with stable populations,
this could be ∞.

**Fix applied (three places):**

1. `_deny()` gains `current_crl_seq` kwarg and includes it in the
   response body. All 8 deny call sites updated to pass
   `crl_seq = ctx.crl.current_seq() if ctx.crl is not None else None`.
2. `AuthorizationDeny` gains `current_crl_seq: int = 0` field; parse
   path extracts it from the response.
3. Enforce listener's deny branch calls
   `self.crl_sync.maybe_sync(result.current_crl_seq)` if nonzero.

**Verified post-fix:**

```
alice has cached entry, cert revoked on CA (seq → 1)
$ mssh_as bart acct whoami        # bart denied by policy
msshd.crl_sync: caught up from seq=0 to seq=1
$ mssh_as alice acct whoami       # alice's cache invalidated by CRL
mssh: server closed before sending ack       # now correctly denied
```

**Detection in static tests:** the existing `test_ca_crl.py` exercises
the CRL machinery but not the deny-response carrying current_crl_seq.
Add a Tier-2 test: ‘revoke a cert, force a deny from msshd, assert
last_crl_seq advanced.'

---

## Bug architectural caveat: CRL sync remains lazy

Even with #10 fixed, msshd only learns about CRL changes when SOMEONE
makes a CA call. If a server has 100% cache hits forever — small fleet,
stable population, recently warm — revocations propagate only via
the next cold call, which might never come.

**Not a bug per se:** the design is explicit that the strict-mode
threshold (`crl_strict_threshold`, default 50) catches drift via a
forced cold-call after the threshold is crossed. For small fleets,
this threshold is effectively never reached.

**Possible improvement (open / architectural):** a periodic
poll-the-CRL task at startup + every N minutes, even with no traffic.
Cheap (a single GET /v1/crl), bounded propagation. Cost: msshd has a
background task even when idle.

