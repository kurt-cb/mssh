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

