# Bug #2 — Exit code from remote command is never propagated

**Status:** OPEN.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

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
