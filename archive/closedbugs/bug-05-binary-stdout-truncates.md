# Bug #5 — Binary data in remote stdout truncates to zero bytes

**Status:** CLOSED.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

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
