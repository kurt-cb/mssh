# Bug #6 — mssh hangs on unreachable IP (no connect timeout)

**Status:** CLOSED in v0.1.0 (commit pending) — mssh now uses a 5s connect timeout. Regression test: `python/tests/test_client_connect_timeout.py`.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

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
