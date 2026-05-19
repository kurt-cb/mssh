# Bug #8 — `flip_to_per_connection` reverts on every server

**Status:** CLOSED.

_Originally tracked in `adhoc-bugs.md` (rounds 1+2, 2026-05-18 / 2026-05-19)._

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
