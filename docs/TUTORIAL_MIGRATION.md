# mssh — migration tutorial (Phase 0 → Phase 2)

Sibling to [TUTORIAL_USER_MANAGEMENT.md](TUTORIAL_USER_MANAGEMENT.md). Where that one starts with a
prebuilt Phase-2 lab, this one walks the **actual migration sequence**
operators face when adopting mssh in front of existing SSH
infrastructure:

  - Phase 0 — existing fleet with vanilla sshd + `authorized_keys`
  - Phase 1 — drop msshd in **fallback** mode on port 2200, still
    using the operator's existing sshd_config for auth
  - Phase 2 — flip msshd to **enforce** mode, CA becomes the auth
    oracle

Pairs with [MIGRATION.md](MIGRATION.md) — the production runbook.
This tutorial is the sandbox where you build muscle-memory before
running the same sequence on real hosts.

## Prerequisites

Same as [TUTORIAL_USER_MANAGEMENT.md § Prerequisites](TUTORIAL_USER_MANAGEMENT.md#prerequisites) —
LXD/Incus, source checkout, dev install:

```bash
cd /path/to/mssh
make dev-install        # installs mssh* wheels editable into .venv
```

---

## 0. Start with a fully-provisioned lab (default Phase 2)

For the WALKTHROUGH to work, we want the lab's flip helpers
(`flip_to_fallback`, `flip_to_enforce`) on the CA. Those scripts are
installed by the test framework at Phase-2 setup, along with all the
per-user PKI and per-server mTLS material the migration requires.

```bash
cd python
./setup_adhoc.sh          # default Phase 2 — installs everything
```

What you get when the `adhoc>` prompt drops:
  - 5 LXC containers (CA, acct, sales, hr, eng)
  - msshd in enforce mode on each server (the destination state)
  - Helper scripts on the CA: `flip-to-fallback.sh`,
    `flip-to-enforce.sh`, `flip-to-per-connection.sh`
  - Per-user PKI material in `./adhoc-keys/` so the host can
    `mssh user@server` as any user

The shell has `./adhoc-env.sh` sourced, exposing per-server
`$acct_IP`, `$ca_IP`, …, container names `$acct_CONTAINER`,
`$ca_CONTAINER`, …, and helper functions `mssh_as`, `ssh_as`,
`ssh_as_2200`, `flip_to_fallback`, `flip_to_enforce`.

> **Why not start at Phase 1?** `./setup_adhoc.sh msshd 1` STOPS at
> Phase 1 — useful for testing the "install msshd in fallback" path
> in isolation but doesn't enroll users or install the flip helpers.
> To walk the full migration STORY interactively, the Phase-2 lab
> + flip helpers is what you want; the helpers can take the lab BACK
> to Phase 1 state at any moment via `flip_to_fallback`.

### Verify the start state

We're at Phase 2 (enforce). Three transports exist:

```bash
ssh_as alice acct whoami         # → alice  (Phase 0 path, always works)
ssh_as_2200 alice acct whoami    # FAILS in enforce — msshd terminates mTLS on 2200
mssh_as alice acct whoami        # → alice  (Phase 2 path, CA mediated)
```

---

## 1. Go backward to Phase 1 (msshd in fallback)

To see what Phase 1 looks like from the operator's perspective, run
`flip_to_fallback` — it rewrites each server's `wrapper.yaml` to
`mode: fallback` and restarts msshd.

```bash
flip_to_fallback
# → 4 servers OK (fallback)
```

Now both transports work because msshd is a TCP proxy:

```bash
ssh_as alice acct whoami         # → alice  (Phase 0 path)
ssh_as_2200 alice acct whoami    # → alice  (msshd:2200 transparently
                                 #          proxies to sshd:22)
mssh_as alice acct whoami        # FAILS: TLS handshake error
#                                  (msshd in fallback doesn't
#                                  terminate TLS — mssh requires it)
```

**What an operator sees here in production:** users' existing
`ssh` continues to work. The new `ssh -p 2200` ALSO works. The
operator hasn't changed any auth yet — `authorized_keys` is still
the source of truth. The lab's flip just made msshd a TCP proxy
that's invisible to existing flows.

This is the "no-risk wiring check" phase. In real ops, you stay
here for days/weeks while verifying:

  - msshd starts reliably under systemd on every host
  - The port-2200 firewall path is open
  - Users' clients can reach port 2200 (DNS, NAT, etc.)
  - msshd doesn't crash under load

---

## 2. Inspect the CA's state during Phase 1

Even in fallback, the CA has metadata about every server you
enrolled. From the operator workstation (host):

```bash
mssh-admin --ca-url https://${ca_IP}:8443 \
           --admin-cert ./python/adhoc-ca-creds/bootstrap-admin-cert.pem \
           --admin-key  ./python/adhoc-ca-creds/bootstrap-admin-key.pem \
           --ca-cert    ./python/adhoc-ca-creds/tls-ca-cert.pem \
           status
```

You'll see `✓` for "CA reachable", `✓` for "N servers enrolled",
and `✓` for "users enrolled with keys + policies" — because the
Phase-2 setup already did all of that. msshd is just not USING the
CA to authorize sessions right now (it's in fallback).

> In the real migration this is where you do `mssh-admin server add`
> + `mssh-admin user add` for each server and user — the lab front-
> loaded that work in Phase 2 setup. See
> [MIGRATION.md](MIGRATION.md) for the full enrollment sequence.

---

## 3. Move to Phase 2 — flip msshd to enforce

This is where the actual security model kicks in. Each `mssh-admin
flip-to-enforce` step:
  1. Generates per-user mTLS certs (the CA's signing cert mints
     them)
  2. Enrolls users at the CA with policies (alice → accounting only,
     bob → sales only, etc.)
  3. Updates each server's wrapper.yaml to `mode: enforce`
  4. Restarts msshd — which now calls the CA on every connection,
     mints an ephemeral OpenSSH user cert, and proxies the session
     to the hermetic inner sshd

The lab's helper does all of this:

```bash
flip_to_enforce
```

After this, the transports diverge:

```bash
# Phase 0 path (port 22, the operator's existing sshd):
ssh_as alice acct whoami         # → alice  (always works — break-glass)

# Phase 1 path (port 2200 in fallback mode) NO LONGER WORKS — msshd
# now terminates mTLS on 2200 and rejects raw ssh:
ssh_as_2200 alice acct whoami    # → "Connection closed by ... port 2200"

# Phase 2 path (port 2200, msshd in enforce mode, CA call per session):
mssh_as alice acct whoami        # → alice  (CA mediated)

# Phase 2, denied: alice has no policy for srv-sales.
mssh_as alice sales whoami       # → exits non-zero, "denied" in stderr
```

The fallback transport stops accepting raw SSH on port 2200 as soon
as you flip to enforce — port 2200 now speaks mTLS+JSON, and only the
`mssh` client knows how to. Port 22 (Phase 0) stays open as the
break-glass path.

**What you're seeing in a real deployment:**
  - Users start using `mssh user@host` (not `ssh`).
  - Every `mssh` triggers an authorize call to the CA — visible in
    the CA's audit log.
  - The CA can deny based on policy. Lost keys / departed employees
    can be revoked centrally (`mssh-admin user remove`); the change
    propagates within the cache TTL.
  - Port 22 still works (and stays as the break-glass path) — you
    don't have to turn it off to be done.

---

## 4. Roll back to Phase 1 on one server

Imagine you find a regression in mssh on the sales server only.
Roll just that one host back to fallback while leaving the rest in
enforce:

```bash
lxc exec ${sales_CONTAINER} -- sh -c \
  "sed -i 's/^mode: enforce/mode: fallback/' /etc/mssh/wrapper.yaml \
   && systemctl restart msshd"
```

Now bob's `ssh -p 2200 bob@sales` (raw SSH) works again — msshd
is back to being a transparent proxy. **But `mssh bob@sales` no
longer works on that server** — mssh requires msshd to terminate
mTLS, and in fallback mode there's no TLS terminator. Users on a
rolled-back server use raw ssh (port 22 or port 2200) until the
host returns to enforce.

To flip everything back uniformly:

```bash
flip_to_enforce
```

**What you're seeing in a real deployment:**
  - The migration is **reversible per-server, per-config-line**.
    Production operators with strict change-management often spend
    weeks with some servers in each mode.
  - No "big-bang cutover" needed. Adopt mssh on the schedule that
    suits your fleet.

---

## 5. Compare to the production runbook

Now skim [MIGRATION.md](MIGRATION.md). The sequence is the same:

| Tutorial step | Production runbook step |
|---|---|
| `setup_adhoc.sh msshd 0` | Operator brings their existing fleet, no mssh yet |
| `flip_to_fallback` | Per-server: `mssh-admin server add`, install msshd, `mode: fallback` |
| `flip_to_enforce` | Per-server: `mode: enforce` flip, after users are enrolled |
| `sed -i 's/enforce/fallback/'` | Per-server rollback in MIGRATION.md § 4.4 |

The adhoc lab compresses days of careful production rollout into a
few seconds of script. The state transitions are real — the
underlying msshd, CA, and policy machinery is the same code that
ships in v0.1.0.

---

## 6. Tear down

```bash
exit             # leave the adhoc> shell
./cleanup_containers.sh
```

If you want to keep the prebaked images for the next run:

```bash
# (skip; they persist by default)
```

To delete the prebaked images too:

```bash
lxc image delete mssh-ubuntu-fixed mssh-alpine-fixed
```

---

## Where to go next

  - **Run the production migration:** [MIGRATION.md](MIGRATION.md).
  - **Operate a deployed mssh:** [operations.md](operations.md).
  - **Try the prebuilt Phase-2 lab tutorial** for the day-in-the-life
    operator view, including audit trail and banner customization:
    [TUTORIAL_USER_MANAGEMENT.md](TUTORIAL_USER_MANAGEMENT.md).
