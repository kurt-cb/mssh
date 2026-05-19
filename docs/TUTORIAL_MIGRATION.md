# mssh — migration tutorial (Phase 0 → Phase 2)

Sibling to [TUTORIAL.md](TUTORIAL.md). Where that one starts with a
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

Same as [TUTORIAL.md § Prerequisites](TUTORIAL.md#prerequisites) —
LXD/Incus, source checkout, dev install:

```bash
cd /path/to/mssh
make dev-install        # installs mssh* wheels editable into .venv
```

---

## 0. Start the lab at Phase 0 (no mssh yet)

The same `setup_adhoc.sh` you use elsewhere accepts a phase argument
that tells it where to stop. Phase 0 = "vanilla sshd, nothing else."

```bash
cd python
./setup_adhoc.sh msshd 0
```

What you get:

  - 5 LXC containers (CA, acct, sales, hr, eng)
  - Unix accounts for every user (`alice`, `bob`, …) on every server
  - SSH keys generated **inside each user's primary container** (the
    realistic onboarding path)
  - **Vanilla sshd on port 22** on every server
  - **No msshd anywhere yet.** No CA configured beyond the user-cert
    bootstrap. No port 2200 listener.

When the lab settles to a `adhoc>` prompt with **"SUCCESS — msshd
adhoc lab is up at Phase 0"**, you're at the starting line.

The shell that drops you in has `./adhoc-env.sh` sourced, which
exports per-server `$acct_IP`, `$ca_IP`, … plus container names
`$acct_CONTAINER`, `$ca_CONTAINER`, … (every lab gets a random
prefix, so the names below use those variables instead of
hardcoding).

```bash
# Verify: alice can ssh to her server on port 22 with her key.
ssh_as alice acct whoami
# → alice

# Verify: there's NO mssh wrapper listening on port 2200 yet.
ssh -p 2200 -i adhoc-keys/alice alice@$acct_IP whoami 2>&1
# → Connection refused (expected — msshd isn't installed yet)
```

This is what a typical operator world looks like before they pick
up mssh: every server has sshd, every user has an `authorized_keys`
entry, no central oracle.

---

## 1. Move to Phase 1 — drop msshd in fallback

`mssh-admin server add` enrolls each server at the CA — but in
**fallback** mode msshd doesn't *use* the CA cert for authorization
yet. It just listens on port 2200 and forwards every connection
through to the existing sshd on port 22. The point of this phase is
to **verify msshd is in the path** without changing any auth.

The lab's helper does this for every server in one shot:

```bash
# Move to Phase 1 (msshd in fallback on every server).
flip_to_fallback
```

Behind the scenes this:
  1. Enrolls every server at the CA (`mssh-admin server add`)
  2. Provisions each server with its mTLS cert + key
  3. Writes a `wrapper.yaml` with `mode: fallback`
  4. Starts msshd on port 2200

Now both transports work:

```bash
# Original sshd on 22, unchanged.
ssh_as alice acct whoami         # → alice

# msshd on 2200, transparent proxy to sshd:22.
ssh_as_2200 alice acct whoami    # → alice (proxied through msshd)
```

**What's worth noticing:**

  - The user's SSH key was good enough for both paths. The
    `authorized_keys` on the server still authorizes them.
  - msshd in fallback mode is a TCP proxy. It does not call the CA
    on the auth path. If you stopped the CA right now, both ssh
    paths would still work.
  - This is the "no-risk wiring check" phase. You've proven the
    gateway is listening, accepting TLS, and forwarding traffic.

In production, an operator stays in this phase until they're
confident:
  - msshd starts reliably under systemd
  - The port-2200 firewall path is open
  - Users' clients can reach port 2200 (DNS, NAT, etc.)
  - msshd doesn't crash under load

---

## 2. Inspect the CA at this point

Even in fallback, the CA has metadata about every server you
enrolled. From the CA host:

```bash
lxc exec ${ca_CONTAINER} -- su - root-admin -c 'mssh-admin status'
```

You'll see `✓` for "CA reachable", `✓` for "N servers enrolled",
`✗` for "every enrolled user has a key" (none yet — we haven't
enrolled users at the CA in fallback, only servers).

This is the operator's "I have a CA but it's not making decisions
yet" state. Audit logs are quiet; the audit-log lookup returns
nothing because no authorize calls have happened.

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
    [TUTORIAL.md](TUTORIAL.md).
