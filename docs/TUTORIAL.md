# mssh — guided tutorial

Hands-on walkthrough that takes you from "what is mssh" to "I can
explain every piece on a whiteboard" in about 60 minutes. Uses the
LXC adhoc lab as the sandbox so you can see every behavior live
without provisioning any real infrastructure.

Pairs with the **migration runbook** ([MIGRATION.md](MIGRATION.md))
— the runbook is what you'd run in production; this tutorial is the
sandbox where you build confidence in each step before doing it for
real.

## Prerequisites

  - Linux host with [LXD or Incus](https://linuxcontainers.org/) — `lxc list`
    runs cleanly.
  - mssh source checked out, `pip install -e .` done in a venv.
  - ~5 minutes of patience the first time (the lab prebakes a local
    Ubuntu + Alpine image; subsequent runs are faster).

If you've never run the lab before, start with
[INSTALLATION.md § try the adhoc lab first](../INSTALLATION.md).

---

## 0. Start the lab

```bash
cd python
./setup_adhoc.sh
```

What this does, in order:

  1. Builds `mssh-ubuntu-fixed` + `mssh-alpine-fixed` local LXC
     images (one-time, ~2 min).
  2. Launches 5 containers: 1 CA + 4 SSH servers (`acct`, `sales`,
     `hr`, `eng`). Three are Ubuntu, `eng` is Alpine for cross-distro
     coverage.
  3. Walks Phase 0 → 1 → 2 of the adoption journey: vanilla sshd,
     then msshd in fallback, then enforce mode.
  4. Enrols 9 users with realistic department-bounded policies.
  5. Drops you into an `adhoc>` shell with `./adhoc-env.sh` already
     sourced and helper functions in PATH.

When you see the `adhoc>` prompt and **"SUCCESS — msshd adhoc lab
is up at Phase 2 (enforce)"** scrolled up the terminal, you're
ready. Generated artifacts live in `./adhoc-keys/` and
`./adhoc-ca-creds/`; cleanup is `./cleanup_containers.sh`.

```bash
cat ./ADHOC_TEST_ENV.md      # auto-generated overview of the lab
```

---

## 1. The three transports — see them side by side

The lab has three working SSH-style paths into each server. Each
exercises a different layer of the stack.

### 1a. Vanilla ssh on port 22 (Phase 0)

```bash
ssh_as alice acct whoami
# → alice
```

This is plain `ssh -i ~adhoc-keys/alice alice@<acct-ip>`. msshd is
not in this path. This is your **always-on escape hatch** — even in
Phase 2 (enforce), port 22 keeps working for break-glass.

**What you're seeing in a real deployment:** the user's pre-mssh
flow. Every server has sshd on port 22, and users have
`authorized_keys` entries. mssh's job is to replace this, but only
on the operator's schedule.

### 1b. ssh through msshd-fallback on port 2200 (Phase 1)

The lab leaves you in Phase 2 by default; flip to Phase 1 to see
this transport:

```bash
flip_to_fallback
# (runs flip-to-fallback.sh on the CA via ssh as root-admin —
#  no `lxc exec` involved, that's the real operator workflow)

ssh_as_2200 alice acct whoami
# → alice
```

Now traffic goes `ssh client → msshd:2200 → sshd:22`. msshd
transparent-proxies the bytes; **no CA call**, no cert mint.
Authentication is still your existing `authorized_keys`.

**What you're seeing in a real deployment:** Phase 2 of the
migration runbook ([MIGRATION.md § phase 2](MIGRATION.md#phase-2--roll-msshd-onto-each-server-in-fallback-mode)).
You've installed msshd on the server, configured it in `fallback`
mode, and proven that the byte path works. No security change yet.

### 1c. mssh through msshd-enforce on port 2200 (Phase 2)

```bash
flip_to_enforce

mssh_as alice acct whoami
# → alice
```

Now traffic goes `mssh client → msshd:2200 (mTLS) → CA (authorize) →
ephemeral OpenSSH cert minted → hermetic inner sshd → user shell`.
The CA decided, in real time, that alice was allowed to reach
`srv-acct`.

**What you're seeing in a real deployment:** Phase 4 of the runbook
([MIGRATION.md § phase 4](MIGRATION.md#phase-4--flip-servers-to-enforce-role-by-role)).
The cutover from "policy lives on the server" to "policy lives at
the CA." This is the actual security change.

---

## 2. Watch a deny happen

Policy lives at the CA. alice's enrollment has access to the
`accounting` group only; she's not authorized for `sales`.

```bash
mssh_as alice sales whoami
# → command exits non-zero with a denied message in stderr
```

Now ask the CA why:

```bash
lxc exec mssh-adhoc-ca -- cat /var/log/mssh/audit.jsonl \
  | tail -1 | python3 -m json.tool
```

You'll see a record with `decision: deny` and `denied_reason`
pointing at a policy mismatch. **Every authorization call is in the
audit log, allow or deny.**

For the operator's view of the same audit log:

```bash
# From your operator workstation (the host, in this case):
mssh-admin --ca-url https://$(lxc list mssh-adhoc-ca --format csv -c 4 | awk '{print $1}'):8443 \
           --admin-cert ./adhoc-ca-creds/bootstrap-admin-cert.pem \
           --admin-key  ./adhoc-ca-creds/bootstrap-admin-key.pem \
           --ca-cert    ./adhoc-ca-creds/tls-ca-cert.pem \
           audit --decision denied
```

**What you're seeing in a real deployment:** the kind of inquiry an
admin makes when a user calls saying "I can't get in." The audit log
is the single source of truth — no per-server log-spelunking.

---

## 3. Walk the deployment state with mssh-admin

The same workstation creds in §2 let you ask the CA what it knows:

```bash
# Save the verbose flags into a config so you don't retype them:
mkdir -p ~/.mssh-admin
cat > ~/.mssh-admin/config <<EOF
ca_url: https://$(lxc list mssh-adhoc-ca --format csv -c 4 | awk '{print $1}'):8443
admin_cert: $(pwd)/adhoc-ca-creds/bootstrap-admin-cert.pem
admin_key:  $(pwd)/adhoc-ca-creds/bootstrap-admin-key.pem
ca_cert:    $(pwd)/adhoc-ca-creds/tls-ca-cert.pem
EOF

mssh-admin status
```

You should see a green table — CA reachable, 1 admin enrolled,
4 servers, 9 users, every user with at least one key and one policy.

This is the "everything is fine" view. Most of the time, after a
real migration, this is what `status` will report. The interesting
case is when it doesn't:

```bash
mssh-admin user add --user newperson
# (creates the user with no keys, no policies)

mssh-admin status
# Now ✗ on "users without any keys" — newperson is the named user.

mssh-admin next
# Single-line "Next: add a key for newperson" with a copy-paste cmd.
```

**What you're seeing in a real deployment:** the in-product version
of [MIGRATION.md](MIGRATION.md). When you onboard a new user or a
new server, `mssh-admin next` is your guide for "what's the next
command." When `status` is all-green, the deployment is healthy.

Clean up:

```bash
mssh-admin user remove --user newperson
```

---

## 4. Customize the pre-auth banner per server

Each msshd shows a banner before the user authenticates. The
default says "this session is mediated by mssh." Operators can
override it per-server with `wrapper.yaml`:

```bash
# Drop a template file onto the acct server:
cat <<'EOF' | lxc file push - mssh-adhoc-acct/etc/mssh/banner.txt
─── {server} ({group}) — owned by {owner} ───
For access issues: contact #ops on Slack.
EOF

# Tell wrapper.yaml to use it:
lxc exec mssh-adhoc-acct -- sh -c "cat >> /etc/mssh/wrapper.yaml" <<'EOF'

banner:
  template_path: /etc/mssh/banner.txt
  values:
    server: srv-acct
    group: accounting
    owner: finance-ops
EOF

lxc exec mssh-adhoc-acct -- systemctl restart msshd

# Connect and see it:
mssh_as alice acct true 2>&1 | head -5
```

You'll see your banner just before alice's session establishes.

**What you're seeing in a real deployment:** simple per-server
identity in front of every connection. Different teams' servers
can advertise different on-call channels, compliance scope,
maintenance windows, etc. Per-user substitution (`{user}` etc.) is
not supported today — see
[design/future-ideas.md §1](../design/future-ideas.md) for the path.

Revert the change before moving on:

```bash
lxc exec mssh-adhoc-acct -- sh -c \
  "sed -i '/^banner:/,/^$/d' /etc/mssh/wrapper.yaml \
   && systemctl restart msshd"
```

---

## 5. Add a user mid-flow

Imagine you've completed a migration and a new employee joins. Here's
the full lifecycle:

```bash
# 1. Generate the new user's SSH keypair (or have them generate it).
ssh-keygen -t ed25519 -f ./adhoc-keys/newhire -N '' -C 'newhire@adhoc' -q

# 2. Enrol at the CA.
mssh-admin user add --user newhire --key ./adhoc-keys/newhire.pub

# 3. Attach a policy (accounting only, session channel only).
mssh-admin policy add --user newhire \
                      --server-groups accounting \
                      --channels session

# 4. Confirm via status.
mssh-admin status
# All green — newhire is fully provisioned.

# 5. (In real life: hand the user their cert + key + ca files for
#     ~/.mssh/. Here in the lab, mssh-admin user cert mint would
#     produce them; alternatively reuse one of the existing users'
#     PKI as a stand-in.)
```

**What you're seeing in a real deployment:** the canonical 3-command
onboarding path. `mssh-admin status` confirms the new user is
"complete" before you tell them to try connecting. Removing a user
is one command (`mssh-admin user remove --user <name>`) — every
authorize call for them denies within the CA's cache TTL (default
1 minute).

---

## 6. Roll back a server

Imagine you're partway through Phase 4 (flipping servers to enforce)
and one host starts misbehaving. The whole point of the three-mode
design is that this is a one-line revert.

```bash
# Flip back to Phase 1 (fallback) just for the sales server. This is
# what the per-server rollback in MIGRATION.md § 4.4 looks like.
lxc exec mssh-adhoc-sales -- sh -c \
  "sed -i 's/^mode: enforce/mode: fallback/' /etc/mssh/wrapper.yaml \
   && systemctl restart msshd"

# Now the other servers are still in enforce mode, but sales is
# fallback. mssh users on sales drop back to authorized_keys-based
# auth. Confirm:
ssh_as_2200 bob sales whoami    # works (Phase 1 path)
mssh_as bob sales whoami        # also works (mssh just passes
                                # through fallback's transparent proxy)
```

When you've fixed whatever was wrong, flip the single host back:

```bash
lxc exec mssh-adhoc-sales -- sh -c \
  "sed -i 's/^mode: fallback/mode: enforce/' /etc/mssh/wrapper.yaml \
   && systemctl restart msshd"
```

Or `flip_to_enforce` (the helper) to bring every server back to
enforce in one shot.

**What you're seeing in a real deployment:** the reversibility of
each flip. You can keep individual hosts in fallback indefinitely
without affecting the rest of the fleet. Operators with strict
change-management often spend weeks with some servers in each mode.

---

## 7. Inspect the CA's audit trail

Every authorize call lands in the CA's audit log. For a real
deployment-level look:

```bash
lxc exec mssh-adhoc-ca -- tail -20 /var/log/mssh/audit.jsonl \
  | python3 -c 'import sys,json
for line in sys.stdin:
    e = json.loads(line)
    if e.get("event") == "authorize":
        print(f"{e.get(\"timestamp\")} {e.get(\"decision\",\"?\"):>6}"
              f" {e.get(\"user\",\"?\"):>10} → {e.get(\"server\",\"?\")}"
              f" ({e.get(\"denied_reason\") or \"ok\"})")'
```

For the operator-grade view (the same data via the admin API):

```bash
# From the CA host. --decision filters; --limit caps the output.
lxc exec mssh-adhoc-ca -- su - root-admin -c \
    'mssh-admin audit --decision denied --limit 20'
```

**What you're seeing in a real deployment:** the audit log is the
forensic record for "who tried what when." It survives msshd
restarts; it survives every-server-rebooted scenarios; you just
need the CA host (or its backup).

---

## 8. Ask the CA in natural language (MCP, optional)

If you want to drive `mssh-admin` queries from Claude Code / Claude
Desktop instead of typing them by hand, the `mssh-mcp` server
exposes the read-only admin API over the Model Context Protocol.

```bash
# in the same venv as mssh-admin:
pip install 'mssh-admin[mcp]'
```

Then register it with your MCP client. For Claude Code's mcp config:

```json
{
  "mssh-ca": {
    "command": "mssh-mcp",
    "args": []
  }
}
```

After that, in a Claude session you can ask "what's the current
adoption state?" / "show me the last 10 denies for alice" and Claude
will call `mssh-mcp` → CA → return results.

Full setup details, security notes, and the list of exposed tools:
[operations.md § Ask the CA in natural language (MCP)](operations.md#ask-the-ca-in-natural-language-mcp).

---

## 9. The `debug` lab tier (alternative inner sshd)

Production msshd uses **native OpenSSH** as its hermetic inner sshd —
the standard path through every `./setup_adhoc.sh` run you've been
using.

For debugging the CA / cert / policy path in isolation, mssh also
ships a Python-based diagnostic SSH server (`mssh-debug-sshd`). The
adhoc lab can spin up an alternative lab tier that uses it instead
of OpenSSH:

```bash
# Tear down the current lab first.
./cleanup_containers.sh
# Then re-provision in 'debug' mode:
./setup_adhoc.sh debug
```

You'll get the same shaped lab, but the inner SSH server is the
Python diagnostic implementation. Useful when you want verbose
structured logging of the cert validation and policy evaluation
steps without rebuilding OpenSSH with debug logging.

**Important caveat:** debug_sshd is intentionally a smaller SSH
implementation than OpenSSH. If you see a feature work under debug
mode but break under the default msshd lab, suspect a debug_sshd
limitation — not a regression. The production path is what runs on
real servers.

See [design/architecture.md § debug_sshd](../design/architecture.md)
for the full distinction.

---

## 10. What this tutorial did NOT cover

  - **Migration from a pre-mssh deployment.** This tutorial used the
    prebuilt Phase-2 lab. To walk the actual migration sequence
    (Phase 0 vanilla sshd → Phase 1 fallback → Phase 2 enforce),
    follow [TUTORIAL_MIGRATION.md](TUTORIAL_MIGRATION.md) instead —
    same adhoc lab, different starting point.
  - **Multi-CA failover.** Both
    [operations.md § bounce the CA without dropping sessions](operations.md#bounce-the-ca-without-dropping-sessions)
    and the multi-endpoint `ca.endpoints` list in wrapper.yaml
    support running two CAs behind DNS. The lab has only one CA.
  - **Source-CIDR + time-window policies.** The policy YAML schema
    supports both (`source_cidrs: [...]`, `time_window: { ... }`);
    the lab's default policies don't exercise them. See
    [design/api.md § policy management](../design/api.md) for the
    full schema.
  - **Emergency cert for CA-unreachable break-glass.** Disabled by
    default; covered in
    [design/security.md § emergency cert](../design/security.md#emergency-cert).
  - **The hermetic inner sshd's config**. Generated per-startup, hash-
    validated; see [design/architecture.md § hermetic inner sshd](../design/architecture.md#hermetic-inner-sshd).
  - **Browser-based access** — separate design exploration, see
    [design/browser.md](../design/browser.md). Not a part of mssh's
    SSH path.
  - **debug_sshd in-situ swap-in** — diagnostics affordance,
    future-ideas §11. The lab's `debug` tier exists (§9 above), but
    swapping debug_sshd into a running production deployment without
    taking msshd down is not built yet.

---

## 11. Tear down

```bash
exit             # leave the adhoc> shell
./cleanup_containers.sh
```

This deletes the 5 containers. The local `mssh-ubuntu-fixed` and
`mssh-alpine-fixed` images persist — re-running `./setup_adhoc.sh`
reuses them and is much faster than the first run.

To remove the prebaked images too:

```bash
lxc image delete mssh-ubuntu-fixed mssh-alpine-fixed
```

---

## Where to go next

  - **You're deploying for real:** [MIGRATION.md](MIGRATION.md) is
    the production runbook.
  - **You're operating a deployed mssh:** [operations.md](operations.md)
    is the day-to-day reference.
  - **You're contributing:** [design/architecture.md](../design/architecture.md)
    and [design/api.md](../design/api.md). The
    [adhoc lab test source](../python/tests/lxc/test_setup_only_msshd.py)
    is a fully-worked example of every API call.
  - **You're proposing a feature:** read
    [design/future-ideas.md](../design/future-ideas.md) first.
    Many ideas are already captured.
