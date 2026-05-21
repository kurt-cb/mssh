# mssh — migration runbook

Step-by-step operator playbook for moving an existing SSH fleet
onto mssh. The technical pieces — `install_mssh.sh`, `upgrade.sh`,
the three msshd modes, `~/.mssh/` client config — all already exist;
this doc ties them together into a sequence you can hand to whoever
is doing the rollout.

Read this once end-to-end before starting. The migration is
**deliberately gradual** — every step is reversible and existing SSH
keeps working until the operator explicitly retires it. If anything
in this doc looks wrong for your environment, stop and adjust before
running the commands.

For background on what mssh is and why these phases exist, see
[overview.md](overview.md) and
[design/architecture.md](../design/architecture.md). For day-to-day
operator tasks once the migration is done, see
[operations.md](operations.md).

---

## Audience

You're an operator who manages a fleet of SSH servers — typically
between 5 and a few hundred hosts — and an existing user base
authenticated via OpenSSH keys and `authorized_keys`. You want to
move authorization off the individual servers and into a CA without
forcing a flag-day cutover.

**Prerequisites:**

  - One machine to host the CA (separate from your SSH servers).
    Modest CPU; the CA's load is per-connection authorization calls.
  - Network access from every SSH server to the CA's TLS endpoint
    (typically port 8443). **The CA does not need to be reachable
    from the public internet, or from end-user devices.** That's the
    point.
  - Root (or sudo) on each SSH server, and on the CA host.
  - Existing SSH server inventory: hostnames, group membership
    ("accounting", "production", etc.) as you'd describe them today.
  - Existing user list with SSH public keys.

**Time estimate** (rough, for a fleet of ~20 hosts and ~50 users):

  | Phase | One-time effort | Per-host effort | Per-user effort |
  |---|---|---|---|
  | 1. Stand up CA | 30 min | — | — |
  | 2. msshd in fallback | — | 5 min | — |
  | 3. Enrol users | — | — | 2 min |
  | 4. Flip to enforce | — | 3 min | — |
  | 5. Decommission ssh | — | 1 min | — |

  Total: ~1 day of operator time for a 20-host, 50-user fleet,
  spread across as many calendar days as your change-management
  process needs.

---

## The mental model

Five pieces, four of which you install:

  1. **CA** — central authorization service. Holds the signing key
     and the enrollment database. Reachable only from your SSH
     servers and your admin workstation.
  2. **`mssh-admin`** — operator CLI on your workstation. Talks to
     the CA over mTLS. This is what you run to enrol users,
     servers, policies, and rotate certs.
  3. **`msshd`** — gateway daemon on each SSH server, in front of
     the existing sshd. Has three modes:
       - **fallback** — pure TCP proxy. No CA call. Validates the
         deployment without changing auth.
       - **gated** — *deferred*; not in this migration.
       - **enforce** — CA-mediated. Mints ephemeral OpenSSH certs
         for a hermetic inner sshd. Full mssh.
  4. **`mssh`** — client CLI on user laptops. Replaces `ssh` for
     mssh-managed hosts. Uses an mTLS cert plus the user's existing
     SSH key.
  5. **Existing sshd** — keeps running on port 22 throughout the
     migration. mssh runs on port 2200 (configurable). Operators
     decommission ssh on port 22 only at the very end, and only
     when they're satisfied with mssh.

The migration walks msshd through fallback → enforce per server,
on whatever schedule you set. **Existing SSH access on port 22
keeps working at every step** until the final decommission.

---

## Phase 1 — Stand up the CA

### 1.1 Install on the CA host

```bash
# On the CA host, as root.
./install_mssh.sh /path/to/mssh-<version>.tar.gz
# → installs to /opt/mssh, symlinks into /usr/local/bin,
#   drops systemd units (disabled) for msshd and mssh-ca.
```

### 1.2 Initialize the CA

```bash
mssh-admin init --ca-dir /etc/mssh-ca
# Generates: signing-key.pem, signing-cert.pem, bootstrap-admin-*,
#            tls-server-*, tls-ca-cert.pem, enrollment.yaml,
#            ca-config.yaml. Prints the paths.
```

Move the printed `bootstrap-admin-cert.pem` + `bootstrap-admin-key.pem`
to your **operator workstation** (not the CA host). Those are your
admin identity; subsequent `mssh-admin` invocations reference them.

### 1.3 Start the CA service

```bash
systemctl enable --now mssh-ca
mssh-admin --ca-url https://<ca-host>:8443 \
           --admin-cert ./bootstrap-admin-cert.pem \
           --admin-key  ./bootstrap-admin-key.pem \
           --ca-cert    ./tls-ca-cert.pem \
           status
# Expect: "CA reachable at …", "1 admin(s) enrolled", and a row
#         each for servers / users / policies showing zero.
```

If `status` reports anything red, see [troubleshooting](#troubleshooting).

### 1.4 Write a workstation config

Drop the four `--ca-url / --admin-cert / --admin-key / --ca-cert`
values into `~/.mssh-admin/config` so you don't have to type them
on every invocation:

```yaml
# ~/.mssh-admin/config
ca_url: https://ca.internal:8443
admin_cert: /home/operator/.mssh-admin/bootstrap-admin-cert.pem
admin_key:  /home/operator/.mssh-admin/bootstrap-admin-key.pem
ca_cert:    /home/operator/.mssh-admin/tls-ca-cert.pem
```

After this, `mssh-admin status` runs without flags.

---

## Phase 2 — Roll msshd onto each server in fallback mode

The goal of this phase is **wiring confidence**: msshd accepts
connections on port 2200, transparent-proxies them to the existing
sshd on port 22, and the user experience changes only by port number.
**No security change yet.** No CA call yet.

### 2.1 Per-server install + enrollment

For each server (script this when you have more than a handful):

```bash
# On the operator workstation:
mssh-admin server add --name srv-acct-01 --groups accounting,production \
                      --out-dir ./creds/srv-acct-01
# → writes srv-acct-01-cert.pem, srv-acct-01-key.pem, ca-cert.pem
#   into ./creds/srv-acct-01/

# scp the creds + tarball to the server:
scp -r ./creds/srv-acct-01 root@srv-acct-01:/tmp/mssh-creds/
scp mssh-<version>.tar.gz   root@srv-acct-01:/tmp/

# On the server:
ssh root@srv-acct-01
./install_mssh.sh /tmp/mssh-<version>.tar.gz
mkdir -p /etc/mssh
cp /tmp/mssh-creds/* /etc/mssh/
chmod 600 /etc/mssh/srv-acct-01-key.pem
```

### 2.2 Configure msshd in fallback mode

```yaml
# /etc/mssh/msshd.yaml — Phase 2 starting config (fallback only)
mode: fallback
fallback:
  host: 127.0.0.1
  port: 22
listen:
  external_address: 0.0.0.0
  external_port: 2200
```

```bash
systemctl enable --now msshd
ss -ltnp | grep 2200       # confirm msshd is bound
ssh -p 2200 root@localhost # confirm it proxies to system sshd
exit
```

If that `ssh -p 2200` works exactly like `ssh -p 22`, msshd is
correctly wired into the connection path. Move on to the next server.

**At any point in this phase, port 22 keeps working unmodified.**
`ssh -p 22 user@server` is still your fallback if anything goes wrong.

### 2.3 Validate from outside

From a normal user laptop:

```bash
ssh -p 2200 alice@srv-acct-01 -- whoami
# Expect: alice
```

If that works for every (user, server) pair you cared about before,
fallback mode is wired correctly and you're ready to enrol users.

---

## Phase 3 — Enrol users

### 3.1 For each user

```bash
mssh-admin user add --user alice --key /home/alice/.ssh/id_ed25519.pub
# Adds alice. Adds her existing SSH pubkey as one of her keys.

mssh-admin policy add --user alice \
                      --server-groups accounting \
                      --channels session
# Authorizes alice on every server in the "accounting" group, for
# interactive session channels only (no port forwarding, no agent
# forwarding, until a policy says otherwise).
```

Run this once per user. The policy can have multiple rules; rules
union (one user can have several `policy add` calls).

`mssh-admin status` walks the deployment state and surfaces any user
who's missing a key or a policy. Run it after each batch to confirm
nothing got dropped.

### 3.2 Mint the user's mTLS cert

mssh clients need an mTLS client cert from the **user-facing CA**
(distinct from the authorization CA — see
[architecture.md § trust model](../design/architecture.md#trust-model)).
Today the simplest setup uses the mssh CA for both hierarchies:

```bash
mssh-admin user cert mint --user alice --out-dir ./creds/alice
# (Command shape may vary — see your installed mssh-admin --help.)
```

The output is `alice-cert.pem`, `alice-key.pem`, `ca-cert.pem`. The
user puts these in `~/.mssh/` on their laptop:

```bash
# On alice's laptop:
mkdir -p ~/.mssh
chmod 700 ~/.mssh
cp alice-cert.pem ~/.mssh/cert.pem
cp alice-key.pem  ~/.mssh/key.pem
cp ca-cert.pem    ~/.mssh/ca.pem
chmod 600 ~/.mssh/*.pem
```

### 3.3 Verify per-user reachability

The user should now be able to call mssh in **enforce mode**
preview — but msshd is still in fallback, so the call works through
the proxy. Smoke test:

```bash
# As alice, from alice's laptop:
mssh -p 2200 alice@srv-acct-01 -- whoami
# Expect: alice (same as ssh -p 2200 still does)
```

---

## Phase 4 — Flip servers to enforce, role by role

This is the actual security cutover. Pick one server group and one
user group at a time. Each flip is reversible by changing one line
in `msshd.yaml` and restarting msshd.

### 4.1 Pre-flight checks

```bash
mssh-admin status
# Expect all checks green: servers, users, keys, policies.
```

If anything is red, fix it before flipping anything. The pre-auth
banner the user sees on connect will reflect the server's status.

### 4.2 Flip one server

```bash
# On the chosen server:
sed -i 's/^mode: fallback/mode: enforce/' /etc/mssh/msshd.yaml
systemctl restart msshd
journalctl -u msshd --since '1 minute ago'
# Look for: "running in enforce mode", "inner sshd up on 127.0.0.1:…"
```

### 4.3 Verify from a user

```bash
# Authorized user — should succeed:
mssh -p 2200 alice@srv-acct-01 -- whoami

# Unauthorized user — should be denied at the CA:
mssh -p 2200 unauthorized@srv-acct-01 -- whoami
```

Watch the CA audit log to confirm the deny landed:

```bash
mssh-admin audit --decision denied --limit 50  # NB: --since is future work
```

### 4.4 If something goes wrong

The flip is reversible:

```bash
sed -i 's/^mode: enforce/mode: fallback/' /etc/mssh/msshd.yaml
systemctl restart msshd
```

You're back to Phase 2 behavior on that server. Diagnose, fix, flip
again. The user's port-22 ssh is still untouched as the final
escape hatch.

### 4.5 Per-role rollout

Repeat 4.2 + 4.3 for one server-group at a time:

```
Week 1:  flip the dev / test group(s).        Watch for issues.
Week 2:  flip the staging group(s).            Watch for issues.
Week 3:  flip the production group(s).         Watch for issues.
Week 4:  flip the bastions / break-glass last.
```

Slow is fine. Operators with strict change-management often spend
months in mixed mode, with some groups in fallback and others in
enforce. That's the design intent.

---

## Phase 5 — Decommission legacy ssh

Only after you're confident every user / server pair works under
mssh:

### 5.1 Move msshd to port 22

```bash
# On each server, swap msshd to port 22 (sshd has to move or stop):
systemctl stop ssh
sed -i 's/external_port: 2200/external_port: 22/' /etc/mssh/msshd.yaml
systemctl restart msshd
ss -ltnp | grep ':22 '   # confirm msshd is on port 22
systemctl disable ssh    # belt and braces
```

The `scripts/upgrade.sh cutover` step automates this if you'd rather.

### 5.2 Tell users to clean ~/.ssh/

```
"On <date>, port 2200 is going away. mssh moved to port 22. Your
 mssh command stays the same — drop the -p 2200 flag and use:
    mssh alice@srv-acct-01
 Your existing ~/.ssh/config will work for the host names but the
 key files there are no longer used. You can rm ~/.ssh/id_* once
 you've verified mssh works for every host you need."
```

`~/.ssh/` doesn't have to disappear immediately — many users have
non-mssh SSH targets (other vendors, public github, etc.) and that
still uses `~/.ssh/`. mssh is specifically about hosts you manage.

### 5.3 Update monitoring + alerting

Anything that watched port 22 for `sshd_login_failed` style alerts
will go silent. Re-aim it at:

  - msshd journal (`journalctl -u msshd`) — connection-level events.
  - mssh CA audit (`/var/log/mssh-ca/audit.jsonl`) — every authorize
    decision, allow or deny, with per-user / per-server breakdown.

---

## Troubleshooting

### "mssh-admin status reports CA not reachable"

Check the CA service: `systemctl status mssh-ca`. The CA writes its
log to journald — `journalctl -u mssh-ca -n 100`.

Common causes:

  - CA's TLS cert SAN doesn't include the URL the client is using.
    `--ca-url https://ca.internal:8443` requires `ca.internal` in
    the cert's SubjectAltName. Regenerate with
    `mssh-admin init --ca-dir … --tls-server-san DNS:ca.internal`.
  - Firewall: client → CA on port 8443 must be open.

### "msshd in fallback mode but `ssh -p 2200` fails"

Check msshd is bound: `ss -ltnp | grep 2200`. If yes, check it's
actually proxying — `ssh -vvv -p 2200 user@localhost` from on-box
will surface the connection error.

If msshd is bound but proxying fails:

  - `fallback.host` / `fallback.port` in msshd.yaml may not match
    where the existing sshd is listening.
  - Existing sshd may be down: `systemctl status ssh`.

### "User can `ssh -p 22` but not `mssh -p 2200` (enforce mode)"

Check the CA audit:

```bash
mssh-admin audit --decision denied --user <username> --limit 50
```

Common denied reasons:

  - **`policy_mismatch`** — no policy attaches this user to this
    server's groups. Add one:
    `mssh-admin policy add --user alice --server-groups <group>`.
  - **`source_cidr_mismatch`** — user came from an IP outside the
    policy's `source_cidrs`. Either widen the policy or have them
    connect from an allowed network.
  - **`time_window`** — outside policy's allowed hours. Wait or
    widen.

### "msshd refuses to start after a msshd.yaml edit"

```bash
journalctl -u msshd -n 50
# Typically reports the specific config error.
```

Roll back: `git diff msshd.yaml` if your config is under git; or
re-derive from `config/msshd.yaml.example` and your CA enrollment.

### Rollback any single server

```bash
# Stop msshd; system sshd on port 22 is still running.
systemctl stop msshd
# Users can `ssh user@server` on port 22 as before. Nothing else
# breaks; the CA isn't part of the path anymore.
```

To return that server to mssh, restart msshd: `systemctl start msshd`.

---

## What this runbook intentionally does NOT cover

  - **`gated` mode.** Designed but not implemented today. See
    [future-ideas.md §gated mode](../design/future-ideas.md). When
    available, it slots between fallback and enforce as an
    intermediate phase where the CA gates the connection but the
    operator's existing sshd does the actual auth.
  - **Legacy-config import.** A future `mssh-admin import` (see
    [future-ideas.md §13](../design/future-ideas.md)) will scrape
    existing `authorized_keys` + `sshd_config` to produce a draft
    enrollment YAML. Until that lands, Phase 3 is manual: one
    `user add` + `policy add` per user.
  - **Multi-CA / failover deployments.** This doc assumes one CA.
    Multi-CA is supported (`ca.endpoints` is a list in `msshd.yaml`)
    but operationally complex; see
    [operations.md § bounce the CA without dropping sessions](operations.md#bounce-the-ca-without-dropping-sessions).
  - **Distro-native packaging.** Today's install is `install_mssh.sh`
    (or `make dev-install` for a checkout). Real `.deb` / `.rpm` /
    `.apk` packages are on the roadmap — see
    [future-ideas.md §16](../design/future-ideas.md).

---

## Reference: every command in order

Stripped of context, for the "I know what I'm doing, just show me
the commands" reader:

```bash
# Phase 1 — CA host:
./install_mssh.sh mssh-<ver>.tar.gz
mssh-admin init --ca-dir /etc/mssh-ca
systemctl enable --now mssh-ca

# Phase 2 — per server:
mssh-admin server add --name <name> --groups <g1,g2> --out-dir ./creds/<name>
scp -r ./creds/<name>          root@<name>:/tmp/mssh-creds/
scp mssh-<ver>.tar.gz          root@<name>:/tmp/
ssh root@<name> ./install_mssh.sh /tmp/mssh-<ver>.tar.gz
ssh root@<name> '/etc/mssh/{cp creds, write msshd.yaml fallback, systemctl enable --now msshd}'

# Phase 3 — per user:
mssh-admin user add    --user <u> --key /path/to/<u>.pub
mssh-admin policy add  --user <u> --server-groups <group> --channels session
mssh-admin user cert mint --user <u> --out-dir ./creds/<u>
# (deliver creds/<u> to user; they place under ~/.mssh/)

# Phase 4 — flip each server:
ssh root@<name> "sed -i 's/^mode: fallback/mode: enforce/' /etc/mssh/msshd.yaml; systemctl restart msshd"
mssh-admin audit --decision denied --limit 50   # confirm clean

# Phase 5 — decommission:
ssh root@<name> "systemctl stop ssh; sed -i 's/external_port: 2200/external_port: 22/' /etc/mssh/msshd.yaml; systemctl restart msshd"
```

For an auto-generated playbook (every command + actual output)
from a randomized test fleet, see [future-ideas.md §20](../design/future-ideas.md)
on the end-to-end migration test.
