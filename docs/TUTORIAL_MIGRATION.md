# mssh — migration tutorial (Phase 1 → Phase 2)

Walks the actual command sequence an operator runs to move from
**Phase 1** (msshd installed in fallback, transparent TCP proxy to
existing sshd) to **Phase 2** (msshd in enforce, CA mediates every
session). Uses the adhoc lab as a sandbox.

Sibling tutorial:
[TUTORIAL_USER_MANAGEMENT.md](TUTORIAL_USER_MANAGEMENT.md) starts
from a prebuilt Phase-2 lab and exercises day-in-the-life operator
flows (add/remove users, banners, audit, rollback). This one walks
the **adoption sequence** that gets you to that state.

Production runbook: [MIGRATION.md](MIGRATION.md). The lab compresses
the same sequence into ~10 minutes.

## What you'll do

1. Bring up a Phase-1 lab (msshd in fallback on every server, no
   CA-mediated auth yet).
2. Enroll each server at the CA with `mssh-admin server add`.
3. Mint the user-facing PKI (user-CA + per-server wrapper TLS
   cert + per-user mTLS cert) with `scripts/mint-user-pki.py`.
4. Generate a wrapper-user-CA signing key on each server
   (`ssh-keygen`).
5. Enroll each user + add policies with `mssh-admin user add` /
   `policy add`.
6. Push the wrapper cert material to each server, write the
   enforce-mode `wrapper.yaml`, restart msshd.
7. Verify with `mssh user@server:2200`.
8. Roll one server back to fallback to see per-server reversibility.

## Prerequisites

Same as [TUTORIAL_USER_MANAGEMENT.md § Prerequisites](TUTORIAL_USER_MANAGEMENT.md#prerequisites):

```bash
cd /path/to/mssh
make dev-install        # installs mssh* wheels editable into .venv
```

---

## 0. Start a Phase-1 lab

```bash
cd python
./setup_adhoc.sh msshd 1        # STOP at Phase 1 — msshd in fallback only
```

What you get when the `adhoc>` prompt drops:
  - 5 LXC containers (CA, acct, sales, hr, eng)
  - Vanilla sshd on port 22 of each server, populated with
    `authorized_keys` for alice/bob/carol/dave/…
  - msshd installed on each server with `mode: fallback` —
    a transparent TCP proxy from `:2200` → `127.0.0.1:22`
  - `mssh-ca` running on the CA container, with one bootstrap admin
    enrolled — **but no servers or users enrolled yet**
  - `./adhoc-keys/` on the host: per-user SSH keys (Phase-0 path)
  - `~/.mssh-admin/config` pointing at the CA's bootstrap admin creds

At this point both ssh paths work; mssh does not:

```bash
ssh_as alice acct whoami         # → alice  (port 22, vanilla sshd)
ssh_as_2200 alice acct whoami    # → alice  (port 2200, msshd-proxied to sshd)
mssh_as alice acct whoami        # FAILS: TLS handshake error (msshd in fallback
                                 #        doesn't terminate TLS; mssh requires it)
```

**Where you stand:** msshd is wired in, but nothing in mssh's
security model is engaged yet. `authorized_keys` is still the auth
oracle. This is "no-risk wiring check" — in production you'd stay
here for days/weeks while verifying msshd starts reliably under
systemd, port 2200 is reachable through your NAT/firewall, etc.

---

## 1. Enroll each server at the CA

```bash
cd /tmp && mkdir -p migration && cd migration
mssh-admin server add --name srv-acct  --groups accounting   --out-dir ./srv-acct-creds
mssh-admin server add --name srv-sales --groups sales        --out-dir ./srv-sales-creds
mssh-admin server add --name srv-hr    --groups hr           --out-dir ./srv-hr-creds
mssh-admin server add --name srv-eng   --groups engineering  --out-dir ./srv-eng-creds
```

Each call mints an mTLS keypair the server will use to authenticate
itself to the CA on every `authorize` call. The `--out-dir`
contains:

  - `ca-cert.pem` — the CA's TLS-server root (so the server can
    verify the CA's identity).
  - `srv-<name>-cert.pem` + `srv-<name>-key.pem` — the server's own
    mTLS client cert + key (signed by the CA's signing key).

```bash
mssh-admin server list
# enrolled_at           groups            mtls_subject   name
# 2026-05-19T19:24:26Z  ['accounting']    CN=srv-acct    srv-acct
# 2026-05-19T19:27:41Z  ['sales']         CN=srv-sales   srv-sales
# 2026-05-19T19:27:42Z  ['hr']            CN=srv-hr      srv-hr
# 2026-05-19T19:27:42Z  ['engineering']   CN=srv-eng     srv-eng
```

---

## 2. Mint the user-facing PKI

The CA you bootstrapped manages **server mTLS + authz certs**. It does
**not** mint:
  - the TLS server cert msshd serves on port 2200,
  - the user-CA that signs that wrapper TLS cert,
  - per-user mTLS client certs (presented by `mssh`).

In production this is your **org's existing PKI** (Vault, AWS PCA,
openssl ceremony, …). For the lab — and for small deployments — the
repo ships a reference script:

```bash
python /path/to/mssh/scripts/mint-user-pki.py \
    --out-dir ./user-pki \
    --servers "srv-acct:$acct_IP,srv-sales:$sales_IP,srv-hr:$hr_IP,srv-eng:$eng_IP" \
    --users   "alice,bob,carol,dave"
```

Produces under `./user-pki/`:
  - `user-ca.crt` + `user-ca.key` — trust anchor + signing key
    (**keep `user-ca.key` safe**; the lab leaves it on disk for
    convenience, production should put it in a key store).
  - `wrapper-<server>.crt` + `wrapper-<server>.key` — TLS material
    each server's msshd will serve on `:2200`.
  - `<user>.crt` + `<user>.key` — mTLS material to give to each
    user's workstation.
  - `<user>.pub` — the ssh-ed25519 wire form of the same key, ready
    for `mssh-admin user add --key`.

> The same Ed25519 key sits in the mTLS cert AND the SSH `.pub`. The
> mssh client uses the cert for the outer TLS handshake; the CA
> matches the inner ssh-ed25519 pubkey hash against the enrolled
> user record.

---

## 3. Generate a wrapper-user-CA signing key per server

msshd in enforce mode mints **ephemeral OpenSSH user certs** for
each session and hands them to a hermetic inner sshd. The signing
key lives entirely on each server's filesystem — it never leaves
the host:

```bash
for s in srv-acct srv-sales srv-hr srv-eng; do
    ssh-keygen -t ed25519 -N '' -f ./wrapper-user-ca-${s} -q -C "wrapper-user-ca-${s}"
    chmod 600 ./wrapper-user-ca-${s}
done
```

---

## 4. Enroll each user + add a policy

```bash
mssh-admin user add --user alice --key ./user-pki/alice.pub
mssh-admin policy add --user alice --server-groups accounting --channels session

mssh-admin user add --user bob   --key ./user-pki/bob.pub
mssh-admin policy add --user bob   --server-groups sales      --channels session

mssh-admin user add --user carol --key ./user-pki/carol.pub
mssh-admin policy add --user carol --server-groups hr         --channels session

mssh-admin user add --user dave  --key ./user-pki/dave.pub
mssh-admin policy add --user dave  --server-groups engineering --channels session

mssh-admin status            # ✓ servers ✓ users ✓ policies
mssh-admin next              # "Deployment looks fully provisioned…"
```

Each user is now enrolled with exactly one server group reachable.
This is the source-of-truth that msshd will consult on every
connection once you flip.

---

## 5. Push the cert material to each server

For each container, push five files (the wrapper TLS pair, the
trust anchor, the server's mTLS-to-CA pair, the CA's TLS root, the
wrapper-user-CA signing key + pub):

```bash
# Done once per server. In production this is scp / Ansible / config
# management; in the lab it's `lxc file push`.
for pair in srv-acct:acct srv-sales:sales srv-hr:hr srv-eng:eng; do
    name="${pair%%:*}"; short="${pair##*:}"
    cn_var="${short}_CONTAINER"; cn="${!cn_var}"

    lxc exec "$cn" -- mkdir -p /etc/mssh /var/lib/mssh /var/lib/mssh/inner-sshd /var/log/mssh

    lxc file push ./user-pki/wrapper-${name}.crt "$cn/etc/mssh/wrapper-server.crt"
    lxc file push ./user-pki/wrapper-${name}.key "$cn/etc/mssh/wrapper-server.key"
    lxc file push ./user-pki/user-ca.crt         "$cn/etc/mssh/user-ca.pub"

    lxc file push ./${name}-creds/${name}-cert.pem "$cn/etc/mssh/wrapper-mtls.crt"
    lxc file push ./${name}-creds/${name}-key.pem  "$cn/etc/mssh/wrapper-mtls.key"
    lxc file push /path/to/mssh/python/adhoc-ca-creds/tls-ca-cert.pem \
                  "$cn/etc/mssh/server-mtls-ca.pub"

    lxc file push ./wrapper-user-ca-${name}     "$cn/var/lib/mssh/wrapper-user-ca"
    lxc file push ./wrapper-user-ca-${name}.pub "$cn/var/lib/mssh/inner-sshd/wrapper-user-ca.pub"

    lxc exec "$cn" -- chmod 600 /etc/mssh/wrapper-server.key /etc/mssh/wrapper-mtls.key \
                                 /var/lib/mssh/wrapper-user-ca
done
```

These files are safe to push while msshd is still in fallback —
fallback mode ignores them.

---

## 6. Flip wrapper.yaml to enforce and restart

Write `/etc/mssh/wrapper.yaml` on each server:

```yaml
mode: enforce
listen:
  external_address: 0.0.0.0
  external_port: 2200
tls:
  server_cert: /etc/mssh/wrapper-server.crt
  server_key:  /etc/mssh/wrapper-server.key
  user_ca_pubkey: /etc/mssh/user-ca.pub
ca:
  endpoints: [https://CA_IP:8443]
  client_cert: /etc/mssh/wrapper-mtls.crt
  client_key:  /etc/mssh/wrapper-mtls.key
  ca_pubkey:   /etc/mssh/server-mtls-ca.pub
  timeout_seconds: 5
inner:
  sshd_binary: /usr/sbin/sshd
  port_range: [49152, 65535]
  mode: long-lived
users:
  allowed: ["*"]
logging:
  level: info
  destination: stderr
  audit_destination: file:/var/log/mssh/wrapper-audit.jsonl
```

Then `systemctl restart msshd` (or, on Alpine,
`fuser -k -9 2200/tcp; nohup msshd --config /etc/mssh/wrapper.yaml &`).

---

## 7. Verify

From the operator workstation (or anywhere with network access to
the servers and the user mTLS files):

```bash
PKI=./user-pki

# alice has accounting policy → allowed:
MSSH_CERT=$PKI/alice.crt MSSH_KEY=$PKI/alice.key MSSH_CA=$PKI/user-ca.crt \
    mssh alice@$acct_IP:2200 -- whoami
# → alice (with the per-server banner)

# alice tries sales → denied by policy:
MSSH_CERT=$PKI/alice.crt MSSH_KEY=$PKI/alice.key MSSH_CA=$PKI/user-ca.crt \
    mssh alice@$sales_IP:2200 -- whoami
# → mssh: wrapper rejected request: no_matching_policy: user 'alice'
#         has no policy granting access to server 'srv-sales'

# bob has sales policy → allowed:
MSSH_CERT=$PKI/bob.crt   MSSH_KEY=$PKI/bob.key   MSSH_CA=$PKI/user-ca.crt \
    mssh bob@$sales_IP:2200 -- whoami
# → bob
```

The actionable deny ("no_matching_policy: user 'alice'…") is the
v1.1 protocol's typed deny ack at work — operators see exactly why
a request failed, not just "Connection closed".

Phase 0 (port 22, the existing sshd) still works — `authorized_keys`
remains as a break-glass path. You haven't decommissioned it.

---

## 8. Per-server rollback

A regression on `srv-sales`? Roll just that one host back to
fallback:

```bash
lxc exec $sales_CONTAINER -- sh -c \
  "sed -i 's/^mode: enforce/mode: fallback/' /etc/mssh/wrapper.yaml \
   && systemctl restart msshd"
```

Now:

```bash
# mssh stops working on that server (no TLS terminator):
MSSH_CERT=$PKI/bob.crt MSSH_KEY=$PKI/bob.key MSSH_CA=$PKI/user-ca.crt \
    mssh bob@$sales_IP:2200 -- whoami
# → mssh: TLS handshake failed: WRONG_VERSION_NUMBER

# Raw ssh on port 2200 works again (msshd is back to TCP-proxying):
ssh -p 2200 -i $BOB_KEY bob@$sales_IP whoami
# → bob
```

Flip it back:

```bash
lxc exec $sales_CONTAINER -- sh -c \
  "sed -i 's/^mode: fallback/mode: enforce/' /etc/mssh/wrapper.yaml \
   && systemctl restart msshd"
```

**What this proves:** the migration is reversible **per-server,
per-config-line**. Production operators with strict change-
management often spend weeks with some servers in each mode.
No big-bang cutover required.

---

## How the lab's `flip_to_*` helpers relate

The Phase-2 setup (`./setup_adhoc.sh` with no args, or `msshd 2`)
runs through steps 1–6 above for you AND installs helper scripts
on the CA host (`flip-to-fallback.sh`, `flip-to-enforce.sh`,
`flip-to-per-connection.sh`). Those helpers `ssh` into each server
container and run the `sed` + restart sequence from step 8 — the
same flip you'd do manually.

If you're exploring day-in-the-life operator flows (audit log,
banner customization, add/remove users at runtime), the prebuilt
Phase-2 lab is friendlier; see [TUTORIAL_USER_MANAGEMENT.md].

---

## Production runbook

The sequence matches [MIGRATION.md](MIGRATION.md) one-for-one:

| Tutorial step | Production runbook step |
|---|---|
| `setup_adhoc.sh msshd 1` | Operator installs msshd in fallback on every host |
| `mssh-admin server add` | Per-server enrollment ceremony |
| `scripts/mint-user-pki.py` | Org PKI mints user-CA + wrapper TLS + per-user mTLS |
| `ssh-keygen wrapper-user-ca` | Per-server, on-host signing key |
| `mssh-admin user add` + `policy add` | Per-user enrollment |
| push files + flip wrapper.yaml | Config-management rollout |
| `sed enforce→fallback` | Per-server rollback path |

---

## Known gaps

- **`mssh-admin pki`**: minting the user-CA + wrapper TLS + per-user
  mTLS is currently a separate script. See
  [design/future-ideas.md](../design/future-ideas.md) — folding this
  into a `mssh-admin pki bootstrap` / `mssh-admin user mint-mtls`
  surface is on the roadmap.
- **`mssh-admin import`**: importing existing `authorized_keys` into
  CA-side user enrollment is tracked as future-ideas §13.

---

## Tear down

```bash
exit                       # leave the adhoc> shell
./cleanup_containers.sh    # destroys the lab; keeps prebaked images
```

---

## Where to go next

  - **Day-in-the-life operator flows:** [TUTORIAL_USER_MANAGEMENT.md](TUTORIAL_USER_MANAGEMENT.md).
  - **Production migration playbook:** [MIGRATION.md](MIGRATION.md).
  - **Operate a deployed mssh:** [operations.md](operations.md).
