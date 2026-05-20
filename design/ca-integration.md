# mssh-ca — install, configure, mint credentials for other apps

How to stand up `mssh-ca` and use it as your org's credential
service. The first half (install + SSH/mTLS credential minting) is
**implemented today**. The second half (OpenVPN, WireGuard, PGP,
generic TLS, code-signing) is the **§5 design proposal** — see
[future-ideas.md §5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel)
for status. Each subsection below labels itself ✅ (implemented),
🟡 (partial), or 🚧 (design only) so operators can tell what they
can use today vs. what's planned.

Cross-references:
  - Day-to-day operator tasks: [operations.md](../docs/operations.md).
  - Architectural rationale for the three trust hierarchies:
    [architecture.md](architecture.md) and [security.md](security.md).
  - Live walkthrough in the adhoc lab: [TUTORIAL_USER_MANAGEMENT.md](../docs/TUTORIAL_USER_MANAGEMENT.md).

---

## Part 1 — Install and configure `mssh-ca` ✅

### The trust hierarchies you'll touch

mssh-ca's bootstrap produces three logical hierarchies. Each has a
separate lifecycle. Keep them straight before you start minting:

| Hierarchy | Signs | Where keys live | Today's CLI surface |
|---|---|---|---|
| **CA signing key** | Authorization X.509 certs, server mTLS, admin mTLS | `<ca-dir>/signing-key.pem` (CA host only) | `mssh-admin init`, `server add`, `admin add` |
| **User-facing CA** | mssh client mTLS certs, msshd's TLS server cert on `:2200` | Operator's PKI — *not* the mssh-CA process | `scripts/mint-user-pki.py` (or any org PKI); future `mssh-admin pki` ([§25](future-ideas.md#25-mssh-admin-pki--first-class-user-facing-pki-ceremony)) |
| **msshd local user-CA** | Ephemeral OpenSSH user certs handed to the hermetic inner sshd | Per-msshd, under `/var/lib/mssh/wrapper-user-ca` (never leaves the host) | `ssh-keygen` at host provisioning time |

The §5 expansion (OpenVPN, WireGuard, PGP, generic TLS) adds **new
per-protocol hierarchies under the CA signing key**, with their
own intermediate certs where appropriate. The user-facing CA and
the per-msshd local user-CA are unchanged.

### Bootstrap

```bash
mssh-admin init --ca-dir /etc/mssh-ca
```

Outputs in `/etc/mssh-ca/`:

```
signing-key.pem                       # CA signing key — protect carefully
signing-cert.pem                      # CA signing root (self-signed)
tls-server-cert.pem  tls-server-key.pem   # CA's HTTPS listener identity
tls-ca-cert.pem      tls-ca-key.pem       # signs server/admin mTLS
bootstrap-admin-cert.pem
bootstrap-admin-key.pem
ca-config.yaml                        # service config (port, paths)
```

Move `bootstrap-admin-{cert,key}.pem` to your operator workstation
(`~/.mssh-admin/` per convention). Subsequent `mssh-admin` commands
use those as the initial admin identity. Audit-only and additional
superusers come from `mssh-admin admin add` against this bootstrap
identity.

### Start the service

Via systemd (unit shipped under `systemd/mssh-ca.service`):

```bash
systemctl enable --now mssh-ca
```

Or in the foreground:

```bash
mssh-ca --config /etc/mssh-ca/ca-config.yaml
```

The CA listens HTTPS on the port in `ca-config.yaml` (default 8443).
mTLS-authenticated; clients (msshd, mssh-admin) present a cert
signed by `tls-ca-key.pem`. Admin endpoints additionally check that
the client subject is in the enrolled admin set.

See [operations.md § bootstrap a CA](../docs/operations.md#bootstrap-a-ca)
for the operator-facing playbook including custody guidance.

### Where each artifact goes

```
Operator workstation:                  CA host:                      Each msshd host:
~/.mssh-admin/                         /etc/mssh-ca/                 /etc/mssh/
├── config (URL + cert paths)          ├── signing-key.pem           ├── wrapper.yaml
├── bootstrap-admin-cert.pem    <──    ├── signing-cert.pem          ├── wrapper-mtls.crt   <── mssh-admin server add
├── bootstrap-admin-key.pem     <──    ├── tls-ca-cert.pem      ──>  ├── server-mtls-ca.pub
└── tls-ca-cert.pem             <──    ├── tls-ca-key.pem            ├── user-ca.pub        <── user-facing CA
                                       ├── tls-server-cert.pem       └── wrapper-server.crt <── user-facing CA
                                       └── tls-server-key.pem        /var/lib/mssh/
                                                                     └── wrapper-user-ca    <── ssh-keygen, local
```

The arrows show "where this file came from" — copy them at install
time. Nothing flows back to the CA after bootstrap.

---

## Part 2 — Minting credentials today ✅

### Server mTLS cert (msshd → CA channel)

```bash
mssh-admin server add --name srv-acct \
                       --groups accounting \
                       --out-dir ./srv-acct-creds
```

Produces in `./srv-acct-creds/`:

  - `ca-cert.pem` — the CA's TLS root (so the server trusts the CA's HTTPS listener).
  - `srv-acct-cert.pem` — the server's mTLS client cert (signed by `tls-ca-key.pem`).
  - `srv-acct-key.pem` — the matching private key (mode 600).

Push to `/etc/mssh/wrapper-mtls.{crt,key}` on the server; restart
msshd. The cert validity defaults to 30 days; rotation is
`mssh-admin server remove && mssh-admin server add` (the web portal's
**Re-issue mTLS** button automates this — see
[operations.md § browse from a web UI](../docs/operations.md#browse-the-deployment-from-a-web-ui-msshd-admin-web)).

### Admin mTLS cert

The bootstrap admin is minted at `mssh-admin init` time. Additional
admins:

```bash
mssh-admin admin add --name carol --role superuser
# (admin cert + key returned in the response; distribute carefully)
```

Same signing key as server mTLS; the CA recognises them by checking
the subject CN against the admin enrollment set + the role
(`superuser` vs `auditor`).

### User-facing PKI — wrapper TLS cert + per-user mTLS

This is the **user-facing CA hierarchy**, separate from the CA
signing key. Today it's minted by a standalone helper:

```bash
python scripts/mint-user-pki.py \
    --out-dir ./user-pki \
    --servers "srv-acct:10.0.0.10,srv-sales:10.0.0.11" \
    --users   "alice,bob,carol"
```

Produces:

  - `user-ca.crt` / `user-ca.key` — the user-facing CA root + signing key.
  - `wrapper-<server>.crt` / `.key` — the cert msshd serves on
    port 2200 (signed by user-ca).
  - `<user>.crt` / `<user>.key` — per-user mTLS client cert
    (signed by user-ca), what the `mssh` CLI presents.
  - `<user>.pub` — the SSH-ed25519 wire form of the same Ed25519
    key, ready for `mssh-admin user add --key`.

Distribution: `user-ca.crt` becomes `/etc/mssh/user-ca.pub` on
every msshd host; `wrapper-<server>.{crt,key}` lands on that
server as `/etc/mssh/wrapper-server.{crt,key}`; `<user>.{crt,key}`
goes to that user's workstation as `~/.mssh/cert.pem` /
`~/.mssh/key.pem`.

The standalone script is a stopgap. The first-class CLI
(`mssh-admin pki bootstrap / server mint / user mint`) is tracked
as [§25](future-ideas.md#25-mssh-admin-pki--first-class-user-facing-pki-ceremony) — same
shape, just folded into the main CLI.

### msshd local user-CA (per-msshd OpenSSH signing key)

Generated **on each msshd host**, never visible to the CA:

```bash
# As part of msshd install on each server:
mkdir -p /var/lib/mssh /var/lib/mssh/inner-sshd
ssh-keygen -t ed25519 -N '' -f /var/lib/mssh/wrapper-user-ca \
           -C "wrapper-user-ca-$(hostname)"
chmod 600 /var/lib/mssh/wrapper-user-ca
cp /var/lib/mssh/wrapper-user-ca.pub \
   /var/lib/mssh/inner-sshd/wrapper-user-ca.pub
```

msshd uses this to mint **ephemeral** OpenSSH user certs (typically
60-second validity) on every authorized connection. The inner sshd
trusts this CA via the `TrustedUserCAKeys` directive. Loss of this
key means an attacker on the msshd host can forge inner-sshd
sessions — but only on *that* host; the CA's authorize step is
unaffected.

### Audit log

Every minting operation lands in the audit log:

```bash
mssh-admin audit --type admin --limit 20
# shows server.add, user.add, admin.add, ... events
```

For authorization decisions (every connection):

```bash
mssh-admin audit --decision denied
```

---

## Part 3 — Extension: minting credentials for other applications 🚧

The remainder of this document describes the **§5 design proposal**.
None of it is implemented as of v0.1.1. Treat these sections as the
target shape for `mssh-admin` and `mssh-ca`; the LOC estimates in
§5 are the budget for shipping each piece.

### Design notes that apply to all extensions

  - **Each protocol gets its own intermediate cert** under the CA
    signing root, so leaf rotations don't churn the trust anchor and
    operators can audit per-protocol usage cleanly.
  - **Same enrollment DB.** A WireGuard peer for alice references
    the same enrollment record as her SSH cert; revoke once,
    propagate everywhere.
  - **Same policy DSL.** Validity windows, source CIDRs, and the
    channels/SANs lists extend rather than replace the existing
    policy schema.
  - **Same audit log.** Every mint / renew / revoke lands in
    `audit.jsonl` with `type=cert.<protocol>`. One tail for the
    whole credential surface.

### TLS server certs for internal services (X.509) 🚧

The most direct §5 extension — same minting machinery as the user-
facing CA's wrapper server certs, exposed as a first-class admin
operation:

```bash
# Proposed shape (§5):
mssh-admin cert mint --type tls-server \
                     --cn grafana.internal.example.com \
                     --san DNS:grafana.internal.example.com \
                     --san IP:10.10.0.42 \
                     --validity-days 30 \
                     --out grafana-cert.pem grafana-key.pem
```

ACME endpoint compatibility (so existing certbot-style clients can
use mssh-ca with no code changes) is the high-leverage adoption
multiplier in §5; budgeted separately.

### HTTPS user (client) certs 🚧

Browser-imported mTLS for authenticating users to internal HTTPS
apps. Same signing machinery as the user-facing CA mTLS path; the
difference is the consumer (browser keystore vs `mssh` CLI):

```bash
# Proposed shape:
mssh-admin cert mint --type https-user \
                     --user alice \
                     --validity-days 90 \
                     --out alice-https.p12
```

`.p12` (PKCS#12) output for one-click browser import.

### OpenVPN certs 🚧

OpenVPN uses standard X.509 PKI — same cert_minter.py codepath as
TLS server / HTTPS-user certs, plus an exporter that emits a
`.ovpn` config bundle with the cert+key+CA stitched together:

```bash
# Proposed shape:
mssh-admin openvpn issue --user alice \
                          --server-cn vpn.example.com \
                          --validity-days 30 \
                          --out alice-vpn.ovpn
```

The `.ovpn` carries the user's leaf cert + key + the OpenVPN
server's CA fingerprint + the server endpoint. User imports into
their OpenVPN client and connects. Revocation goes through the
same CRL (`mssh-admin cert revoke <serial>`) that already drives
the authz cert flow.

### Code-signing certs 🚧

Trace a binary back to a specific admin or build agent:

```bash
# Proposed shape:
mssh-admin cert mint --type code-sign \
                     --cn "Build agent 03" \
                     --validity-days 180 \
                     --out build03-codesign.p12
```

Useful when CI pipelines need to attest "this artifact was signed
by an authorized build identity." Mostly endpoint plumbing; the
crypto is identical to other X.509 leafs.

### WireGuard peer keypairs 🚧

Non-X.509 — WireGuard uses raw Curve25519 keypairs plus metadata
(AllowedIPs, endpoint, persistent-keepalive). The CA owns the
keypair lifecycle but can't sign anything; it stores per-user /
per-host metadata and emits `wg-quick`-compatible config bundles:

```bash
# Proposed shape:
mssh-admin wireguard server init \
                              --interface wg0 \
                              --network 10.20.0.0/24 \
                              --endpoint vpn.example.com:51820

mssh-admin wireguard issue --user alice \
                            --server wg0 \
                            --out alice-wg.conf
```

Output is a ready-to-import `wg-quick` config:

```ini
[Interface]
PrivateKey = <alice's freshly-minted private key>
Address    = 10.20.0.10/32
DNS        = 10.20.0.1

[Peer]
PublicKey  = <server's WG public key>
Endpoint   = vpn.example.com:51820
AllowedIPs = 10.20.0.0/24
PersistentKeepalive = 25
```

Revocation removes the peer from the server's `wg0` config, which
admins push to the WireGuard host (a small daemon on the WG server
polls `mssh-admin wireguard sync` and rewrites `/etc/wireguard/wg0.conf`).
For details on the polling agent see future design doc;
v1 leaves operators to script the sync.

### PGP (OpenPGP) keys 🚧

Different crypto family entirely; needs an OpenPGP library and a
parallel signing key. The CA grows a **PGP signing key** (separate
from the X.509 signing key), used to sign user PGP keys analogous
to a private OpenPGP CA:

```bash
# Proposed shape:
mssh-admin pki gpg init                                # generates CA's PGP signing key (one-time)
mssh-admin user pgp-key mint --user alice              # mints alice's PGP keypair, signs it
mssh-admin user pgp-key set  --user alice --key alice.asc   # OR import a user-supplied public key

mssh-admin user pgp-key show --user alice              # ASCII-armored pubkey, by username
mssh-admin user pgp-key remove --user alice            # revokes (signature withdrawn)
```

Consumers (e.g., the `mscp` proposal in
[§27](future-ideas.md#27-mscp--pgp-encrypted-file-transfer-using-the-ca-as-key-directory))
fetch by username and trust the CA's signature as proof of identity:

```bash
mscp encrypt --to alice payroll-Q2.xlsx > payroll-Q2.xlsx.gpg
# resolves alice → CA fetch → gpg encrypt → blob safe for any transport
```

The PGP signing key has its own custody requirements — separate
from the X.509 signing key — and is the largest piece of the §5
budget (~700 LOC).

### ACME endpoint compatibility 🚧

A separate listener on mssh-ca speaking RFC 8555 (ACME). Lets
existing `certbot` / lego / cert-manager clients use mssh-ca with
no code changes:

```bash
# On a server that wants a TLS cert from mssh-ca:
certbot certonly --server https://mssh-ca.internal:8443/acme/v1 \
                 --email ops@example.com \
                 -d service.internal.example.com
```

ACME's account model maps to mssh-CA's admin / server enrollment
records; account creation requires a one-time admin-approved
enrollment. Highest adoption-value piece of §5 once the X.509
expansion is in.

---

## Part 4 — Policy and audit across credential types 🚧

The existing policy DSL (`mssh-admin policy add --user --servers
--channels --max-validity ...`) extends to each new credential
type rather than getting a separate per-type policy surface:

```bash
# Proposed shape — policies span credential types:
mssh-admin policy add --user alice \
                      --types ssh-session,openvpn,wireguard \
                      --max-validity-days 30 \
                      --source-cidrs 10.20.0.0/16
```

Authorize calls for any cred type land in the same audit log:

```bash
mssh-admin audit --type cert.openvpn --user alice --limit 20
mssh-admin audit --decision denied --since "2026-05-01"
```

Revocation is unified: `mssh-admin cert revoke <serial>` works for
any X.509 leaf; `mssh-admin wireguard revoke --user alice`
removes the peer; `mssh-admin user pgp-key remove` retracts the
PGP signature.

---

## Part 5 — Migration recipes 🚧

Most orgs already have *some* PKI today. mssh-ca's value is in
**unifying** that, not in replacing each piece overnight. Sketched
migration paths for the common cases:

### From an existing internal X.509 CA

  - Issue the new mssh-ca signing key as an intermediate signed
    by the existing root. All existing trust stores keep working
    until you're ready to flip the trust anchor.
  - Migrate per-service certs at renewal time — point each
    service's renewal script at mssh-ca's ACME endpoint.

### From an existing OpenVPN deployment

  - Stand up mssh-ca with `--issue-openvpn-as` pointing at your
    existing OpenVPN CA's serial-number range to avoid collisions
    during the cross-over.
  - New users get mssh-issued `.ovpn` bundles via
    `mssh-admin openvpn issue`; legacy users keep their old certs
    until they expire.
  - When the last legacy cert expires, decommission the old CA.

### From an existing WireGuard deployment

  - mssh-admin wireguard import scans an existing `wg0.conf`,
    creates one user enrollment per `[Peer]`, and stores the
    public keys. (Private keys stay where they are — mssh-ca only
    issues new private keys for new enrollments.)
  - Future revocations / rotations go through mssh-admin; legacy
    peers can continue indefinitely.

### From "every user picks their own PGP key"

  - Operator publishes a "trusted PGP keys" page rendered by
    mssh-ca from the enrollment DB.
  - Users upload their existing PGP public keys via
    `mssh-admin user pgp-key set`. The CA signs each one with its
    OpenPGP signing key; downstream verifiers check the CA's
    signature as proof of org-vouched identity.
  - Users who don't have a PGP key get one minted by the CA via
    `mssh-admin user pgp-key mint`.

---

## Status summary

| Capability | Status | Where |
|---|---|---|
| `mssh-admin init` — CA bootstrap | ✅ | [operations.md](../docs/operations.md#bootstrap-a-ca) |
| Server mTLS cert (for msshd → CA) | ✅ | `mssh-admin server add` |
| Admin mTLS cert | ✅ | `mssh-admin admin add` |
| User-facing mTLS + wrapper TLS | 🟡 | `scripts/mint-user-pki.py`; `mssh-admin pki` ([§25](future-ideas.md#25-mssh-admin-pki--first-class-user-facing-pki-ceremony)) pending |
| msshd local user-CA (per-host) | ✅ | `ssh-keygen` at install time |
| TLS server certs (generic, internal services) | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) |
| HTTPS user mTLS certs | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) |
| Code-signing certs | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) |
| OpenVPN cert + `.ovpn` bundle | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) |
| WireGuard peer keypair + config | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) |
| PGP (OpenPGP) key directory + signing | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) + [§27](future-ideas.md#27-mscp--pgp-encrypted-file-transfer-using-the-ca-as-key-directory) |
| ACME endpoint | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) |

Sensible incremental rollout: X.509 expansion (TLS server, HTTPS
user, OpenVPN, code-sign) → ACME → WireGuard → PGP. The X.509
chunk is the highest payoff for the smallest risk; everything
after that depends on actual operator demand.
