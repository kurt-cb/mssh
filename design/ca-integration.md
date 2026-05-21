# mssh-ca — install, configure, mint credentials for other apps

How to stand up `mssh-ca` and use it as your org's credential
service. SSH/mTLS, generic-TLS, HTTPS user certs, OpenVPN bundles,
code-signing certs, and WireGuard peer keypairs are **implemented
today** under `mssh-admin cert mint`, `mssh-admin openvpn issue`,
and `mssh-admin wireguard ...`. PGP/OpenPGP and ACME are still
**design only** — see [future-ideas.md §5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel).

Each subsection labels itself:

  - **✅ implemented** — has a stable CLI / API surface; operators can use it.
  - **🟡 partial** — crypto primitive lands in `cert_minter.py` today;
    operators have to call it from Python or stitch outputs by hand.
    The first-class CLI is the gap.
  - **🚧 design only** — needs new crypto family / library / endpoint.

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

### TLS server certs for internal services (X.509) ✅

```bash
mssh-admin cert mint --type tls-server \
                     --cn grafana.internal.example.com \
                     --san DNS:grafana.internal.example.com \
                     --san IP:10.10.0.42 \
                     --validity-days 30 \
                     --out grafana
# wrote grafana-cert.pem, grafana-key.pem, grafana-ca.pem
```

EKU = serverAuth. SAN syntax: `DNS:<name>`, `IP:<addr>`, or a bare
host (treated as DNS). Without `--out` the PEM cert + key are
written to stdout. Validity defaults to 90 days; capped at 825.

Audit entry lands as `cert.mint.tls-server` with `{cn, validity_days,
sans}`. Revocation goes through `mssh-admin cert revoke <serial>`
and propagates via the existing CRL feed.

For auto-renewal across the fleet, see
[`mssh-admin cert renew`](#cert-renew-) below — service-driven
refresh via daily systemd-timer, no ACME involved.

### HTTPS user (client) certs ✅

```bash
# PEM pair + .p12 bundle in one shot:
mssh-admin cert mint --type https-user --cn alice \
                     --p12-password CHANGEME --out alice
# wrote alice-cert.pem, alice-key.pem, alice-ca.pem
# wrote alice.p12 (PKCS#12, encrypted, mode 0600)
```

EKU = clientAuth. The `.p12` is browser-importable directly (Chrome
/ Firefox / Safari accept it native). The PEM pair authenticates on
any HTTPS endpoint that trusts the mssh-CA's `tls-ca-cert.pem` as a
client-cert root.

**This is the new dedicated verb.** Pre-v0.1.4 operators had to use
`mssh-admin admin add` to mint browser-mTLS certs — that path is
still there, but it (a) enrolls the recipient as an admin (showing
up in `mssh-admin admin list`), (b) logs the mint as `admin.add` in
the audit, (c) forces a permission role (`auditor`) even when the
recipient has no admin privileges, and (d) lacks the `--validity-days`
knob. `cert mint --type https-user` avoids all four: it signs a cert
and that's it. No enrollment row, no role, audit entry is
`cert.mint.https-user`.

### OpenVPN certs ✅

```bash
mssh-admin openvpn issue --cn alice \
                          --server-endpoint "vpn.example.com 1194" \
                          --validity-days 30 \
                          --out alice-vpn.ovpn
# wrote alice-vpn.ovpn (mode 0600)
```

Outputs a single `.ovpn` file with the client cert + key + CA inlined
plus the OpenVPN client directives (`client`, `dev tun`, `proto udp`,
`remote-cert-tls server`, `cipher AES-256-GCM`, `auth SHA256`).
Drop into any OpenVPN client; no further setup required.

`--proto {udp,tcp}` and `--dev {tun,tap}` flags exist for non-default
transports. Audit entry: `openvpn.issue` with full metadata.

Revocation: standard `mssh-admin cert revoke <serial>` appends to
the CRL log. Each leaf the CA issues carries a `CRLDistributionPoints`
extension pointing at the CA's signed X.509 CRL endpoint
(`GET /v1/crl.pem`) — set `crl_url` in `ca-config.yaml` to enable.
OpenVPN's `--crl-verify` reads the CRL directly from this URL, or
operators can pull it periodically with `curl` and feed it to OpenVPN.

### Code-signing certs ✅

Trace a binary back to a specific admin or build agent:

```bash
mssh-admin cert mint --type code-sign \
                     --cn "Build agent 03" \
                     --validity-days 180 \
                     --out build03
# wrote build03-cert.pem, build03-key.pem, build03-ca.pem
```

EKU = codeSigning (only — no clientAuth, no serverAuth). Default
validity is 365 days, longer than the TLS leafs since code-signing
certs commonly live longer than the artifacts they sign. Audit
entry: `cert.mint.code-sign`.

Useful when CI pipelines need to attest "this artifact was signed
by an authorized build identity." For long-term verifiability you
typically also need a timestamping authority — RFC 3161 timestamping
is a separate piece not part of v1 (operators can sign + timestamp
with a separate service like `signtool` / `osslsigncode`).

### WireGuard peer keypairs ✅

Non-X.509 — WireGuard uses raw Curve25519 keypairs plus metadata
(AllowedIPs, endpoint, persistent-keepalive). The CA owns the
keypair lifecycle and emits `wg-quick`-compatible config bundles.
Enable WireGuard on the CA by setting `wireguard.path` in
`ca-config.yaml` (path to a JSON catalog the CA maintains).

**Bootstrap a server (interface):**

```bash
mssh-admin wireguard server-init \
    --name wg0 \
    --network 10.20.0.0/24 \
    --endpoint vpn.example.com:51820
# created WireGuard server 'wg0' (pubkey xZ7yRzMnPg...)
```

The CA generates a Curve25519 keypair, allocates `10.20.0.1/24` as
the server address (first usable IP in the network), and records
the metadata. The server's private key never leaves the CA — pull
the config via `server-show` and install on the WireGuard host.

**Issue a peer:**

```bash
mssh-admin wireguard issue \
    --name alice \
    --server wg0 \
    --persistent-keepalive 25 \
    --out alice-wg.conf
# wrote alice-wg.conf (mode 0600 — contains private key)
```

Output is a ready-to-`wg-quick-up` config:

```ini
# mssh-admin wireguard issue — config for alice
[Interface]
Address    = 10.20.0.2/32
PrivateKey = <alice's freshly-minted private key>

# wg0
[Peer]
PublicKey  = <server's WG public key>
Endpoint   = vpn.example.com:51820
AllowedIPs = 10.20.0.0/24
PersistentKeepalive = 25
```

IP allocation is sequential — each new peer takes the next free
address in the server's network. Returns 507 (Insufficient Storage)
if the network is exhausted.

**Emit the server-side `wg0.conf`:**

```bash
mssh-admin wireguard server-show --name wg0 --out /etc/wireguard/wg0.conf
# wrote /etc/wireguard/wg0.conf
systemctl reload wg-quick@wg0    # or: wg syncconf wg0 <(wg-quick strip wg0)
```

Re-run after every `issue` / `revoke` and reload. Revocation
(`mssh-admin wireguard revoke --name alice --server wg0`) removes
the peer immediately from the CA catalog; reloading the server
applies the change.

**Auditor role** has read access (`server-list`, `server-show`,
`peer-list`); only `superuser` can init / issue / revoke.

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

### `cert renew` 🟡

Service-side auto-renewal of any cert mssh-ca has issued. The
**replacement for an ACME endpoint** — the 2026-05-21 direction
review dropped ACME (compatibility with certbot / cert-manager
isn't a goal) in favor of this simpler shape: a single
mTLS-authenticated endpoint where the cert being renewed IS the
auth credential.

```bash
# Run daily by systemd-timer on each service host.
mssh-admin cert renew \
    --cert /etc/grafana/tls.crt \
    --key  /etc/grafana/tls.key \
    --out-cert /etc/grafana/tls.crt \
    --out-key  /etc/grafana/tls.key \
    --threshold-days 14 \
    --on-renew "systemctl reload grafana"
```

What happens:

  1. Read the existing cert. Bail with exit 0 (no-op) if
     `not_after - now > threshold_days`.
  2. Open mTLS to mssh-ca presenting `--cert`/`--key` as the
     client identity. The CA validates the chain at the TLS
     layer (so already "we issued this") and checks it isn't in
     the CRL.
  3. The CA validates the cert is in its renewable window:
     - Early: `not_after - now ≤ renewal_window_days` (default 30)
     - Grace: `now - not_after ≤ grace_period_days` (default 7)
     - Outside both → 410 Gone, operator must re-mint.
  4. CA mints a new leaf with the same CN, SANs, EKU, and
     validity_days as the presented cert.
  5. Returns new PEM + key.
  6. CLI writes them atomically, runs `--on-renew`.

#### Renewable scope

Any cert mssh-ca has issued: from `cert mint --type {tls-server,
https-user, code-sign}`, from `openvpn issue`, from `server add`,
from `admin add`. All flow through the same renewal endpoint;
the CA infers the cert type from the presented cert's EKU + the
issuing intermediate.

#### What it does NOT do

  - **Doesn't auto-revoke the predecessor.** Already-expired
    certs don't need explicit revocation. Pre-expiry renewal of
    a still-valid cert leaves the old cert technically usable
    until its not_after. Operators who want immediate
    invalidation pass `--revoke-old`.
  - **Doesn't auto-renew indefinitely.** The CA enforces
    `cert_renewal_max_age_days` (default 2×validity). Past that,
    the service has to do a fresh `cert mint` — operator-mediated
    by design.
  - **Doesn't handle key rotation.** v1 keeps the existing
    private key. A future `--rotate-key` flag could mint a fresh
    keypair on renewal; not v1.

#### Systemd-timer template

```
# /etc/systemd/system/cert-renew@.service
[Unit]
Description=Renew mssh TLS cert for %i

[Service]
Type=oneshot
ExecStart=mssh-admin cert renew \
    --cert /etc/%i/tls.crt \
    --key  /etc/%i/tls.key \
    --out-cert /etc/%i/tls.crt \
    --out-key  /etc/%i/tls.key \
    --threshold-days 14 \
    --on-renew "systemctl reload %i"
```

```
# /etc/systemd/system/cert-renew@.timer
[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
```

Then per service:
```bash
systemctl enable --now cert-renew@grafana.timer
systemctl enable --now cert-renew@prometheus.timer
```

#### Why this beats ACME for an internal CA

  - ACME's value was being a drop-in for existing renewal
    automation. Without that goal, ACME's complexity (state
    machine, JWS, accounts, challenges) is parallel-system
    overhead.
  - mssh-ca already has every authorization signal it needs:
    "this cert presented itself" + "we issued it" + "it's not
    revoked" is sufficient evidence to renew. ACME's challenge
    layer (HTTP-01 / DNS-01 / TLS-ALPN-01) recreates the same
    signal via a different path.
  - 250 LOC server + 120 LOC client + 50 LOC systemd-timer vs.
    ~2000 LOC for a from-scratch RFC 8555 implementation.

### Passkey RP service for external tools 🚧

mssh-ca can act as a **WebAuthn relying party on behalf of external
applications**, using [mssh-passkey](mssh-passkey-module.md) as
the public-facing broker. An external tool with its own users gets
a turnkey passkey integration without having to embed WebAuthn
machinery itself: it pushes "challenge user X" through mssh-ca,
mssh-ca + mssh-passkey run the ceremony, the external tool gets
back a verified outcome.

Composes with [future-ideas §5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel)
— mssh-ca offering credential-ish services to neighboring
applications. Architectural decision in
[passkey-design-document.md](passkey-design-document.md) (Option 2 —
Browser-Native WebAuthn). Broker module in
[mssh-passkey-module.md](mssh-passkey-module.md).

This is **distinct from** the mssh-admin 2FA flow ([admin-2fa.md](admin-2fa.md)),
which gates *mssh-ca's own* privileged operations behind a
passkey ceremony. The dataflow has a different shape (more
hops, different consumer of the outcome). See the **Why two
flows?** subsection below if you're unsure which you want.

#### Architecture

mssh-ca holds the credentials, performs WebAuthn verification,
and acts as a service layer between the external tool and the
mssh-passkey broker. The external tool never talks to mssh-passkey
directly; it talks to mssh-ca, which talks to mssh-passkey, which
talks to the user's phone.

```
            ┌──────────────────────────┐
            │  external tool           │
            │   (separate application; │
            │    not part of mssh)     │
            │                          │
            │   "challenge user X      │
            │    for operation Y"      │
            └────────────┬─────────────┘
                         │  mTLS — external
                         │  tool authenticates
                         │  to mssh-ca with its
                         │  own client cert
                         ▼
            ┌──────────────────────────┐
            │  mssh-ca                 │
            │   (private network)      │
            │                          │
            │   • holds credentials    │
            │     PER EXTERNAL TOOL    │
            │     (each tool's users   │
            │      stored separately   │
            │      under tool_id)      │
            │   • generates options    │
            │   • verifies responses   │
            │   • forwards outcome to  │
            │     external tool        │
            └────────────┬─────────────┘
                         │  mTLS, same
                         │  passkey broker
                         │  as elsewhere
                         ▼
            ┌──────────────────────────┐
            │  mssh-passkey (broker)   │
            │   (public-facing, HTTPS) │
            └────────────┬─────────────┘
                         │
                         │ HTTPS (public web)
                         ▼
            ┌──────────────────────────┐
            │  user's phone browser    │
            └──────────────────────────┘
```

#### External-tool dataflow

End-to-end: an external tool wants its user `alice@externalcorp`
to approve operation Y. Three back-end layers + the browser.

```
  external tool         mssh-ca              mssh-passkey         user's
                     (private net)             (broker)            phone
       │                  │                       │                     │
       │ POST /v1/         │                       │                     │
       │ external/        │                       │                     │
       │ passkey/         │                       │                     │
       │ challenge        │                       │                     │
       │ (mTLS)           │                       │                     │
       │ {tool_id,        │                       │                     │
       │  user_id,        │                       │                     │
       │  description,    │                       │                     │
       │  ttl_seconds,    │                       │                     │
       │  outcome_url}    │                       │                     │
       ├─────────────────►│                       │                     │
       │                  │                       │                     │
       │                  │ 1. authn external     │                     │
       │                  │    tool by mTLS CN;   │                     │
       │                  │    lookup tool's      │                     │
       │                  │    enrollment +       │                     │
       │                  │    user_id's          │                     │
       │                  │    registered         │                     │
       │                  │    credentials        │                     │
       │                  │                       │                     │
       │                  │ 2. webauthn.          │                     │
       │                  │    generate_          │                     │
       │                  │    authentication_    │                     │
       │                  │    options(rp_id,     │                     │
       │                  │      allow_           │                     │
       │                  │      credentials=     │                     │
       │                  │      user's IDs)      │                     │
       │                  │                       │                     │
       │                  │ 3. POST /broker/      │                     │
       │                  │    ceremony  (mTLS)   │                     │
       │                  │    {type:"approve",   │                     │
       │                  │     options_json,     │                     │
       │                  │     description,      │                     │
       │                  │     callback_url=     │                     │
       │                  │       mssh-ca's own   │                     │
       │                  │       callback URL}   │                     │
       │                  │ ──────────────────►   │                     │
       │                  │                       │                     │
       │                  │ {ceremony_id, qr_url} │                     │
       │                  │ ◄──────────────────   │                     │
       │                  │                       │                     │
       │ 4. {ceremony_id, │                       │                     │
       │     qr_url}      │                       │                     │
       │ ◄────────────────│                       │                     │
       │                  │                       │                     │
       │ 5. (external     │                       │                     │
       │     tool sends   │                       │                     │
       │     qr_url to    │                       │                     │
       │     alice via    │                       │                     │
       │     its own UX)  │                       │                     │
       │                  │                       │                     │
       │                  │                       │   GET /approve/<id> │
       │                  │                       │ ◄───────────────────│
       │                  │                       │                     │
       │                  │                       │   page + ceremony   │
       │                  │                       │ ───────────────────►│
       │                  │                       │                     │
       │                  │                       │       6. WebAuthn   │
       │                  │                       │          get(opts)  │
       │                  │                       │                     │
       │                  │                       │ POST /approve/<id>/ │
       │                  │                       │ respond             │
       │                  │                       │ ◄───────────────────│
       │                  │                       │                     │
       │                  │ 7. POST callback      │                     │
       │                  │    {ceremony_id,      │                     │
       │                  │     outcome,          │                     │
       │                  │     response_json}    │                     │
       │                  │ ◄──────────────────   │                     │
       │                  │                       │                     │
       │                  │ 8. verify response    │                     │
       │                  │    against user's     │                     │
       │                  │    stored public      │                     │
       │                  │    key + signing      │                     │
       │                  │    counter            │                     │
       │                  │                       │                     │
       │                  │ 9. POST outcome_url   │                     │
       │                  │    (mTLS)             │                     │
       │                  │    {ceremony_id,      │                     │
       │                  │     outcome,          │                     │
       │                  │     user_id,          │                     │
       │                  │     verified: true}   │                     │
       │ ◄────────────────│                       │                     │
       │                  │                       │                     │
       │ 10. external tool│                       │                     │
       │     proceeds     │                       │                     │
       │     with Y       │                       │                     │
```

Notice the **two callback hops**: mssh-passkey calls back to
mssh-ca (its trust boundary stops there); mssh-ca then verifies
and calls back to the external tool's outcome_url. The external
tool never sees the raw `response_json` — only the verified
boolean + the ceremony metadata.

#### Per-tool isolation

Each external tool gets its own "namespace" in mssh-ca's
credential store. Tool `foo` enrolling `alice@foo` and tool `bar`
enrolling `alice@bar` are independent — different credentials,
different RP IDs (potentially), different audit lanes. Tools are
enrolled at mssh-ca with their own mTLS client certs (similar to
admin enrollment, but with a separate role):

```bash
mssh-admin external-tool add \
    --name internal-payroll-app \
    --rp-id payroll.example.com \
    --outcome-url-prefix https://payroll.example.com/mssh-callbacks/
```

This produces an mTLS client cert+key for the external tool to
present when calling mssh-ca's `/v1/external/passkey/...`
endpoints. mssh-ca records the tool's `name`, allowed `rp_id`,
and the URL prefix the tool's outcome callbacks must use (so a
compromised tool cert can only deliver outcomes to that tool's
own infrastructure, not somewhere unexpected).

#### Proposed CLI surface (mssh-ca)

```bash
# Tool lifecycle:
mssh-admin external-tool add    --name <tool> --rp-id <fqdn> --outcome-url-prefix <url>
mssh-admin external-tool list
mssh-admin external-tool remove --name <tool>

# User-under-tool lifecycle (parallels mssh-admin user passkey ...):
mssh-admin external-tool user-passkey enroll --tool <name> --user <user_id>
mssh-admin external-tool user-passkey list   --tool <name> --user <user_id>
mssh-admin external-tool user-passkey revoke --tool <name> --user <user_id> --credential-id <hex>
```

These all live under `mssh-admin external-tool ...` to keep them
visually distinct from the admin-2FA management commands
(`mssh-admin user passkey ...`), which operate on mssh-ca's own
admin enrollments.

#### Proposed mssh-ca endpoints (external-tool-facing)

  - `POST /v1/external/passkey/enroll-begin` — get a registration
    URL for a new user-under-tool credential
  - `POST /v1/external/passkey/challenge` — push an approval
    ceremony for an existing user-under-tool
  - `GET  /v1/external/passkey/ceremony/<id>` — poll fallback
  - `DELETE /v1/external/passkey/credential/<tool>/<user>/<cred_id>` —
    remote revoke
  - `POST /v1/external/passkey/admin/tool` — admin-only CRUD on
    external-tool enrollments

All mTLS-authenticated. The first four are scoped to the calling
tool's own users — tool `foo` cannot mint a challenge for a user
belonging to tool `bar`.

#### Why two flows?

The flow above and the [admin-2fa.md](admin-2fa.md) flow share
the broker, the WebAuthn protocol, and the cryptographic
verification path. They differ in:

| Aspect | admin-2fa flow | external-tool flow |
|---|---|---|
| Who is the user being challenged? | An mssh-ca admin (operator) | An end-user of an external tool |
| Where do their credentials live? | Under their admin record in mssh-ca's enrollment DB | Under their user record namespaced to a `tool_id` in mssh-ca's external-tool store |
| Who initiated the operation? | The admin themselves (via mssh-admin CLI) | The external tool (via mTLS to /v1/external/passkey/...) |
| Who consumes the verified outcome? | mssh-ca itself, to proceed with the privileged operation | The external tool, via a callback to its `outcome_url` |
| Number of callback hops | 1 (broker → mssh-ca) | 2 (broker → mssh-ca → external tool) |
| Audit trail location | mssh-ca's admin audit log | mssh-ca's external-tool audit log + the tool's own |

Use **admin-2fa** when you want to gate operations on mssh-ca
itself. Use **external-tool integration** when you have a
separate application that wants WebAuthn auth for its users and
doesn't want to embed the machinery.

#### Open questions

  - **Tool-level rate limits.** A buggy or compromised external
    tool could flood mssh-ca with ceremony requests. Per-tool
    rate limits should be configurable at `external-tool add`
    time. Probably defaulting to something like 10 ceremonies
    per minute per tool, raisable as needed.
  - **Tool-cert rotation.** Same shape as admin cert rotation;
    needs an explicit operator runbook entry.
  - **AAGUID allowlist per tool.** Should each external tool be
    able to require its own allowlist (different hardware
    standards for different applications)? Probably yes — a
    field on the external-tool enrollment record. v1 inherits
    mssh-ca's global allowlist; per-tool override is v2.
  - **Outcome_url scheme.** What scheme is `outcome_url` allowed
    to use? https:// only with mTLS validation, definitely;
    additional restrictions (must match `outcome_url_prefix`
    from enrollment) catch a compromised tool delivering to
    unexpected destinations.

#### Composition / cross-references

  - [mssh-passkey-module.md](mssh-passkey-module.md) — broker
    internals.
  - [admin-2fa.md](admin-2fa.md) — the *other* passkey flow:
    mssh-ca challenging its own admins.
  - [passkey-design-document.md](passkey-design-document.md) —
    architectural decision record for Option 2.
  - [browser.md § WebAuthn](browser.md#webauthn-with-hardware-only-authenticators--the-cleaner-path)
    — AAGUID allowlist + hardware-bound constraint.
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
  - Migrate per-service certs at renewal time — operator
    `cert mint`s once against mssh-ca, then `cert renew` takes
    over via systemd-timer (see "cert renew" above).

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
| TLS server certs (generic, internal services) | ✅ | `mssh-admin cert mint --type tls-server` |
| HTTPS user mTLS certs | ✅ | `mssh-admin cert mint --type https-user [--p12-password ...]` |
| OpenVPN cert + `.ovpn` bundle | ✅ | `mssh-admin openvpn issue` |
| Code-signing certs | ✅ | `mssh-admin cert mint --type code-sign` (codeSigning EKU; no TSA in v1) |
| WireGuard peer keypair + config | ✅ | `mssh-admin wireguard server-init / issue / server-show / revoke` |
| CRL Distribution Point embedded in leaves | ✅ | Set `cert_generation.crl_url` in `ca-config.yaml`; CA exposes `GET /v1/crl.pem` (X.509 CRL signed by the TLS CA) |
| PGP (OpenPGP) key directory + signing | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) + [§27](future-ideas.md#27-mscp--pgp-encrypted-file-transfer-using-the-ca-as-key-directory) — needs OpenPGP library + parallel signing key |
| Cert auto-renewal (`mssh-admin cert renew`) | 🟡 | `POST /v1/cert/renew` endpoint + CLI + systemd-timer template. **Replaces ACME** (dropped 2026-05-21). See `cert renew` section above. |
| ACME endpoint | ❌ | **DROPPED 2026-05-21.** ACME was for compatibility with existing renewal automation (certbot, cert-manager); not a goal for mssh-ca. Use `mssh-admin cert renew` instead. |
| Passkey integration (admin-2FA + external-tool RP) | ✅ | mssh-passkey broker module (v0.1.5) + mssh-ca shared bits + admin-2FA + external-tool RP. See [admin-2fa.md](admin-2fa.md) + [§ Passkey RP service](#passkey-rp-service-for-external-tools-) above |
| v2 PKI hierarchy (Root + named intermediates) | 🟡 | Foundation primitives landed; full migration is roadmapped at [notes-pki-hierarchy.md](notes-pki-hierarchy.md). Until v2 ships, all §5 leaves share one signing key — see "implication for currently-landed §5 work" below |

Remaining roadmap, in priority order:

  - **PGP (OpenPGP)** — composes with [§27](future-ideas.md#27-mscp--pgp-encrypted-file-transfer-using-the-ca-as-key-directory)
    (the `mscp` consumer). Needs an OpenPGP library and a parallel
    signing key with its own custody requirements.
