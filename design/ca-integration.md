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

ACME endpoint compatibility — so existing certbot-style clients can
use mssh-ca with no code changes — is the high-leverage adoption
multiplier still pending in §5.

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

### mssh-passkey integration for 2FA on CA operations 🚧

Composes with [future-ideas §6](future-ideas.md#6-require-2fa-for-high-privilege-roles-with-air-gap-fallback)
(2FA for high-privilege roles) and [§7](future-ideas.md#7-passkey--webauthn-support)
(Passkey / WebAuthn). Architectural decision and option evaluation
in [passkey-design-document.md](passkey-design-document.md)
(Option 2 — Browser-Native WebAuthn — is the selected default).

**Important scoping:** there are multiple potential consumers for
passkeys in the mssh ecosystem (mssh client step-up, admin web
portal step-up, kiosk login, etc.). This section is **only** about
the operator-facing use case: gating high-privilege CA operations
behind a passkey challenge. Other consumers can use the same
`mssh-passkey` module independently; their integration shape is out
of scope here.

The **module itself** (storage schema, registration ceremony,
broker API, browser pages, Apache2 deployment shape) is designed
in [mssh-passkey-module.md](mssh-passkey-module.md). This section
covers only what mssh-ca operators need to know to consume it.

#### Architecture: mssh-passkey is a **broker-only** separate module

mssh-passkey is a **new module, independent of mssh and mssh-ca**.
It lives on a public-facing server reachable both from the user's
phone browser (via HTTPS) and from mssh-ca (via mTLS).

Critically: **mssh-passkey is a relay only.** Credentials (public
keys, AAGUIDs, sign counts), challenge generation, attestation +
assertion verification, AAGUID allowlist enforcement — all of it
lives in mssh-ca. The broker holds in-flight ceremony state
(`options_json`, response, callback URL, TTL) and nothing else.

```
                            ┌────────────────────────────┐
                            │  mssh-ca                   │
                            │   (private network)        │
                            │                            │
                            │   • holds credentials       │
                            │     (in user enrollment    │
                            │      records)              │
                            │   • generates WebAuthn     │
                            │     options + challenges   │
                            │   • verifies attestation   │
                            │     + assertion responses  │
                            │   • enforces AAGUID        │
                            │     allowlist              │
                            └─────────────┬──────────────┘
                                          │
                                  mTLS,   │  (mssh-ca is a CLIENT
                                  full    │   of mssh-passkey;
                                  cert    │   not the other way
                                  valid.  │   around)
                                  both    │
                                  ways    │
                                          │
                            ┌─────────────▼──────────────┐
                            │  mssh-passkey  (broker)    │
                            │   (public-facing, HTTPS)   │
                            │                            │
                            │   • stores in-flight       │
                            │     ceremonies (one table) │
                            │   • serves register +      │
                            │     approve HTML pages     │
                            │   • RELAYS opaque blobs:   │
                            │       options_json down,   │
                            │       response_json up     │
                            │   • DOES NOT verify        │
                            │   • holds NO keys, NO      │
                            │     user identities        │
                            └─────────────┬──────────────┘
                                          │
                                          │  HTTPS (public web)
                                          │  user opens QR URL
                                          ▼
                            ┌────────────────────────────┐
                            │  user's phone browser      │
                            │   • mobile Safari / Chrome │
                            │   • navigator.credentials. │
                            │       create() / get()     │
                            │   • Face ID / Touch ID     │
                            │   • signs over the         │
                            │     mssh-ca-issued         │
                            │     challenge              │
                            └────────────────────────────┘
```

Key consequences of this split:

  - **mssh-ca stays private-network.** WebAuthn requires HTTPS +
    a public-resolvable origin for the browser; mssh-ca shouldn't
    take on either. mssh-passkey absorbs that responsibility for
    the user-facing TLS only — the cryptographic verification
    happens in mssh-ca behind the mTLS wall.
  - **The broker holds no keys.** Compromise of mssh-passkey
    cannot forge signatures or fabricate authentic credentials;
    the worst it can do is drop transactions or swap descriptions
    across in-flight ceremonies. Both are bounded incidents, not
    full identity-store breaches.
  - **One source of truth for credentials.** alice's registered
    authenticators sit in mssh-ca's enrollment record alongside
    her SSH keys + policies. No second database to sync.
  - **The broker is a generic relay.** Other consumers (msshd,
    admin web portal, future kiosks) can each hold their own
    credentials in their own enrollment DBs and share the broker
    without coordinating with mssh-ca.

#### Registration dataflow

End-to-end registration of alice's first authenticator. mssh-ca
generates the `PublicKeyCredentialCreationOptions` (with its own
challenge), the broker relays it to the browser, the browser does
the WebAuthn ceremony, and the response comes back through the
broker to mssh-ca which verifies + stores the credential.

```
  mssh-admin            mssh-ca              mssh-passkey         user's phone
   (operator)        (private net)             (broker)            (browser)
       │                  │                       │                     │
       │ user passkey     │                       │                     │
       │ enroll           │                       │                     │
       │ --user alice     │                       │                     │
       │  ──────────────► │                       │                     │
       │                  │                       │                     │
       │                  │ 1. webauthn.          │                     │
       │                  │    generate_          │                     │
       │                  │    registration_      │                     │
       │                  │    options(           │                     │
       │                  │      rp_id="passkey   │                     │
       │                  │             .example  │                     │
       │                  │             .com",    │                     │
       │                  │      user="alice")    │                     │
       │                  │ → options_json,       │                     │
       │                  │   challenge_bytes     │                     │
       │                  │                       │                     │
       │                  │ 2. store challenge    │                     │
       │                  │    locally under      │                     │
       │                  │    ceremony_id        │                     │
       │                  │                       │                     │
       │                  │ 3. POST /broker/      │                     │
       │                  │    ceremony  (mTLS)   │                     │
       │                  │    {type:"register",  │                     │
       │                  │     options_json,     │                     │
       │                  │     description,      │                     │
       │                  │     callback_url}     │                     │
       │                  │ ──────────────────►   │                     │
       │                  │                       │                     │
       │                  │                       │ 4. INSERT ceremony  │
       │                  │                       │    (stores opaque   │
       │                  │                       │     options_json +  │
       │                  │                       │     callback_url)   │
       │                  │                       │                     │
       │                  │ 5. {ceremony_id, url} │                     │
       │                  │ ◄──────────────────   │                     │
       │                  │                       │                     │
       │ 6. URL printed   │                       │                     │
       │ ◄────────────────│                       │                     │
       │                  │                       │                     │
       │ 7. (operator     │                       │                     │
       │     sends url    │                       │                     │
       │     to alice OOB)│                       │                     │
       │                  │                       │                     │
       │                  │                       │  GET /register/<id> │
       │                  │                       │ ◄───────────────────│
       │                  │                       │                     │
       │                  │                       │ 8. HTML page with   │
       │                  │                       │    options_json     │
       │                  │                       │    embedded         │
       │                  │                       │ ───────────────────►│
       │                  │                       │                     │
       │                  │                       │      9. navigator.  │
       │                  │                       │         credentials.│
       │                  │                       │         create(     │
       │                  │                       │           options)  │
       │                  │                       │         → Face ID   │
       │                  │                       │         → attestation
       │                  │                       │           Object    │
       │                  │                       │                     │
       │                  │                       │  POST /register/    │
       │                  │                       │  <id>/respond       │
       │                  │                       │  {attestation       │
       │                  │                       │   Object, client    │
       │                  │                       │   DataJSON,         │
       │                  │                       │   transports}       │
       │                  │                       │ ◄───────────────────│
       │                  │                       │                     │
       │                  │                       │ 10. UPDATE ceremony │
       │                  │                       │     outcome=        │
       │                  │                       │     "approved",     │
       │                  │                       │     response_json   │
       │                  │                       │     (broker does    │
       │                  │                       │      NOT verify)    │
       │                  │                       │                     │
       │                  │                       │ {ok: true}          │
       │                  │                       │ ───────────────────►│
       │                  │                       │                     │
       │                  │                       │      11. "Submitted"│
       │                  │                       │           page      │
       │                  │                       │                     │
       │                  │ 12. POST callback_url │                     │
       │                  │     (mTLS)            │                     │
       │                  │     {ceremony_id,     │                     │
       │                  │      outcome:         │                     │
       │                  │       "approved",     │                     │
       │                  │      response_json}   │                     │
       │                  │ ◄──────────────────   │                     │
       │                  │                       │                     │
       │                  │ 13. webauthn.verify_  │                     │
       │                  │     registration_     │                     │
       │                  │     response(         │                     │
       │                  │       response,       │                     │
       │                  │       expected_       │                     │
       │                  │         challenge,    │                     │
       │                  │       expected_rp_id, │                     │
       │                  │       expected_origin)│                     │
       │                  │                       │                     │
       │                  │     • signature valid?│                     │
       │                  │     • origin/rp_id    │                     │
       │                  │       match?          │                     │
       │                  │     • AAGUID in       │                     │
       │                  │       allowlist?      │                     │
       │                  │                       │                     │
       │                  │ 14. INSERT credential │                     │
       │                  │     into alice's      │                     │
       │                  │     enrollment        │                     │
       │                  │     record:           │                     │
       │                  │     (credential_id,   │                     │
       │                  │      public_key,      │                     │
       │                  │      aaguid,          │                     │
       │                  │      sign_count, ...) │                     │
       │                  │                       │                     │
       │                  │ 15. 200 OK            │                     │
       │                  │ ──────────────────►   │                     │
```

If any of mssh-ca's verifications fail at step 13 (signature
invalid, origin mismatch, AAGUID not in allowlist, etc.),
mssh-ca refuses to insert the credential, logs the failure with
the ceremony_id, and returns 200 to the broker anyway (the
broker doesn't care whether mssh-ca accepted — its job ended at
step 11). mssh-admin sees the registration as failed via mssh-ca's
own audit log.

#### Authentication (approval) dataflow

End-to-end approval of a pending high-privilege operation. Same
broker-only shape as registration; mssh-ca generates the
`PublicKeyCredentialRequestOptions` with alice's registered
credential IDs in `allowCredentials`, the broker relays it, the
browser signs the challenge, mssh-ca verifies and proceeds with
the original operation.

```
  mssh-admin            mssh-ca              mssh-passkey         user's phone
   (operator)        (private net)             (broker)            (browser)
       │                  │                       │                     │
       │ <high-privilege  │                       │                     │
       │  command>        │                       │                     │
       │  ──────────────► │                       │                     │
       │                  │                       │                     │
       │                  │ 1. check policy:      │                     │
       │                  │    "alice's role      │                     │
       │                  │     requires passkey  │                     │
       │                  │     2FA → defer the   │                     │
       │                  │     operation pending │                     │
       │                  │     ceremony"         │                     │
       │                  │                       │                     │
       │                  │ 2. lookup alice's     │                     │
       │                  │    registered         │                     │
       │                  │    credential_ids     │                     │
       │                  │                       │                     │
       │                  │ 3. webauthn.          │                     │
       │                  │    generate_          │                     │
       │                  │    authentication_    │                     │
       │                  │    options(           │                     │
       │                  │      rp_id, challenge,│                     │
       │                  │      allow_           │                     │
       │                  │      credentials=     │                     │
       │                  │      alice's IDs)     │                     │
       │                  │ → options_json,       │                     │
       │                  │   challenge_bytes     │                     │
       │                  │                       │                     │
       │                  │ 4. store ceremony     │                     │
       │                  │    locally:           │                     │
       │                  │    (ceremony_id,      │                     │
       │                  │     challenge,        │                     │
       │                  │     pending_op_id,    │                     │
       │                  │     description,      │                     │
       │                  │     expected_user=    │                     │
       │                  │     alice)            │                     │
       │                  │                       │                     │
       │                  │ 5. POST /broker/      │                     │
       │                  │    ceremony  (mTLS)   │                     │
       │                  │    {type:"approve",   │                     │
       │                  │     options_json,     │                     │
       │                  │     description=      │                     │
       │                  │       "Revoke admin   │                     │
       │                  │        cert for bob", │                     │
       │                  │     callback_url}     │                     │
       │                  │ ──────────────────►   │                     │
       │                  │                       │                     │
       │                  │                       │ 6. INSERT ceremony  │
       │                  │                       │                     │
       │                  │ {ceremony_id, qr_url} │                     │
       │                  │ ◄──────────────────   │                     │
       │                  │                       │                     │
       │ 7. URL printed   │                       │                     │
       │ ◄────────────────│                       │                     │
       │                  │                       │                     │
       │ 8. (operator     │                       │                     │
       │     sends url    │                       │                     │
       │     to alice via │                       │                     │
       │     slack/email/ │                       │                     │
       │     hands phone) │                       │                     │
       │                  │                       │                     │
       │                  │                       │   GET /approve/<id> │
       │                  │                       │ ◄───────────────────│
       │                  │                       │                     │
       │                  │                       │ 9. HTML page:       │
       │                  │                       │    description +    │
       │                  │                       │    [Approve][Deny]  │
       │                  │                       │    options_json     │
       │                  │                       │    embedded for JS  │
       │                  │                       │ ───────────────────►│
       │                  │                       │                     │
       │                  │                       │     10. navigator.  │
       │                  │                       │         credentials.│
       │                  │                       │         get(options)│
       │                  │                       │         → Face ID   │
       │                  │                       │         → assertion │
       │                  │                       │                     │
       │                  │                       │  POST /approve/<id>/│
       │                  │                       │  respond            │
       │                  │                       │  {credentialId,     │
       │                  │                       │   authData,         │
       │                  │                       │   clientDataJSON,   │
       │                  │                       │   signature}        │
       │                  │                       │ ◄───────────────────│
       │                  │                       │                     │
       │                  │                       │ 11. UPDATE ceremony │
       │                  │                       │     outcome=        │
       │                  │                       │     "approved",     │
       │                  │                       │     response_json   │
       │                  │                       │     (broker does    │
       │                  │                       │      NOT verify)    │
       │                  │                       │                     │
       │                  │                       │ {ok: true}          │
       │                  │                       │ ───────────────────►│
       │                  │                       │                     │
       │                  │                       │      12. "Submitted"│
       │                  │                       │                     │
       │                  │ 13. POST callback_url │                     │
       │                  │     (mTLS)            │                     │
       │                  │     {ceremony_id,     │                     │
       │                  │      outcome:         │                     │
       │                  │       "approved",     │                     │
       │                  │      response_json}   │                     │
       │                  │ ◄──────────────────   │                     │
       │                  │                       │                     │
       │                  │ 14. webauthn.verify_  │                     │
       │                  │     authentication_   │                     │
       │                  │     response(         │                     │
       │                  │       response,       │                     │
       │                  │       expected_       │                     │
       │                  │         challenge,    │                     │
       │                  │       expected_rp_id, │                     │
       │                  │       expected_origin,│                     │
       │                  │       credential_     │                     │
       │                  │         public_key,   │                     │
       │                  │       credential_     │                     │
       │                  │         current_sign_ │                     │
       │                  │         count)        │                     │
       │                  │                       │                     │
       │                  │     • signature valid?│                     │
       │                  │     • counter > prev? │                     │
       │                  │                       │                     │
       │                  │ 15. UPDATE alice's    │                     │
       │                  │     credential        │                     │
       │                  │     sign_count +      │                     │
       │                  │     last_used_at      │                     │
       │                  │                       │                     │
       │                  │ 16. APPROVE the       │                     │
       │                  │     original          │                     │
       │                  │     pending operation │                     │
       │                  │                       │                     │
       │                  │ 17. 200 OK            │                     │
       │                  │ ──────────────────►   │                     │
       │                  │                       │                     │
       │ 18. operation    │                       │                     │
       │     result       │                       │                     │
       │ ◄────────────────│                       │                     │
```

If alice clicks **Deny** instead, step 10 is replaced by a
`POST /approve/<id>/deny` (no WebAuthn). Broker sets
`outcome = "denied"`, callback posts back with the denial,
mssh-ca cancels the pending operation.

If the ceremony times out, the broker's sweeper runs every 30s
and marks expired ceremonies; mssh-ca either receives an
`"expired"` callback or learns via its own TTL poll on the
pending operation.

#### Operator flow (proposed)

```
1. Admin runs `mssh-admin <some-high-privilege-command> --user alice`.
2. Policy says alice's role requires passkey 2FA.
3. mssh-admin → mssh-ca: invoke the command.
4. mssh-ca → mssh-passkey (mTLS): "I need alice to approve this
   transaction. Here's the metadata: action=<desc>, ttl=5min."
5. mssh-passkey returns: transaction_id, qr_url
   (https://passkey.example.com/approve/<token>).
6. mssh-ca holds the operation pending; emits the qr_url back to
   mssh-admin, which displays it as a QR (or just a URL).
7. Admin sends the URL to alice (slack / email / hands phone).
8. alice opens the URL on her phone browser, sees "approve
   <action>?". She taps. Browser invokes WebAuthn; she completes
   biometric.
9. mssh-passkey verifies the WebAuthn assertion against alice's
   registered public key.
10. mssh-passkey notifies mssh-ca (webhook or polled):
    "transaction <id> approved by alice".
11. mssh-ca proceeds with the original operation; audit logged
    with the transaction_id + alice's verified identity.
```

#### Configuration

mssh-ca consumes mssh-passkey via config:

```yaml
# ca-config.yaml
passkey:
  # Public URL of the mssh-passkey service. Users will see this
  # in QR codes / browser address bar.
  url: https://passkey.example.com

  # mTLS cert + key mssh-ca presents when calling the broker
  # API. Signed by the operator's trust hierarchy; mssh-passkey
  # validates incoming clients against ca_cert below.
  client_cert: /etc/mssh-ca/passkey-client.crt
  client_key:  /etc/mssh-ca/passkey-client.key

  # Trust anchor for verifying mssh-passkey's own TLS cert. Full
  # cert validation in both directions.
  ca_cert: /etc/mssh-ca/passkey-server-ca.pem

  # Callback URL mssh-passkey hits when a transaction completes.
  # Hosted by mssh-ca on its existing admin listener; uses the
  # same mTLS hierarchy.
  callback_url: https://mssh-ca.internal:8443/v1/admin/passkey/callback
```

If `passkey:` is absent from ca-config.yaml, passkey 2FA is
unavailable and policies requiring it fail closed at policy load
time.

#### CLI surface (proposed)

```bash
# Initiate alice's first-time enrollment with the mssh-passkey
# module. Returns a QR-URL alice opens on her phone to register
# her hardware-bound credential. mssh-ca records (via callback)
# that alice has at least one credential registered.
mssh-admin user passkey enroll --user alice

# Show what mssh-passkey holds for alice (credentials, last-use
# timestamps). mssh-ca asks the broker via mTLS.
mssh-admin user passkey list --user alice

# Revoke a credential at the broker. mssh-ca calls passkey API
# with the credential ID.
mssh-admin user passkey revoke --user alice --credential-id <hex>

# Tag a policy as passkey-required.
mssh-admin policy add --user alice \
    --servers prod-* \
    --channels session \
    --require-2fa passkey \
    --2fa-within-seconds 60
```

Note these are all **CA-side** commands; the user-facing
ceremony happens in the browser at mssh-passkey's URL, not
through the mssh CLI.

#### Broker API surface (mTLS)

The two dataflow diagrams above show the request shapes. The
broker API is intentionally tiny: one POST to create a ceremony
(register or approve), one GET for status, one DELETE to cancel.
See [mssh-passkey-module.md § 5](mssh-passkey-module.md#5-broker-api-surface-mtls)
for the complete contract — the broker is its own module and the
contract lives in its own design doc.

#### Why this architecture (vs. WebAuthn at the CA directly,
or the broker holding keys)

Two earlier drafts collapsed for distinct reasons:

  1. **mssh-ca as WebAuthn RP directly** — WebAuthn requires a
     public HTTPS origin, which would pull mssh-ca out of its
     private network. Loses the core "stolen creds useless
     off-network" property.

  2. **Broker holds credentials** — A compromised broker could
     forge assertions. With credentials at mssh-ca and the broker
     as relay, a compromised broker can only drop transactions or
     swap descriptions (transaction-binding attack, bounded —
     mitigated by description correlation IDs and operator OOB
     confirmation).

The broker-only architecture is strictly better than either:

  - **Tiny attack surface.** No keys, no per-user data, no
    AAGUID allowlist. Broker compromise is bounded.
  - **One source of truth.** Credentials live alongside SSH keys
    in mssh-ca's enrollment record; no two-database sync.
  - **Multi-consumer reuse.** Any back-end with its own
    enrollment DB (msshd, future kiosks, admin web portal) can
    share the broker without coordinating with mssh-ca.

#### Composition / cross-references

  - **[future-ideas §6](future-ideas.md#6-require-2fa-for-high-privilege-roles-with-air-gap-fallback)** —
    2FA for high-privilege roles. mssh-passkey is the *passkey
    factor* implementation §6 mentions; TOTP/push are separate
    factors §6 still defers.
  - **[future-ideas §7](future-ideas.md#7-passkey--webauthn-support)** —
    Passkey / WebAuthn umbrella discussion. Settled by
    [passkey-design-document.md](passkey-design-document.md)
    Option 2.
  - **[passkey-design-document.md](passkey-design-document.md)** —
    architectural decision record (4 options, picked #2).
    Trust model details, server hardening requirements, threat
    matrix.
  - **[browser.md § WebAuthn](browser.md#webauthn-with-hardware-only-authenticators--the-cleaner-path)** —
    AAGUID allowlist rationale, hardware-bound-only constraint.
    Carries into mssh-passkey's registration validation.
  - **[§26 admin web portal](future-ideas.md#26-admin-web-portal-via-mssh-tunneled-localhost)** —
    *separate* consumer of mssh-passkey; the web portal can use
    the same broker API for step-up auth on destructive actions
    without going through mssh-ca. Out of scope here.

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
| TLS server certs (generic, internal services) | ✅ | `mssh-admin cert mint --type tls-server` |
| HTTPS user mTLS certs | ✅ | `mssh-admin cert mint --type https-user [--p12-password ...]` |
| OpenVPN cert + `.ovpn` bundle | ✅ | `mssh-admin openvpn issue` |
| Code-signing certs | ✅ | `mssh-admin cert mint --type code-sign` (codeSigning EKU; no TSA in v1) |
| WireGuard peer keypair + config | ✅ | `mssh-admin wireguard server-init / issue / server-show / revoke` |
| CRL Distribution Point embedded in leaves | ✅ | Set `cert_generation.crl_url` in `ca-config.yaml`; CA exposes `GET /v1/crl.pem` (X.509 CRL signed by the TLS CA) |
| PGP (OpenPGP) key directory + signing | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) + [§27](future-ideas.md#27-mscp--pgp-encrypted-file-transfer-using-the-ca-as-key-directory) — needs OpenPGP library + parallel signing key |
| ACME endpoint | 🚧 | [§5](future-ideas.md#5-the-ca-could-mint-credentials-for-other-applications-step-ca-parallel) — separate listener + RFC 8555 state machine; full server is ~2000+ LOC, deserves its own design pass |
| mssh-passkey integration (CA-side 2FA via separate broker) | 🚧 | mssh-passkey is a new public-facing module (per [passkey-design-document.md](passkey-design-document.md) Option 2); mssh-ca consumes it via mTLS. See this doc § "mssh-passkey integration for 2FA on CA operations". Two API contracts still to solidify (registration, public broker). |
| v2 PKI hierarchy (Root + named intermediates) | 🟡 | Foundation primitives landed; full migration is roadmapped at [notes-pki-hierarchy.md](notes-pki-hierarchy.md). Until v2 ships, all §5 leaves share one signing key — see "implication for currently-landed §5 work" below |

Remaining roadmap, in priority order:

  - **ACME endpoint** — biggest adoption multiplier (every certbot /
    cert-manager / lego deployment becomes a consumer), biggest
    implementation cost (~2000+ LOC for a from-scratch RFC 8555
    server). Most likely a library evaluation pass (`acme`/`josepy`
    from EFF) precedes any code.
  - **PGP (OpenPGP)** — composes with [§27](future-ideas.md#27-mscp--pgp-encrypted-file-transfer-using-the-ca-as-key-directory)
    (the `mscp` consumer). Needs an OpenPGP library and a parallel
    signing key with its own custody requirements.
