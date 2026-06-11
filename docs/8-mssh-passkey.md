# mssh-passkey — broker deployment manual

**Design reference:** [design §8 mssh-passkey](../design/mssh_design_v1.md#8--module-mssh-passkey-).

mssh-passkey is the WebAuthn ceremony broker. It's **optional** —
deploy it only if you want admin-2FA (§13.5) or want to expose
mssh-ca as a WebAuthn RP for external tools (§13.6).

---

## Why a broker exists

mssh-ca lives on a private network and should never accept browser
traffic from the internet. The broker is the internet-facing piece;
mssh-ca talks to it over mTLS from inside the trusted network.

The broker holds **no key material** and **no per-user state** — only
short-lived ceremony records (typically 5-minute lifetime). It's a
relay.

---

## Deploy

```sh
# 1. Install (system pkg)
sudo apt install mssh-passkey

# 2. Mint a broker cert (signed by host-mint, by an mssh-ca superuser):
mssh-admin cert mint --type tls-server --cn passkey.example.com \
  --san DNS:passkey.example.com --out passkey-cert.pem

# 3. Install /etc/mssh-passkey/config.yaml (see §14.3.4)

# 4. Set up apache2 as TLS terminator + reverse proxy
#    (config sketch in design §15.8)

# 5. Start
sudo systemctl enable --now mssh-passkey

# 6. Tell mssh-ca about it (in ca-config.yaml's admin_2fa: block):
#    broker_url: https://passkey.example.com
```

---

## Front-end variants

```yaml
# /etc/mssh-passkey/config.yaml
front_end: apache    # production: apache2 reverse proxy terminates TLS
# OR
front_end: dev       # lab: broker terminates TLS in-process (single port)
```

Production: apache2 listens on 443 with a public TLS cert;
reverse-proxies to the broker's mTLS port for backend endpoints and
its HTTPS port for browser pages.

Lab: broker binds two ports directly. No apache2 needed.

Design: [§8.3.6 front-end variants](../design/mssh_design_v1.md#836--front-end-variants-) +
[§15.8 apache2 integration](../design/mssh_design_v1.md#158-apache2-as-tls-terminator--reverse-proxy-).

---

## Hardening v2 (v1 ship blocker)

The broker is internet-facing. v1 hardening defends mssh-ca
**even if the broker is compromised**. The defenses live in mssh-ca
(not the broker), so they ship regardless of whether you deploy the
broker.

If you DO deploy the broker, audit:
- `admin_2fa.fail_state: fail-closed` (default in v1; do not change).
- The broker's mTLS cert allowlist on mssh-ca.
- Apache2's rate-limiting + log retention.

Design: [§8.3.7 hardening v2](../design/mssh_design_v1.md#837--hardening-v2-anti-compromised-broker---p2--v1-ship-blocker-unconditional) +
[§13.9.1](../design/mssh_design_v1.md#1391--passkey-broker-hardening-v2--837).

---

## What it stores

| Path | Contents | Design § |
|------|----------|---------|
| `/var/lib/mssh-passkey/ceremonies.sqlite` | Single table, short-lived ceremonies | §14.6 + §8.3.1 |
| `/etc/mssh-passkey/{cert,key}.pem` | Broker's mTLS cert (host-mint signed) | §3.6 |
| `/var/log/mssh-passkey/` | Daemon log | §17.5 |

No long-term user state. Expired ceremonies are deleted after 24h
(configurable via `callback.retention_window_seconds`).

---

## Replaceable broker (3rd-party integration)

The §3.6 wire protocol is a frozen v1 contract. A 3rd party can
run their own broker as long as it speaks:
- `POST/GET/DELETE /broker/ceremony[/<id>]` per §8.3.2.
- The callback delivery protocol per §8.3.4.
- mTLS-gating with `X-Client-CN`.

Design: [§15.4 replaceable broker](../design/mssh_design_v1.md#154-replaceable-mssh-passkey-broker-).

---

## Related docs

- [docs/4-mssh-ca.md § Adopt 2FA](4-mssh-ca.md#adopt-2fa-for-admins) — wiring the broker to mssh-ca
- [docs/7-mssh-admin.md § 2FA prompts](7-mssh-admin.md#2fa-prompts) — what operators see
- [docs/15-third-party-integration.md](15-third-party-integration.md) — external-tool RP flows that use the broker
