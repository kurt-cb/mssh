# msshd — operator manual

**Design reference:** [design §5 msshd](../design/mssh_design_v1.md#5--module-msshd).
Tutorial tone; design § is canonical.

msshd is the server-side gateway daemon. Every SSH-reachable host
in your mssh deployment runs msshd; it sits in front of (or
replaces) the operator's existing sshd.

---

## Pick a mode

Three modes, picked per host via `msshd.yaml` `mode:` field. Reversible
by config edit. The adoption journey is **fallback → gated → enforce**
(§13.8).

| Mode | What it does | When to use it |
|------|-------------|----------------|
| `fallback` | TCP proxy to your existing sshd, no CA | day 1: prove the gateway is wired in |
| `gated` 🚧 | mTLS + CA approval, then proxy to your sshd | week+: gate access via CA without changing auth |
| `enforce` | mTLS + CA + ephemeral cert + hermetic inner sshd | month+: fully CA-mediated |

Design: [§1.4 operating modes](../design/mssh_design_v1.md#14--operating-modes).

---

## Install

```sh
# 1. Install (system pkg)
sudo apt install msshd

# 2. Enroll the server via mssh-admin (on your workstation)
mssh-admin server add this-host-name --group production
# Capture the mTLS cert/key from the response.

# 3. Install certs + trust anchors on this msshd
sudo install -m 0644 host-mint.pem /etc/mssh/host-mint.pem
sudo install -m 0644 auth.pem      /etc/mssh/auth.pem
sudo install -m 0644 bypass-mint.pem /etc/mssh/bypass-mint.pem
sudo install -m 0644 -o _msshd msshd-server-cert.pem /etc/mssh/
sudo install -m 0600 -o _msshd msshd-server-key.pem  /etc/mssh/
# (similarly for the msshd-mtls-*.pem pair)

# 4. Write /etc/mssh/msshd.yaml (see §14.3.1)

# 5. Move your existing sshd off port 22 (e.g. to 22022)
#    and start msshd on port 22:
sudo systemctl enable --now msshd
```

---

## What lives where

| Path | Contents | Design § |
|------|----------|---------|
| `/etc/mssh/msshd.yaml` | Mode + CA URL + paths | §14.3.1 |
| `/etc/mssh/host-mint.pem` | CA TLS-cert validation pin | §2.3 |
| `/etc/mssh/auth.pem` | Incoming client-cert validation pin | §2.3 |
| `/etc/mssh/bypass-mint.pem` | Bypass-cert validation pin | §2.3 |
| `/etc/mssh/msshd-mtls-*.pem` | msshd→CA client mTLS | §3.2 |
| `/etc/mssh/msshd-server-*.pem` | Outer TLS server cert | §3.1 |
| `/var/lib/mssh/inner-host-key{,.pub}` | Hermetic inner sshd host key | §5.3.10 |
| `/var/lib/mssh/user-ca-key{,.pub}` | msshd's local user-CA | §5.3.13 |
| `/var/lib/mssh/authz_cache.json` | Per-principal authz cache | §5.3.5 + §14.6 |
| `/var/log/mssh/msshd.log` | Daemon log | §17.5 |
| `/run/mssh/msshd-admin.sock` | Diagnostic CLI socket | §5.3.14 |

---

## Common tasks

### Flip mode

```sh
# Edit /etc/mssh/msshd.yaml `mode:` field
sudo systemctl reload msshd     # or restart
```

The flip is reversible; no state migrates between modes.

### Inspect the authz cache

```sh
sudo msshd-admin status
sudo msshd-admin authz-cache show
sudo msshd-admin authz-cache show alice@srv-acct-01
sudo msshd-admin authz-cache invalidate alice@srv-acct-01
```

Design: [§5.3.14 msshd-admin diagnostic CLI](../design/mssh_design_v1.md#5314--msshd-admin-diagnostic-cli-).

### Rotate the local user-CA

```sh
sudo msshd-admin user-ca rotate
sudo systemctl reload msshd
```

The inner sshd reloads `TrustedUserCAKeys`. Existing ephemeral
certs minted by the old key remain valid until natural expiry
(seconds).

Design: [§5.3.13 local user-CA](../design/mssh_design_v1.md#5313--local-user-ca-).

### Inject a bypass cert (CA unreachable)

```sh
# (operator already minted alice-bypass.crt while CA was up; stored offline)
mssh --inject-bypass-cert alice-bypass.crt this-host
# Then alice's next normal connection succeeds with no CA call:
mssh this-host -- whoami
```

Design: [§13.2 CA-bypass cert flow](../design/mssh_design_v1.md#132--ca-bypass-cert-offline-mint--later-inject-).

---

## Troubleshooting

| Symptom | Where to look | Design § |
|---------|---------------|---------|
| TLS handshake fails on outer port | `auth.pem` pin matches admin-issued client certs | §2.3 |
| Authorize denied with `unknown_server` | Server enrollment record vs msshd's mTLS subject | §4.3.1 |
| CA reachable but every authorize denied | Policy match (mssh-admin audit) | §4.3.3 |
| `msshd-admin status` shows CRL gap > 50 | Strict-mode gate is now active | §5.3.9 |
| Inner sshd refuses ephemeral cert | `TrustedUserCAKeys` points at the right pubkey | §5.3.13 |
| Sessions hang on banner | Banner file readable by `_msshd` | §5.3.15 |

---

## Hardening

Every msshd ships with §13.9 hardening members enabled by default.
See [design §13.9 mssh-hardening](../design/mssh_design_v1.md#139--mssh-hardening-v1-deliverable-)
for the complete posture.

---

## Related operator docs

- [docs/4-mssh-ca.md](4-mssh-ca.md) — the CA you're calling
- [docs/6-mssh.md](6-mssh.md) — the client your users run
- [docs/17-operations.md](17-operations.md) — fleet operations
