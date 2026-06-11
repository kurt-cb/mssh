# mssh-ca — operator manual

**Design reference:** [design §4 mssh-ca](../design/mssh_design_v1.md#4--module-mssh-ca-).
This document is tutorial / user-manual tone — it tells you what to
do. Read the design § for *why* and for the canonical contract.

mssh-ca is the central authorization service. Every mssh deployment
runs exactly one mssh-ca instance, typically on a private network
reachable only from your msshd hosts and operator workstations.

---

## Quick start

```sh
# 1. Install (system pkg or pip)
sudo apt install mssh-ca   # or: pip install mssh-ca

# 2. Bootstrap the PKI (one-time)
sudo -u _mssh-ca mssh-ca --config /etc/mssh-ca/ca-config.yaml --bootstrap

# 3. Start
sudo systemctl enable --now mssh-ca

# 4. Capture the bootstrap admin cert + key it minted, install on
#    your operator workstation as ~/.mssh-admin/cert.pem + key.pem.
```

After this, the CA is reachable at the URL in `ca-config.yaml`. Use
`mssh-admin` from your workstation to enroll servers + users +
policies.

---

## What lives where

| Path | Contents | Design § |
|------|----------|---------|
| `/etc/mssh-ca/ca-config.yaml` | CA configuration | §14.3.2 |
| `/var/lib/mssh-ca/root-*.pem` | Root CA cert + key (mode 0600 on key) | §2.2 |
| `/var/lib/mssh-ca/intermediates/<role>/` | The 4 intermediates (`user-mint`, `bypass-mint`, `host-mint`, `auth`) | §2.2 |
| `/var/lib/mssh-ca/intermediates/external-<name>/` | External intermediates (cert only) | §2.6 |
| `/var/lib/mssh-ca/crl/<role>.jsonl` | Per-issuer CRL log | §4.3.5 |
| `/var/lib/mssh-ca/enrollment.yaml` | Servers / users / admins / policies | §14.4 |
| `/var/lib/mssh-ca/audit.jsonl` | Append-only audit log | §4.3.7 |
| `/var/log/mssh-ca/` | Daemon logs | §17.5 |

---

## Common tasks

### Enroll a new server

```sh
mssh-admin server add srv-acct-01 --group accounting
```

Returns the freshly minted server mTLS cert. Capture it and install
on the target host as `/etc/mssh/msshd-mtls-{cert,key}.pem`.
**The CA does not retain the private key** — if you lose the
response, you must re-enroll.

Design: [§4.3.6](../design/mssh_design_v1.md#436--admin-handlers-) /
[§14.1.2](../design/mssh_design_v1.md#1412--admin-endpoints--v1admin).

### Enroll a user + their key

```sh
mssh-admin user add alice
mssh-admin user key add alice --type pubkey --data @/path/to/alice.pub
```

### Attach a policy

```sh
mssh-admin policy add \
  --user alice \
  --servers srv-acct-01 \
  --channels session \
  --source-cidrs 10.0.0.0/8 \
  --max-validity-seconds 600
```

Design: [§4.3.3 policy engine](../design/mssh_design_v1.md#433--policy-engine-).

### Rotate an intermediate

```sh
mssh-admin intermediate rotate user-mint --force
```

The old intermediate's keypair is archived; existing unexpired
authz certs remain valid until natural expiry. New authz certs
are signed by the new keypair.

Design: [§2.5 rotation + revocation](../design/mssh_design_v1.md#25--rotation--revocation-semantics-).

### Revoke a cert

```sh
mssh-admin cert revoke <serial> --reason "key rotation"
```

Propagates to every msshd's authz cache on each msshd's next
authorize call. Strict-mode gate (§5.3.9) bounds the worst-case
propagation delay.

Design: [§13.3 CRL revocation channel](../design/mssh_design_v1.md#133--crl-revocation-channel-).

### Read the audit log

```sh
mssh-admin audit tail --result denied --since "2 hours ago"
mssh-admin audit search --actor alice --action authorize
```

Design: [§4.3.7 audit log](../design/mssh_design_v1.md#437--audit-log-) +
[§13.9.6 audit integrity](../design/mssh_design_v1.md#1396--audit-log-tamper-resistance-posture-).

---

## Adopt 2FA for admins

```sh
# 1. Deploy mssh-passkey (see docs/8-mssh-passkey.md)
# 2. Point ca-config.yaml at the broker (admin_2fa: section)
# 3. Each admin enrolls a credential:
mssh-admin user passkey enroll
# 4. Add a policy requiring 2FA for sensitive admin actions:
mssh-admin policy add --user bob --require-2fa passkey --2fa-within-seconds 3600
```

Design: [§13.5 admin-2FA flow](../design/mssh_design_v1.md#135--admin-2fa-passkey-flow-).

---

## Troubleshooting

| Symptom | Where to look | Design § |
|---------|---------------|---------|
| Every authorize denied with `unknown_server` | Server enrollment record vs. msshd's mTLS cert subject | §4.3.1 |
| Many denied with `clock_drift` | NTP on CA host vs. msshd hosts | §16.1 |
| Cert minted, msshd refuses it | `auth_trust_root` / `bypass_trust_root` pinning in msshd config | §2.3 |
| 2FA never completes | Broker reachability + AAGUID allowlist | §8 + §13.5 |
| CRL not propagating | strict-mode threshold + per-issuer seq gap | §5.3.9 + §13.3 |

---

## Hardening posture

Every v1 deployment ships with the §13.9 hardening members enabled.
You do **not** need to enable them — they're on by default. See
[design §13.9 mssh-hardening](../design/mssh_design_v1.md#139--mssh-hardening-v1-deliverable-).

Operator decisions:
- **MCP** (§12) is OFF by default. If you turn it on, audit the
  capability allow-list (§12.4.3).
- **Admin-web** (§11) is a separate deployment. If you turn it on,
  prefer the mssh-tunneled localhost pattern (§11.3.5) over public
  internet exposure.
- **Bypass certs** (§13.2) are an operator break-glass tool. Mint
  with restraint; store offline.

---

## Related operator docs

- [docs/5-msshd.md](5-msshd.md) — the gateway daemon
- [docs/7-mssh-admin.md](7-mssh-admin.md) — the CLI you use most
- [docs/8-mssh-passkey.md](8-mssh-passkey.md) — broker deployment
- [docs/15-third-party-integration.md](15-third-party-integration.md) — using mssh-ca as a step-ca parallel for OpenVPN/WireGuard/etc.
- [docs/17-operations.md](17-operations.md) — fleet operations + adoption journey
