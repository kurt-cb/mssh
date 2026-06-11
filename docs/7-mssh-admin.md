# mssh-admin — operator CLI manual

**Design reference:** [design §7 mssh-admin](../design/mssh_design_v1.md#7--module-mssh-admin-).

`mssh-admin` is the operator-facing CLI for the mssh-ca admin API.
Most day-to-day mssh deployment work goes through this command.

---

## Setup

The mssh-admin cert + key are minted by `mssh-ca --bootstrap` (for
the bootstrap superuser) or by `mssh-admin admin add` (for
subsequent admins). Install at:

```
~/.mssh-admin/
  cert.pem        # auth-signed admin mTLS cert
  key.pem         # mode 0600
  trust.pem       # host-mint pin for mssh-ca's server cert
  ca-url          # one line, e.g. https://mssh-ca.example.com:4443
```

---

## Quick reference

### Servers

```sh
mssh-admin server add SRV-NAME [--group GROUP]
mssh-admin server remove SRV-NAME
mssh-admin server groups SRV-NAME --add GROUP [--remove GROUP]
mssh-admin server list [--group GROUP] [--name SRV-NAME]
```

`add` returns the freshly minted mTLS cert + key for the server.
**Capture it** — the CA does not retain the key. Install on the
target host per [docs/5-msshd.md](5-msshd.md).

### Users

```sh
mssh-admin user add USERNAME
mssh-admin user key add USERNAME --type pubkey --data @file [--label LABEL]
mssh-admin user key remove USERNAME FINGERPRINT
mssh-admin user remove USERNAME             # 2FA-gated (§13.5)
mssh-admin user list
```

Key types: `pubkey` (SSH wire-format), `openssh-cert`, `x509-cert`.

### Policies

```sh
mssh-admin policy add --user USER --servers S1,S2 [--server-groups G1,G2] \
                      --channels session \
                      [--source-cidrs C1,C2] [--time-window 08:00Z:18:00Z] \
                      [--max-validity-seconds N] \
                      [--force-command CMD] [--env K=V,...] \
                      [--require-2fa passkey --2fa-within-seconds N]
mssh-admin policy remove POLICY-ID
```

Empty fields are "no constraint." `servers` and `server-groups`
are unioned; everything else is intersected.

### Admins

```sh
mssh-admin admin add NAME --role superuser|server-admin|user-admin|auditor
mssh-admin admin remove NAME         # 2FA-gated
mssh-admin admin list
```

Roles per [design §14.1.2 RBAC matrix](../design/mssh_design_v1.md#1412--admin-endpoints--v1admin).

### Certs

```sh
# Mint auxiliary X.509 (NOT authz certs — those mint per /v1/authorize)
mssh-admin cert mint --type tls-server --cn host.example.com --san DNS:host
mssh-admin cert mint --type tls-client --cn alice

# Revoke (any leaf type)
mssh-admin cert revoke SERIAL [--reason "..."] [--issuer ISSUER-ID]
                                     # 2FA-gated

# Renew (the cert IS the auth; runs as a daily systemd timer)
mssh-admin cert renew --cert PATH --key PATH --out-cert PATH --out-key PATH \
                      [--threshold-days N] [--revoke-old] [--on-renew CMD]
```

Design: [§13.4 cert auto-renewal](../design/mssh_design_v1.md#134--cert-auto-renewal-).

### Intermediates

```sh
mssh-admin intermediate list
mssh-admin intermediate rotate ROLE [--force]
mssh-admin intermediate mint-external --name NAME --path-length N
```

Roles: `user-mint`, `bypass-mint`, `host-mint`, `auth`. Rotating
an intermediate is non-disruptive — existing unexpired leaves
remain valid until natural expiry.

Design: [§2.5 rotation + revocation](../design/mssh_design_v1.md#25--rotation--revocation-semantics-).

### Bypass certs

```sh
mssh-admin bypass-cert mint USER --pubkey FILE --valid-days N --out CERT.crt \
                       [--source-bind CIDR] [--server-bind GROUP] \
                       [--channels session] [--force-command CMD] \
                       [--max-session-seconds N]
mssh-admin bypass-cert list
mssh-admin bypass-cert revoke SERIAL
```

**Store the output offline** (USB key, safe). The whole point is
that bypass certs are not on disk during normal operation.

Design: [§13.2 CA-bypass cert flow](../design/mssh_design_v1.md#132--ca-bypass-cert-offline-mint--later-inject-).

### External tools (passkey RP)

```sh
mssh-admin external-tool add TOOL-ID --outcome-url-prefix https://tool/cb/ \
                              [--aaguid AAGUID ...] --out TOOL.crt
mssh-admin external-tool remove TOOL-ID
mssh-admin external-tool list
```

Design: [§13.6 external-tool RP flow](../design/mssh_design_v1.md#136--external-tool-rp-flow-).

### Audit log

```sh
mssh-admin audit tail [--actor ACTOR] [--action ACTION] [--result granted|denied|...]
mssh-admin audit search --since "1 week ago" --until "now" [filters]
mssh-admin audit verify                                  # §13.9.6
```

`audit verify` walks the hash chain + signed checkpoints; any
break is an incident-response signal.

### Templates (per-connection inner sshd config)

```sh
mssh-admin template set --scope default --kind openssh --content @template.conf
mssh-admin template set --scope group --scope-name accounting --kind openssh --content @file
mssh-admin template set --scope server --scope-name srv-acct-01 --kind openssh --content @file
mssh-admin template unset --scope SCOPE [--scope-name N] --kind openssh
mssh-admin template list
mssh-admin template show SRV-NAME [--kind openssh]
```

Precedence: server > group > default > built-in. Used in
per-connection inner-sshd mode (§5.3.11).

### Auxiliary issuance

```sh
mssh-admin openvpn issue --cn CN [--validity-days N] --out config.ovpn
mssh-admin wireguard peer-add --name N [--allowed-ips C] --out peer.conf
```

Design: [§13.7 auxiliary cert issuance](../design/mssh_design_v1.md#137--auxiliary-certificate-issuance-).

---

## 2FA prompts

When you run a gated command (admin.add, admin.remove,
user.remove, cert.revoke, or whatever your operator's policy
gates), the CLI:

1. Prints an approval URL (with terminal QR rendering in v0.3.2+).
2. Polls every 2 seconds.
3. You tap your registered authenticator on your phone.
4. The CLI retries the original call automatically.

If you cancel (Ctrl-C) or the ceremony expires, the command exits
non-zero.

Design: [§7.3.2 2FA polling loop](../design/mssh_design_v1.md#732--2fa-polling-loop-).

---

## Output formats

```sh
--output human       # default; tabular + colorized if TTY
--output json        # one JSON object on stdout (for scripts)
--output quiet       # only the primary identifier, one per line
```

Use `--output quiet` in shell loops:

```sh
for s in $(mssh-admin server list --output quiet); do
  echo "checking $s"
done
```

---

## Related docs

- [docs/4-mssh-ca.md](4-mssh-ca.md) — the CA you're talking to
- [docs/11-mssh-admin-web.md](11-mssh-admin-web.md) — browser equivalent (optional)
- [docs/15-third-party-integration.md](15-third-party-integration.md) — the cert-issuance subcommands in context
- [docs/TUTORIAL_USER_MANAGEMENT.md](TUTORIAL_USER_MANAGEMENT.md) — end-to-end walkthrough
