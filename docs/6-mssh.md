# mssh — user manual (the client)

**Design reference:** [design §6 mssh (client)](../design/mssh_design_v1.md#6--module-mssh-client-).

This is the documentation for end users — the people who type
`mssh server -- cmd` instead of `ssh server cmd`.

---

## What you need

A directory at `~/.mssh/` containing:

```
~/.mssh/
  cert.pem       # the operator gave you this (auth-signed mTLS cert)
  key.pem        # mode 0600 (chmod 600)
  trust.pem      # the operator gave you this too (host-mint pin)
  config.yaml    # operator-provided endpoint list
```

If you don't have these, talk to your mssh administrator. Once
they're in place, `mssh` works just like `ssh`.

---

## Basic usage

```sh
# Run a command (returns its exit code)
mssh srv-acct-01 -- whoami
alice

# Interactive shell
mssh srv-acct-01

# Run with explicit user (overrides config)
mssh alice@srv-acct-01
```

Design: [§6.3.1 config resolution](../design/mssh_design_v1.md#631--config-resolution-) +
[§6.3.2 TLS handshake + session-RPC](../design/mssh_design_v1.md#632--tls-handshake--session-rpc-).

---

## When something denies

mssh exits with code `6` on access-denied. The reason appears on
stderr:

```
mssh: access denied — policy_mismatch: source not in allow-list
```

Common reasons:

| Reason | What it means |
|--------|---------------|
| `unknown_identity` | Your key isn't enrolled at the CA. Talk to admin. |
| `policy_mismatch` | You're enrolled, but no policy permits the requested server/channel. |
| `source_denied` | You're on the wrong network (IP not in policy's `source_cidrs`). |
| `time_window` | Outside the policy's allowed hours. |
| `clock_drift` | Your clock differs from the CA's by too much. Run NTP. |
| `unknown_server` | The server you targeted isn't enrolled at the CA. |

Design: [§16.1 failure model](../design/mssh_design_v1.md#161--failure-model--fail-closed-).

---

## Break-glass: injecting a bypass cert

If the CA is unreachable and you have a pre-minted bypass cert
stored offline:

```sh
# Step 1: inject (one-shot)
mssh --inject-bypass-cert ~/safe/alice-bypass.crt srv-acct-01

# Step 2: use as normal
mssh srv-acct-01 -- whoami
```

The two-step UX is deliberate — bypass certs live in safes, not
on disk. Inject only when you actually need it.

Design: [§6.3.4 bypass-cert injection](../design/mssh_design_v1.md#634--bypass-cert-injection---inject-bypass-cert-) +
[§13.2 end-to-end flow](../design/mssh_design_v1.md#132--ca-bypass-cert-offline-mint--later-inject-).

---

## Failover

If your config has multiple endpoints, mssh tries them in order.
Each gets one TLS handshake attempt; on hard failure (timeout,
TLS error, unreachable), the next is tried. Once one accepts the
connection, no further fallback — if it denies, the call denies.

Design: [§6.3.3 endpoint failover](../design/mssh_design_v1.md#633--endpoint-failover-).

---

## Local-port forwarding (`-L`) 🚧

Not in v1 yet — coming. Will enable e.g. `mssh -L 9443:localhost:9443
mssh-ca-host` for accessing the admin web portal through an
mssh-secured tunnel.

Design: [§6.3.5 -L](../design/mssh_design_v1.md#635--local-port-forwarding--l-) +
[§11.3.5 admin-web via mssh-tunneled localhost](../design/mssh_design_v1.md#1135--admin-web-via-mssh-tunneled-localhost---p3--v1-target).

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Session succeeded; remote command's exit code |
| 1 | Generic error |
| 6 | Access denied |
| 8 | Network or TLS error |
| 128+N | Remote killed by signal N |

Design: [§14.2.1 mssh CLI surface](../design/mssh_design_v1.md#1421--mssh).

---

## Differences from `ssh`

- **No `~/.ssh/known_hosts`.** Server identity is validated against
  `~/.mssh/trust.pem`. No prompt on first connect.
- **No password auth.** Ever. Your mTLS cert is the credential.
- **No agent forwarding by default.** It's a policy decision (CA
  must enable per-policy).
- **Exit codes match.** Scripts that handle `ssh` exit codes work
  unchanged with `mssh`.
