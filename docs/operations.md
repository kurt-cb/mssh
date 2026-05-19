# mssh — operations

This document covers the day-to-day operator workflow: install the
pieces, bootstrap a CA, enrol servers and users, drive the
adoption journey, manage policy, troubleshoot.

For evaluation and high-level overview see
[overview.md](overview.md). For the API contract see
[design/api.md](../design/api.md). For the architecture see
[design/architecture.md](../design/architecture.md).

---

## Quick install (current state)

The packaging story is interim — a proper `apt install mssh msshd`
distro package is on the [future-ideas list](../design/future-ideas.md).
Today the install is:

```bash
# On every machine that runs any mssh component:
git clone https://github.com/kurt-cb/ssh-rt-auth.git
cd mssh/python
pip install -e .
```

This installs the `mssh`, `mssh-admin`, `mssh-ca`, and `msshd`
binaries into your active Python environment.

Future install path (see
[future-ideas §install_mssh](../design/future-ideas.md)):

```bash
install_mssh.sh /path/to/mssh-<version>.tar.gz
# … lays down the venv + binaries + systemd units, disabled.
```

---

## Bootstrap a CA

The CA holds the signing key, so it bootstraps itself:

```bash
mssh-admin init --ca-dir /etc/mssh-ca
# Generates: signing-key.pem, signing-cert.pem (root),
# bootstrap-admin-{cert,key}.pem, tls-{server,ca}-cert.pem.
```

The `bootstrap-admin-{cert,key}.pem` pair is your initial admin
identity. Move them to your operator workstation; subsequent
`mssh-admin` commands will reference them.

Start the CA service:

```bash
mssh-ca --config /etc/mssh-ca/ca-config.yaml
# or via the shipped systemd unit:
systemctl enable --now mssh-ca
```

The CA listens on TLS (port 8443 by default) with mTLS-only
client auth.

---

## Enrol a server

On your operator workstation, with the bootstrap admin creds:

```bash
mssh-admin server add --name srv-acct-01 --groups accounting,production
# → prints the mTLS cert + key (printed once, not retained by CA)
```

Capture the printed cert + key. SSH to the target server (or pipe
through `install_mssh.sh`) and provision them:

```
/etc/mssh/server-mtls.crt   (cert)
/etc/mssh/server-mtls.key   (key, mode 600)
/etc/mssh/ca-tls-root.pem   (the CA's TLS root, for verifying CA replies)
```

Drop a `wrapper.yaml` and start msshd:

```yaml
# /etc/mssh/wrapper.yaml (starting in fallback mode — Phase 1
# of the adoption journey, see below)
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
```

At this point msshd is in front of your existing sshd in
transparent-proxy mode. Users `ssh -p 2200 user@srv-acct-01`
exactly as they would `ssh -p 22 user@srv-acct-01`; the auth
is the operator's existing sshd policy. Verify the wiring is
good before moving on.

---

## Enrol a user

```bash
# user add creates the user AND attaches a key if --key is given.
mssh-admin user add --user alice --key ~alice/.ssh/id_ed25519.pub
mssh-admin policy add --user alice --server-groups accounting --channels session
```

Each `policy add` attaches one rule to the user. Multiple rules
union. See [design/api.md § policy management](../design/api.md#policy-management)
for the full schema (source CIDRs, time windows, max cert validity,
…).

---

## The adoption journey

mssh deliberately supports three operating modes so the cutover from
"vanilla sshd" to "CA-mediated auth" can be done **per-server, on
your schedule, reversibly**. Each mode is a single line in
`wrapper.yaml`; restart msshd to flip.

### Phase 0 — no mssh

Before adoption. Your fleet runs unmodified sshd on port 22.
Users `ssh user@host`. Auth is your existing sshd config.

### Phase 1 — `mode: fallback`

msshd in front, transparent TCP proxy. Users `ssh -p 2200 user@host`.
Your existing sshd policy is still doing all the auth; msshd just
proves it's wired into the connection path.

```yaml
mode: fallback
fallback: { host: 127.0.0.1, port: 22 }
listen: { external_address: 0.0.0.0, external_port: 2200 }
```

What this validates: msshd accepts connections, can bind the new
port, has a sane systemd lifecycle. **No security change yet.**

### Phase 2 — `mode: gated` (deferred)

Not yet implemented. See [future-ideas.md § gated mode](../design/future-ideas.md)
and [archive/design/ssh-rt-auth-detailed-wrapper.md §6.5.1](../archive/design/ssh-rt-auth-detailed-wrapper.md).

When available: msshd does the full mTLS + CA call (so unauthorized
clients can't even attempt auth) but forwards to your existing
sshd for the actual auth. Bridges Phase 1 and Phase 3 without
forcing operators to retranslate their existing sshd policy on
day one.

### Phase 3 — `mode: enforce`

msshd terminates mTLS, calls the CA, mints an ephemeral OpenSSH
user cert, and hands the connection to a **hermetic inner sshd**
that only trusts msshd's mint key. CA policy is now the source of
truth.

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
  endpoints: [https://mssh-ca.internal:8443]
  client_cert: /etc/mssh/server-mtls.crt
  client_key:  /etc/mssh/server-mtls.key
  ca_pubkey:   /etc/mssh/ca-tls-root.pem
  timeout_seconds: 5
inner:
  sshd_binary: /usr/sbin/sshd
  port_range: [49152, 65535]
users:
  allowed: ["*"]
```

Users `mssh user@host:2200`. mssh-admin's enrollment + policy is
the auth oracle. Your existing `/etc/ssh/sshd_config` is bypassed.

### Rolling back

Every step is reversible by flipping `mode:` and restarting msshd.
Operators with `flip-to-enforce.sh` / `flip-to-fallback.sh`
helpers (the adhoc lab ships these) can A/B between modes during
debugging.

---

## Common operator tasks

### Add a user, give them access

```bash
mssh-admin user add --user alice --key /path/to/alice.pub
mssh-admin policy add --user alice --server-groups accounting --channels session
```

### Inspect a user

```bash
mssh-admin user show --user alice
# Single-user detail (keys, policies). Same as `user list --user alice`
# but more discoverable.
```

### Revoke a user immediately

```bash
mssh-admin user remove --user alice
# Any in-flight session is unaffected (already authorized) but all
# future authorize calls deny within the CA's cache TTL (default 1 minute).
# For propagation to active sessions, see future-ideas.md §22 (push channel).
```

### Add a server to a group / change group membership

```bash
mssh-admin server groups --name srv-new --add accounting
# `--remove <group>` and `--set <comma,sep,list>` also work.
```

### Inspect a server

```bash
mssh-admin server show --name srv-acct-01
# Single-server detail (groups, mTLS subject, enrollment timestamp).
```

### Rotate an admin's mTLS cert

```bash
mssh-admin admin add --name bob-2026 --role server-admin     # mint new creds
mssh-admin admin remove --name bob                            # revoke old (do AFTER bob switches)
```

### Search the audit log

```bash
mssh-admin audit --decision denied --limit 20
# JSON-Lines on stdout. Filter further with jq.
# (Time-window flags like --since are future work — see future-ideas.md.)
```

### Bounce the CA without dropping sessions

The CA can be restarted at will. In-flight authorize calls fail
with `result: error` and msshd retries against the next endpoint
in its endpoint list. Existing established SSH sessions are
**unaffected** — they're already authorized.

For zero-downtime CA work, run two CA instances behind your DNS
and rolling-restart them.

### Customize the per-server pre-auth banner

Each msshd shows a banner before the user authenticates. Default is
a generic "mediated by mssh" message. Customize by pointing
`banner.template_path` in `wrapper.yaml` at a text file and listing
substitution values:

```yaml
# /etc/mssh/wrapper.yaml
banner:
  template_path: /etc/mssh/banner.txt
  values:
    server: srv-acct-01
    group: accounting
    owner_email: ops@example.com
```

```text
# /etc/mssh/banner.txt
─── Welcome to {server} ({group}) ───
For access questions: {owner_email}
```

Tokens not present in `values` are left literal so a typo doesn't
crash msshd; a missing or malformed template logs a warning and
falls back to the default banner.

Per-user substitution (`{user}`, CA-decision details) is not
supported today — the inner sshd is long-lived and shares its
banner across sessions. See
[design/future-ideas.md §1](../design/future-ideas.md) for the
per-connection-sshd path that enables per-session banners.

### Check deployment state at any time

```bash
mssh-admin status           # full state dump with ✓/✗ per check
mssh-admin next             # only the next step to do
```

`status` walks the adoption journey — CA bootstrap, service running,
admins enrolled, servers enrolled, users with keys, users with
policies — and prints `✓` or `✗` per check. `next` prints only the
first failing check plus a suggested command, useful while
onboarding a new server or user.

### Ask the CA in natural language (MCP)

The `mssh-mcp` server exposes the read-only admin API over the
[Model Context Protocol](https://modelcontextprotocol.io) so an
LLM-driven client (Claude Code, Claude Desktop, etc.) can answer
questions like *"why was alice denied last Tuesday"* or *"list every
server in the production group"* by calling the same admin endpoints
`mssh-admin` uses.

#### Install

`mssh-mcp` ships in the `mssh-admin` wheel as an optional extra (the
`mcp` Python SDK is a heavy dep most operators don't want):

```bash
# v0.1.0 alpha — nothing is on PyPI yet, so install from the
# repo's pre-built wheels:
make pkg                                 # builds dist/*.whl
.venv/bin/pip install dist/mssh_common-*.whl \
                     dist/mssh_admin-*.whl \
                     dist/mssh_ca-*.whl
.venv/bin/pip install 'mcp>=1.0'        # the [mcp] extra's runtime dep

# Once we publish to PyPI, this collapses to:
#     pip install 'mssh-admin[mcp]'
```

Verify the binary is on `$PATH`:

```bash
mssh-mcp --help
```

#### Configure

`mssh-mcp` reads `~/.mssh-admin/config` (same fields as `mssh-admin`).
Make sure that file has your CA URL + admin cert/key paths so
`mssh-admin status` already works from your workstation; `mssh-mcp`
will use the same credentials.

#### Wire up to Claude Code (CLI)

Claude Code reads `~/.config/claude-code/mcp_servers.json` (or similar
location — check `claude --help` for your version's path). Add:

```json
{
  "mssh-ca": {
    "command": "mssh-mcp",
    "args": []
  }
}
```

Then in a Claude Code session, the tools below appear and you can
ask things like:

  - *"What's the current adoption-phase status of the CA?"*
  - *"Why was the last denied authorize from alice?"*
  - *"Show me the policies attached to root-admin."*

#### Wire up to Claude Desktop

Edit `claude_desktop_config.json` (location depends on OS — see
Claude Desktop docs):

```json
{
  "mcpServers": {
    "mssh-ca": {
      "command": "mssh-mcp",
      "args": []
    }
  }
}
```

Restart Claude Desktop and the tools appear in the tool-use menu.

#### Tools exposed (all read-only in v1)

  - `status` — full deployment state walk (same as `mssh-admin status`).
  - `server_list` — enrolled servers, with optional group / name
    filter.
  - `user_list` — enrolled users with key + policy counts.
  - `user_inspect` — full detail for one user.
  - `audit_search` — recent authorize decisions with filters.
  - `admin_list` — enrolled admins.

Write tools (`server_add`, `user_add`, `policy_add`, key rotation)
are deliberately not in v1 — the trust delegation for write access
needs its own design (see [design/future-ideas.md §12](../design/future-ideas.md)).

#### Security note

`mssh-mcp` runs locally on your workstation and uses your *admin*
mTLS creds to talk to the CA. The LLM never sees the certs
themselves — it only sees the JSON the CA returns. Same trust
boundary as running `mssh-admin` manually.

If you don't want an LLM client to be able to read your audit log
or user/policy table, **don't install `mssh-admin[mcp]`**. The
extras dependency is opt-in for exactly this reason.

---

## Troubleshooting

### "msshd won't start"

Check the systemd journal: `journalctl -u msshd -n 100`.
Common causes:

  - `wrapper.yaml` syntax error → msshd refuses to start, logs
    the parse failure.
  - mTLS cert files missing or wrong permissions (`server-mtls.key`
    must be mode 600).
  - In enforce mode: CA endpoint unreachable at startup. msshd
    will retry; check connectivity from the server to the CA.

### "Client gets denied, but should be allowed"

  - Check the CA audit log for the denied entry's
    `denied_reason`. The enum tells you which check failed
    (policy_no_match, policy_source_cidr, etc.).
  - Look up the user's policies:
    `mssh-admin user show alice`.
  - Verify the server's group membership matches the policy:
    `mssh-admin server show srv-acct-01`.

### "Client gets allowed, but inner sshd then refuses"

Means the ephemeral OpenSSH cert msshd minted failed to load
into the hermetic inner sshd. Check msshd's stderr for the cert
mint output and the inner sshd's complaint. Usually a clock-skew
issue (the cert is not yet valid) or a mismatch between msshd's
local user-CA pubkey and the inner sshd's `TrustedUserCAKeys`
pin.

### "I want to switch a server to debug mode"

Production msshd uses **native OpenSSH** as its hermetic inner sshd
— that's the only thing that runs in the data path on a real server.

`debug_sshd` is a separate, **Python-based** SSH server we ship for
*diagnostic* purposes only. It calls the same CA / cert-parsing code
that the production path uses, so you can isolate "is the CA decision
right?" from "is OpenSSH config right?" without touching prod.

Today: the adhoc lab has a `debug` tier that brings up debug_sshd
instead of the OpenSSH hermetic inner — `./setup_adhoc.sh debug` from
`python/`. For an existing deployment, you currently have to stop
msshd and run `mssh-debug-sshd` directly. See
[future-ideas.md §11](../design/future-ideas.md) for the planned
in-situ swap-in that doesn't require taking msshd down.

**Important:** debug_sshd is intentionally a smaller SSH implementation
than OpenSSH. If something works under debug_sshd but breaks under
production msshd, suspect a debug_sshd limitation, not a production
bug.

### "I think my CA signing key is compromised"

Worst case. Procedure:

  1. Stop the CA. Every server fails closed.
  2. Generate a fresh CA signing key + new root cert.
  3. Re-enrol every server (their old mTLS creds were signed by
     the old root and are now invalid).
  4. Re-enrol every admin.
  5. Re-issue every authorization cert (they were signed by the
     old root too).

The audit log on the old CA host is invaluable here for "what
did the attacker touch."

If you've enabled emergency certs on servers, those continue to
work until manually revoked — handy for break-glass continuity
during the re-bootstrap, dangerous if the attacker has access
to those certs.

---

## Future operator features

These aren't here yet but are on the roadmap:

  - **`gated` mode** — Phase 2 of the journey (above).
  - **`install_mssh.sh`** — distro-agnostic installer that
    simulates `apt install mssh msshd`.
  - **Legacy config import** — `mssh-admin import` scrapes
    existing `authorized_keys` + `sshd_config` into a draft
    CA enrollment.
  - **Dual-enforce mode** — CA evaluates both the imported
    legacy ruleset AND the new policy, logs divergence cases
    so the operator can tighten without disruption.
  - **MCP interface to the CA** — natural-language diagnostics
    ("why was alice denied yesterday?") + trusted-AI config.
  - **Browser-based bastion** — xterm.js terminal over HTTPS
    with mTLS auth; zero-install client.
  - **Native distro packages** (`.deb`, `.rpm`, `.apk`).

See [design/future-ideas.md](../design/future-ideas.md) for the
full list with scope estimates.
