# debug_sshd — diagnostic SSH server

**Design reference:** [design §10 debug_sshd](../design/mssh_design_v1.md#10--module-debug_sshd-).

**Not for production deployments.** debug_sshd is an AsyncSSH-based
SSH server with verbose, structured logging of every auth-path
step. Used to diagnose why production msshd is misbehaving.

---

## When to reach for it

You're seeing a denied connection on production msshd and the
authorize logs don't make obvious sense. You want to see exactly
which step in the auth path failed.

Stand up debug_sshd alongside (or in place of) the inner sshd
temporarily, point the mssh client at it, and observe.

Triage rules (per design §10.1):

- If something works in debug_sshd but **not** in production
  msshd: likely a debug_sshd limitation (it has a smaller protocol
  surface). Don't infer a production bug.
- If something works in production but **breaks** in debug_sshd:
  treat as a debug_sshd issue first.

---

## Run it

```sh
mssh-debug-sshd --config /tmp/debug.yaml --listen 127.0.0.1:2222 --trace 2> debug.log
```

In another terminal:

```sh
mssh --endpoint 127.0.0.1:2222 srv-acct-01 -- whoami
```

Watch the JSON-Lines log in `debug.log`:

```json
{"ts":"...","step":"auth.pubkey","user":"alice","fp":"SHA256:...","result":"granted"}
{"ts":"...","step":"ca.request","request_id":"..."}
{"ts":"...","step":"ca.response","status":200,"result":"granted"}
{"ts":"...","step":"channel.open","type":"session"}
```

---

## In-situ swap-in 🚧

Operator affordance: temporarily replace production msshd's inner
sshd with debug_sshd to diagnose a misbehaving live session, with
a sideband channel that streams the trace to a CA audit log.

Captured idea; not implemented in v1. See [design §10.4](../design/mssh_design_v1.md#104--in-situ-swap-in-deferred-).

---

## Related docs

- [docs/5-msshd.md](5-msshd.md) — the production gateway
- Adhoc lab: `./setup_adhoc.sh debug` spins up a debug_sshd container.
