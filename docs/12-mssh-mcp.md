# mssh-mcp — Model Context Protocol interface

**Design reference:** [design §12 mssh-mcp](../design/mssh_design_v1.md#12--module-mssh-mcp-).

**Optional. OFF BY DEFAULT.** Surface for trusted-AI diagnostic
flows over MCP. Read this section's threat model before turning it on.

---

## Threat model first

MCP can be tricked. Prompt injection can convince an LLM-driven
agent to issue a destructive admin call. Therefore mssh-mcp's v1
posture is:

1. **Same auth as mssh-admin** — every MCP action requires the
   same mTLS + role check as the equivalent CLI command. The
   MCP's mTLS cert is just another admin cert.
2. **Capability subset** — v1 is read-mostly. The capability
   allow-list (§12.4.3) explicitly enumerates what's permitted.
3. **Audit tagging** — every MCP call carries `origin: mcp` in
   the audit record (§4.3.7).
4. **OFF by default** — must be turned on in `ca-config.yaml`'s
   `mcp:` block.
5. **No bypass-cert mint, ever** — under any v1 configuration.

Design: [§12.2 threat model](../design/mssh_design_v1.md#122--threat-model-).

---

## When (and whether) to enable it

Enable only if:
- You have an AI agent under operator control (not user-facing).
- The capability set in §12.4.1 covers your diagnostic needs and
  you don't need any of the gated-out mutating actions.
- Your operator team has explicitly reviewed the capability
  allow-list.

If any of these is "no," leave `mcp.enabled: false`. The hardening
(audit tagging + capability allow-list) ships regardless — see
§13.9.2 — so flipping it on later doesn't need a release.

---

## Capability allow-list

```yaml
# /etc/mssh-ca/ca-config.yaml
mcp:
  enabled: false                            # default
  capability_allow_list:
    - server.list
    - user.list
    - admin.list
    - policy.read
    - intermediate.list
    - audit.read
    - template.list
    - template.show
```

**Mutating actions are NOT allowed in v1.** Even if you somehow
add them to the list, mssh-ca refuses calls with `Origin: mcp`
for non-allowed actions (defense in depth).

Design: [§12.4.3 capability allow-list](../design/mssh_design_v1.md#1243--capability-allow-list--p3--v1-ship-blocker-if-mcp-is).

---

## Related docs

- [docs/4-mssh-ca.md](4-mssh-ca.md) — turning MCP on lives in `ca-config.yaml`
- [design §12.2 threat model](../design/mssh_design_v1.md#122--threat-model-) — required reading
- [design §13.9.2 hardening](../design/mssh_design_v1.md#1392--mcp-attack-surface-controls--1242--1243) — what ships regardless
