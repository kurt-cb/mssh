# 09. Channel Plugin Interface

After authentication completes, an mssh session may request **authenticated channels** — application-layer services gated by the user's cert policy. VPN tunnels are one example; database proxies, kubernetes API gateways, file-staging brokers, audit sidecars, custom enterprise gateways, and more all fit the same shape.

This document defines the Authenticated Channel Plugin Protocol (ACPP) — the local IPC by which sshd talks to channel plugin processes — and the cert extension that grants channel access.

## Design rationale

The temptation when designing SSH extensions is to bake specific features into sshd. mssh deliberately does not. The reason: every feature baked in is a feature sshd's maintainers must understand, ship, secure, and support. The set of useful features (VPN flavors, proxy modes, application gateways) is open-ended and changes over time. A baked-in approach guarantees that sshd is always behind, and that the things it does include are a compromise.

The alternative is a clean separation. sshd does the part sshd is good at: authenticate the user, validate the cert, enforce the cert's policy. A separate plugin process does the application-specific work, having been handed a *pre-authorized* scope. The plugin never sees raw cert data, never makes auth decisions, and never operates outside the bounds sshd hands it. The plugin can be anything that speaks the protocol — a few hundred lines of Python or Go or Rust — and can be developed and deployed entirely separately from sshd.

A useful side effect: the same plugin pattern that enables VPN enables everything else. The mechanism is not VPN-specific. Naming it "channel" reflects its generality.

## What ships with mssh v1

Exactly one plugin: an `echo` plugin that accepts a channel, accepts bytes from the client, and writes them back. It exists to:

- Validate that the protocol works end-to-end.
- Provide a worked example for plugin authors.
- Give the test suite something to exercise against.

No VPN plugin. No proxy plugin. No kubernetes plugin. Those are out-of-tree projects that can ship independently. The mssh project's job is to define the protocol and validate it works, not to provide application-layer services.

## The mssh-channel-policy cert extension

The cert extension that grants channel access:

```
ChannelPolicy ::= SEQUENCE OF ChannelGrant

ChannelGrant ::= SEQUENCE {
   channelType     UTF8String,         -- e.g., "echo", "vpn-wireguard",
                                       --        "tcp-proxy", "k8s-api"
   scope           ChannelScope,
   duration        INTEGER OPTIONAL,   -- seconds; defaults to cert validity
   maxInstances    INTEGER DEFAULT 1,
   constraints     SEQUENCE OF Constraint OPTIONAL
}

ChannelScope ::= CHOICE {
   opaqueScope  [0] OCTET STRING,      -- channel-type-specific
                                       -- (often JSON; channel type
                                       --  defines the schema)
   structuredScope [1] SEQUENCE OF (UTF8String, ANY)
                                       -- for simple key/value scopes
}

Constraint ::= SEQUENCE {
   constraintType  UTF8String,
   constraintValue ANY
}
```

The `channelType` is a string identifier registered in a registry (informally for now, formally in a future spec annex). Built-in types:

| channelType        | Meaning                                              |
|--------------------|------------------------------------------------------|
| `echo`             | Reference plugin; echoes bytes back                  |
| `vpn-wireguard`    | WireGuard tunnel (if a plugin implements it)         |
| `vpn-ipsec`        | IPsec tunnel (if a plugin implements it)             |
| `tcp-proxy`        | sshuttle-style TCP forwarding (if a plugin)          |
| `k8s-api`          | Kubernetes API proxy (if a plugin)                   |
| `db-proxy`         | Database proxy, type identified in scope             |
| `recording`        | Audit/recording sidecar                              |
| `<vendor>.<name>`  | Vendor-specific (dotted-namespace identifier)        |

The `scope` is interpreted by the plugin for that channel type. For `echo`, the scope is empty. For `tcp-proxy`, it might be a list of permitted destinations: `{"hosts": ["10.0.1.0/24:443", "db.internal:5432"]}`. For `k8s-api`, it might be `{"clusters": ["prod"], "namespaces": ["app-frontend"], "verbs": ["get","list","watch"]}`. The cert format does not validate scope contents — it carries them. The plugin validates.

Common constraints:

- `maxBandwidthBps` — per-channel rate limit.
- `requireAuditTo` — list of audit endpoints the plugin must report to.
- `denyConcurrentWith` — list of channel types that may not be active simultaneously.

## Negotiation: from cert to channel

The flow:

1. **Auth completes** as in `04-handshake-and-hop-chain.md`. sshd has the validated client cert with its `mssh-channel-policy` extension parsed.
2. **Client requests a channel** by opening a special SSH channel type:
   ```
   byte      SSH_MSG_CHANNEL_OPEN
   string    "mssh-channel"
   uint32    sender channel
   uint32    initial window size
   uint32    maximum packet size
   string    channelType        ; e.g. "echo", "tcp-proxy"
   string    channelParameters  ; JSON, plugin-defined
   ```
3. **sshd looks up the channelType** in its `ChannelPlugin` config map. If no plugin is configured for that type, the open is refused with `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED` and the reason "no channel plugin configured for type X".
4. **sshd checks the cert's channel policy.** Is there a `ChannelGrant` matching this `channelType`? If yes, sshd extracts the scope and constraints. If no, the open is refused with the reason "cert does not grant channel type X".
5. **sshd connects to the plugin's Unix socket** (path from configuration) and sends a `negotiate` JSON-RPC call carrying:
   - The cert subject (user identity).
   - The cert's grant for this channel type (scope + constraints).
   - The client's `channelParameters` from the open request.
   - A session id (to correlate audit events).
6. **Plugin responds** with either `accept` (the channel may open, with any plugin-imposed parameter adjustments) or `reject` (with a reason). The plugin may also request that sshd open additional auxiliary channels — for instance, a VPN plugin may request a second channel for the dataplane control stream — though dataplane bytes flow through the plugin process, not through sshd.
7. **sshd opens the SSH channel** to the client on success, or refuses with the plugin's reason on failure.
8. **Data flow** from the client through sshd to the plugin. sshd is a relay for channel bytes; the plugin processes them and may write bytes back. sshd does not inspect the bytes, but does enforce window and packet-size accounting per the SSH connection protocol.

Note that for high-performance channel types (VPN-style), the design pattern is for the plugin to negotiate over the SSH channel and then establish a *separate* dataplane (WireGuard UDP, IPsec ESP) outside the SSH connection entirely. The SSH channel persists for control messages and teardown; the bulk data goes around. This avoids the TCP-over-TCP problem while keeping policy enforcement in sshd. For lower-volume channel types, all bytes can stay inside the SSH channel.

## The JSON-RPC protocol

Transport: a Unix domain socket, owned by the sshd user, mode 0600 (so only sshd can connect). Each socket serves one channel type — the plugin author starts the plugin daemon, points it at a socket path, and registers that path in `sshd_config`.

Framing: newline-delimited JSON. Each request is one JSON object on one line; each response is one JSON object on one line. JSON-RPC 2.0 semantics:

```json
{"jsonrpc": "2.0", "id": 42, "method": "negotiate", "params": {...}}
{"jsonrpc": "2.0", "id": 42, "result": {...}}
{"jsonrpc": "2.0", "id": 42, "error": {"code": -32000, "message": "..."}}
```

### Methods sshd calls on the plugin

#### negotiate

Called once per channel open request.

**params:**
```json
{
  "channelId": "ssh-session-abc/channel-1",
  "user": {
    "subject": "CN=alice, OU=users, O=Acme, C=US",
    "certSerial": "0123abcd",
    "certIssuerSki": "8c9f..."
  },
  "channelType": "tcp-proxy",
  "grantedScope": {"hosts": ["10.0.1.0/24:443"]},
  "grantedConstraints": [
    {"type": "maxBandwidthBps", "value": 1048576}
  ],
  "clientParameters": "{\"requested_host\":\"10.0.1.50:443\"}",
  "sessionMetadata": {
    "sourceIp": "192.0.2.42",
    "authTime": "2026-05-10T14:00:00Z"
  }
}
```

**result (accept):**
```json
{
  "action": "accept",
  "auxChannels": [],
  "pluginParameters": "{\"target\":\"10.0.1.50:443\"}"
}
```

**result (reject):**
```json
{
  "action": "reject",
  "reason": "Requested host 10.0.1.50:443 is in granted scope but plugin policy further restricts to 10.0.1.0/29; this host is not in /29."
}
```

The plugin's rejection reason is forwarded to the client as the channel-open failure description.

#### establish

Called after sshd has confirmed the channel to the client.

**params:**
```json
{
  "channelId": "ssh-session-abc/channel-1",
  "dataSocket": "/run/mssh/data-abc-1.sock"
}
```

sshd creates a second Unix socket (under the same security boundary) and listens. The plugin connects to this socket and reads/writes the channel data stream. sshd relays bytes between the SSH channel and the data socket.

**result:** simple ack.

#### teardown

Called when the SSH channel closes (either side).

**params:**
```json
{
  "channelId": "ssh-session-abc/channel-1",
  "reason": "client_closed",
  "durationSeconds": 142,
  "bytesIn": 12480,
  "bytesOut": 1492048
}
```

**result:** simple ack. The plugin cleans up any side state.

### Methods the plugin calls on sshd

Plugins occasionally need to ask sshd for things. sshd serves a small set of methods on the same socket, with the polarity inverted:

#### requestAuxChannel

The plugin requests sshd to open an additional SSH channel back to the client. Used for, e.g., a VPN plugin that wants both a control channel and a status-update channel.

**params:** channel type and parameters.

**result:** new channel id.

#### log

Plugin emits a log line to sshd's audit log. sshd may filter or annotate but does not refuse.

#### policyQuery

Plugin asks sshd to evaluate a policy question against the cert — for example, "does the cert allow the user to invoke audit mode?" sshd inspects the cert and returns yes/no. This avoids the plugin needing to re-parse cert extensions.

### Lifecycle

A plugin process can serve many channels concurrently. sshd accepts multiple JSON-RPC requests on the same socket connection (interleaved by `id`). The plugin must handle concurrent `negotiate` and `establish` calls.

When sshd starts, it connects to each configured plugin socket and sends a `helo` call:

```json
{"jsonrpc":"2.0","id":1,"method":"helo","params":{"sshd_version":"3.0.0","protocol_version":"acpp-1"}}
```

The plugin responds with its supported channel types and version. If the response is incompatible, sshd logs an error and refuses to use the plugin — but does not refuse to start (other plugins, and non-channel SSH activity, continue normally).

When sshd stops, it sends a `goodbye` to each plugin, allowing graceful teardown. The plugin may keep running and serve future sshd instances.

If a plugin process crashes mid-session, the data socket connection breaks, sshd notices, closes the affected channels with a clean error, and continues serving the SSH session for non-channel activity.

## Security boundary

The plugin is a separate process. sshd never executes plugin code in its own address space. The plugin runs as its own user, typically `mssh-plugin-<type>`, with no privileges except those needed for its job (a VPN plugin needs `CAP_NET_ADMIN`; an echo plugin needs nothing).

The Unix socket is the only IPC channel. There is no shared memory, no signals beyond standard process supervision, no environment-variable passing of secrets.

sshd never hands the plugin:

- The cert's private key.
- Other users' cert data.
- The trust root.
- Anything about other concurrent sessions.

sshd hands the plugin:

- The current user's cert subject (identity only).
- The current user's grant for this channel type.
- A data socket scoped to this channel.

A compromised plugin can therefore misbehave within its grant — for example, a compromised tcp-proxy plugin could leak data flowing through it. But it cannot escalate beyond its grant, cannot affect other channels or sessions, and cannot extract cert keys. The blast radius is bounded to the plugin's scope.

## Configuration

```
# sshd_config

ChannelPlugin echo /run/mssh/plugins/echo.sock
ChannelPlugin tcp-proxy /run/mssh/plugins/tcp-proxy.sock
ChannelPlugin vpn-wireguard /run/mssh/plugins/wg.sock

ChannelPluginUser echo mssh-plugin-echo
ChannelPluginUser tcp-proxy mssh-plugin-tcpproxy
ChannelPluginUser vpn-wireguard mssh-plugin-wg
```

sshd starts and connects to each configured socket. Each plugin must already be running (started by the operator's init system, systemd unit, runit script, etc.). sshd does not launch plugins — keeping process management out of sshd's responsibilities.

## The echo reference plugin

The shipping reference plugin is intentionally trivial. Pseudocode:

```
loop {
    accept JSON-RPC connection on socket
    spawn handler:
        on negotiate: respond accept
        on establish:
            connect to data socket
            loop {
                read bytes
                write same bytes back
            }
        on teardown: log and exit
}
```

About 100 lines in any reasonable language. The repository contains an implementation in Go (one source file, no external dependencies) and the equivalent in Python (using stdlib `asyncio` and `json`).

The point of shipping echo is to give plugin authors a concrete template, and to give the conformance suite a non-trivial-but-not-too-complicated subject for protocol testing.

## A worked example: how a hypothetical tcp-proxy plugin would work

This is not shipped, but illustrates the model:

1. A user's cert contains:
   ```
   mssh-channel-policy: [
     {"channelType": "tcp-proxy",
      "scope": {"hosts": ["10.0.1.0/24:443", "db.internal:5432"]}}
   ]
   ```
2. The user runs `mssh -L 8443:10.0.1.50:443 jumphost.example.com`. The client interprets `-L` as a request for a `tcp-proxy` channel.
3. The client connects to `jumphost.example.com`, authenticates, and opens an `mssh-channel` of type `tcp-proxy` with parameters `{"requested_host":"10.0.1.50:443"}`.
4. sshd on jumphost checks the cert's channel policy: yes, `tcp-proxy` granted, with scope including `10.0.1.0/24:443`. Requested host fits.
5. sshd negotiates with the tcp-proxy plugin via JSON-RPC. Plugin accepts.
6. sshd opens the SSH channel back to the client.
7. The client locally listens on port 8443. When a connection arrives, bytes flow: local app → client port 8443 → SSH channel → sshd → data socket → plugin → outbound TCP to 10.0.1.50:443.
8. Reverse direction symmetric.

The user gets sshuttle-like functionality (subnet TCP access via SSH) entirely through the channel mechanism. sshd has no idea what "tcp-proxy" means; it just enforces that the cert allows it and forwards bytes to the plugin. The plugin has no idea what authenticated the user; it just enforces its scope and proxies bytes.

## What this is not

- **Not a substitute for proper application-layer auth.** A channel grants byte-level access to a service. If the service has its own auth (a database, an API), that auth still applies. mssh doesn't replace it; it gates *whether* the user can talk to the service at all.
- **Not a replacement for VPNs that need to route IP packets.** A `tcp-proxy` channel is TCP-only. A `vpn-wireguard` channel routes IP. Choose the right tool. mssh provides the framework for both.
- **Not a sandbox.** The plugin runs in its own process with whatever privileges it needs. mssh does not constrain what the plugin can do beyond what the operator's deployment configures (user, capabilities, namespaces, etc.).
