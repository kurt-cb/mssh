# 14. Debuggability and Operational Visibility

Classic SSH is notoriously hard to debug. The protocol's security-driven information hiding leaks into operational opacity: when something fails, the user gets "Permission denied (publickey)" and the operator gets a server-side log entry that might say "Connection closed by authenticating user" with no useful detail. The user has no idea which of their keys was tried, the server has no obligation to say what was wrong, and the gap fills with workarounds (force-specifying `IdentityFile`, setting `IdentitiesOnly yes`, running with `-vvv`, comparing notes between client and server logs).

mssh takes a different approach. Its security model still requires that the server not leak detail about *why* it rejected a cert — that's still an oracle. But mssh changes the client side: the client knows exactly what it tried, because it tried exactly one thing. The result is dramatically improved debuggability without weakening the wire-level security guarantee.

This document catalogs the debuggability improvements and the design decisions behind them.

## The cert-thrashing problem

### What goes wrong in classic SSH

A user with multiple keys in their agent (corporate, personal, side-project, the test key from that one demo) tries to connect to a server. The classic SSH client offers keys one at a time. The server tries each against its `authorized_keys`, fails, and tracks attempts against `MaxAuthTries` (default 6). If the user has 7+ keys, the server disconnects before reaching the right one. The user sees:

```
$ ssh user@server.example.com
user@server.example.com: Permission denied (publickey).
```

No information about which keys were tried, in what order, or which one the server actually wanted. The user resorts to `-i ~/.ssh/specific_key` or adding an explicit `IdentityFile` block to `~/.ssh/config`, which then breaks the next time they need a different key for the same server.

The cause is structural: the client has no way to know which key the server expects, and the server has no way to hint without leaking. Classic SSH made the trade-off in favor of not leaking, which is correct but leaves users stuck.

### How mssh eliminates it

mssh does not iterate over keys. The client has exactly one cert per principal at a time, obtained from the CA at session start. When connecting to a server, the client presents that cert. There is no "try the next one" cycle because there is no next one.

If the connection fails because the cert is wrong for this server (cert chains to a CA the server doesn't trust, cert subject doesn't match an allowed user, cert has insufficient channel policy, etc.), the client knows:

- Which cert it presented (subject, issuer, validity, all extensions).
- Which server it connected to.
- That the server rejected the connection.

The server still does not say *why* it rejected. But the client can produce a useful error locally:

```
$ mssh user@server.example.com
mssh: connection refused by server.example.com.
       Cert subject: CN=alice, OU=users, O=Example Corp
       Cert issuer:  CN=Example Intermediate, OU=ca, O=Example Corp
       Cert serial:  0123abcd
       Cert valid:   2026-05-10 09:00 UTC to 2026-05-10 17:00 UTC
       Source IP:    192.0.2.42 (matches cert source-bind)
       
       The server rejected this cert. Common causes:
         - This cert's CA is not trusted by this server
         - This server requires a cert with channel policy you don't have
         - This server requires recent 2FA (yours is from 09:00 UTC)
         - This server expects a cluster-scoped cert (yours is unscoped)
       
       Server-side logs will have the specific reason. Ask your server
       administrator for the rejection log for serial 0123abcd at 14:32 UTC.
```

This is genuinely useful. The user has all the information they could reasonably need, the server gave away no specifics, and there's a clear path forward.

### The "no useful client-side info" failure mode is gone

In classic SSH, the asymmetry was unfair: the client knows nothing, the server knows everything. The user calls support; support is the server admin; admin reads the log; admin tells user. mssh closes most of that loop: client knows what it sent, user can self-serve most diagnoses, the server admin is only needed for the genuinely server-side reasons (CA trust config, host-specific policy).

## Server-side error logging

While the server doesn't leak rejection reasons over the wire, it MUST log them locally with enough detail for an administrator to diagnose. Specifically, every cert rejection produces a log entry with:

- Timestamp (with microsecond precision so concurrent events can be ordered).
- Source IP and port.
- Cert serial (the only attacker-visible identifier).
- Cert subject and issuer.
- The specific error code from the protocol error registry.
- The exact failing check (e.g., `SOURCE_BIND_MISMATCH: cert source-bind is 10.0.0.0/24, connection from 192.0.2.42`).
- Any contextual policy state (e.g., for `TIME_WINDOW_VIOLATION`: "cert valid until 17:00 UTC, current time 17:32 UTC").

Log format is structured (JSON or logfmt) so it ships cleanly into log aggregators. The server admin can query: "show me all rejections for cert serial 0123abcd in the last hour" and get the answer immediately.

## The serial number as a correlation handle

Every cert has a unique serial. Both client and server know it. When a user reports a problem, the serial is the only piece of information needed to find both sides of the failure:

- Client log: "Presented cert serial 0123abcd; rejected."
- Server log: "Rejected cert serial 0123abcd: SOURCE_BIND_MISMATCH."
- CA audit log: "Issued cert serial 0123abcd to alice@example.com at 09:00 UTC with source-bind 10.0.0.0/24."

The triangulation is mechanical. No correlation by timestamp guesswork, no matching log lines by IP across machines. Just grep for the serial.

This applies to hop chains too: each hop's cert has a serial, each hop entry is signed and timestamped, and a chain validation failure at the destination logs the specific hop entry that failed. Distributed debugging across a chain becomes a matter of querying each hop's log for the relevant serial.

## Pre-flight validation

The mssh client SHOULD support a `--check` mode that validates a cert without making a connection:

```
$ mssh --check user@server.example.com
Cert presentation summary:
  Subject:           CN=alice, OU=users, O=Example Corp
  Issuer:            CN=Example Intermediate, OU=ca, O=Example Corp
  Serial:            0123abcd
  Valid:             2026-05-10 09:00 UTC to 17:00 UTC (3h 28m remaining)
  Source-bind:       10.0.0.0/24
  Local IP:          192.0.2.42  ← MISMATCH (not in 10.0.0.0/24)
  2FA freshness:     5h 32m ago (depth 0)
  Hop deleg:         allows 4 hops via cluster=jumphost-prod
  Channel policy:    [{type: "echo"}, {type: "tcp-proxy", scope: ...}]
  
Trust root configured for server: <not yet attempted>

Issues detected:
  ⚠ Local IP 192.0.2.42 is not in cert source-bind 10.0.0.0/24.
    Connection will likely fail. Rebind via CA before connecting:
      mssh-ca rebind --new-source 192.0.2.42
```

The check doesn't connect. It just shows what *would* be presented and flags obvious issues the client can detect locally. This catches the source-bind problems, expired certs, missing channel policy for `-L` requests, and stale 2FA before the user wastes a round trip.

## Verbose mode actually verbose

`mssh -v` shows the full handshake decision flow on the client side. Not just "negotiated", but every check the client made:

```
$ mssh -v user@server.example.com
[14:32:01.001] Resolving server.example.com (DNSSEC required)
[14:32:01.045] Resolved to 192.0.2.50, AD bit set, source: dns-validated
[14:32:01.046] Connecting to 192.0.2.50:22
[14:32:01.089] TCP connected, starting SSH transport
[14:32:01.142] KEX complete (curve25519-sha256, chacha20-poly1305)
[14:32:01.143] Server presented cert serial f0e0d0c0, subject CN=server.example.com
[14:32:01.144] Cert chain: 1 intermediate, validates to trust root "example-root"
[14:32:01.144] Cert profile check: passed (full profile)
[14:32:01.145] CA conformance attestation: valid, attestor self-signed
[14:32:01.145] Cert hostname match: CN=server.example.com matches connection target
[14:32:01.145] SSHFP lookup: no records present, cert is sole authority
[14:32:01.146] Server cert validated.
[14:32:01.147] Sending userauth: subject CN=alice, serial 0123abcd
[14:32:01.149] hop-chain-follows: false
[14:32:01.149] channel-request-follows: false
[14:32:01.231] Server rejected: USERAUTH_FAILURE (no further methods)
[14:32:01.231] Connection closed.

Client-side analysis:
  Cert presented:    serial 0123abcd, valid for 3h 28m
  Source-bind check: PASS (local 192.0.2.42 in 10.0.0.0/24)
  Likely cause:      Server does not trust this cert's CA.
                     Server trust roots are not visible to client.
                     Contact server admin or check server's TrustRoot config.
```

The output is dense but every line is useful. There is no "skipping key 1, trying key 2, skipping key 3" noise because that doesn't happen.

## Server-side observability endpoints

For administrators, mssh sshd SHOULD expose an admin socket (Unix socket, restricted permissions) for runtime queries:

```
mssh-sshctl status
  Active sessions: 12
  Last cert rejection: 14:32:01 UTC, serial 0123abcd, SOURCE_BIND_MISMATCH
  Last cert acceptance: 14:31:58 UTC, serial 0456cdef
  CA reachable: yes (last contacted 14:31:30 UTC)

mssh-sshctl reject-log --serial 0123abcd
  14:32:01.231 SOURCE_BIND_MISMATCH cert source-bind 10.0.0.0/24,
                                    connection from 192.0.2.42
  (no prior rejections for this serial)

mssh-sshctl trust-config
  TrustRoot 1: "example-root", SKI ab12cd34, valid until 2027-01-01
  TrustRoot 2: "example-staging-root", SKI ef56gh78, valid until 2026-09-01
  TrustedAttestor: example-conformance-attestor, key SKI ...
```

This replaces the OpenSSH model of "edit `sshd_config`, restart sshd, check `journalctl`" with direct runtime introspection.

## CA-side observability

The CA's REST API includes `/v1/audit/{issuanceLogId}` for retrieving the audit record of a specific issuance. A user troubleshooting a problem can ask "where did this cert come from and what did I do at issuance?" and get a complete answer.

The embedded CA's CLI provides equivalent local queries:

```
mssh-ca audit --serial 0123abcd
  Issued:           2026-05-10 09:00:00 UTC
  To:               CN=alice, OU=users, O=Example Corp
  By:               CN=Example Intermediate
  Requested from:   192.0.2.42
  2FA methods:      totp (09:00:00), smartcard-pin (08:59:55)
  Policy decisions:
    - validity narrowed: requested 28800s, granted 28800s
    - source-bind: granted as requested (10.0.0.0/24)
  Channel policy:   echo, tcp-proxy
```

The audit trail is a first-class observability surface, not a forensic afterthought.

## What this enables

A real operational scenario, end to end:

1. User reports: "I can't connect to server.example.com. Help."
2. User runs `mssh -v user@server.example.com`. Output shows cert serial `0123abcd` was rejected.
3. User runs `mssh --check user@server.example.com`. Output flags: "Local IP 192.0.2.42 is not in cert source-bind 10.0.0.0/24."
4. User self-diagnoses: "Oh, I'm at a coffee shop, not at the office. Need to rebind."
5. User runs `mssh-ca rebind --new-source 192.0.2.42`. CA prompts for TOTP. New cert issued.
6. User retries. Works.

Total: about 90 seconds. No support ticket. In the classic SSH equivalent, this is "I can't connect, the message says permission denied, I tried `-i` with all my keys, none work, please help" — and the response involves an admin reading server logs and getting back the next morning.

## Implementation requirements

The protocol does not mandate any of the above tooling. It mandates the *capability* — the cert serial as a stable identifier, the structured error registry, the audit log format — and lets implementations build whatever surface they want on top. The recommendations in this document represent the reference experience; minimal implementations may provide less and conformant implementations may provide more.

What is mandatory at the protocol level (and tested by the conformance suite):

- Stable error codes from the registry in protocol responses (server-side log entries) and CA REST responses.
- Cert serials present and unique per issuing CA.
- Audit log records for every CA issuance, retrievable via `/v1/audit/{logId}`.
- Hop chain entries individually identifiable for distributed debugging.

What is recommended (and shipped by the reference implementation):

- Client-side detailed error output on connection failure.
- `--check` mode for pre-flight validation.
- `-v` mode with structured handshake trace.
- Server-side admin socket for runtime queries.
- CA-side audit query tools.

## The principle

Security and operability are not in tension here. The information the user needs to debug their own problems is information the user has on their own machine — they have their cert, they know what they typed, they know their local network state. The information the server has the right to withhold (which checks failed and how to bypass them) stays withheld. Closing the operability gap is mostly a matter of surfacing the information that's already available, not weakening the security model.

The result is an SSH variant that's actually pleasant to operate. Users don't dread connection failures because they can diagnose them. Admins don't drown in tickets because users self-serve. The "permission denied (publickey)" message that defined classic SSH's UX failure mode does not exist in mssh.
