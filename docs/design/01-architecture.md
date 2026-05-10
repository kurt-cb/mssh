# 01. Architecture

## Components

```
                              +-----------------+
                              |   Trust root    |
                              |  (offline root  |
                              |   CA cert/key)  |
                              +--------+--------+
                                       |
                              signs intermediate
                                       |
                                       v
   +-----------------+         +-----------------+         +-----------------+
   |  mssh client   |  mTLS   |   External CA   |  mTLS   |  mssh server   |
   |                 |<------->|     daemon      |<------->|     (sshd)      |
   |  - cert store   |  REST   |                 |  REST   |                 |
   |  - PKCS#11      |         |  - LDAP/AD,     |         |  - cert store   |
   |  - channel      |         |    DB, etc.     |         |  - profile      |
   |    plugin(s)    |         |  - policy       |         |    validator    |
   |    (optional)   |         |  - revocation   |         |  - channel      |
   +--------+--------+         +-----------------+         |    plugin(s)    |
            |                                              |    (optional)   |
            |                                              +--------+--------+
            |                  mssh over TCP/22                    |
            +------------------------------------------------------>+
                                  (auth + hop chain)

   Optional alternative: embedded CA instead of external
   +--------+--------+
   |  mssh server   |
   |  with embedded  |
   |       CA        |
   +-----------------+
```

The components are:

**mssh client.** A user-facing or scripted client. Loads a cert from a local store or a PKCS#11 device. Negotiates the mssh handshake. Participates in cert rotation. Optionally invokes one or more channel plugins over local plugin sockets, if the negotiated cert grants channel policy.

**mssh server.** A modified `sshd`. Validates client certs against the configured trust root and the cert profile. Maintains its own cert for server authentication. Talks to the external CA (or invokes its embedded CA) for rotation and revocation checks. Optionally invokes one or more channel plugins.

**External CA daemon.** A separate process exposing the mssh CA REST API over mTLS. Issues, renews, and revokes certs. Implements whatever policy the operator needs (LDAP/AD lookups, time-based access rules, approval workflows, etc.). The protocol is fixed; the policy and storage layer is the implementer's choice.

**Embedded CA.** A minimal CA compiled into sshd itself, for small deployments. Implements the same REST API exposed on a local Unix socket. File-backed. No external dependencies. Detailed in `07-embedded-ca.md`.

**Trust root.** A self-signed root CA cert and (ideally offline) private key. Signs one or more intermediate CA certs. The intermediates do the day-to-day issuance.

**Channel plugin(s).** Optional, zero or more. Each is a separate process that speaks the Authenticated Channel Plugin Protocol over a Unix socket. sshd hands a plugin the authenticated cert's `mssh-channel-policy` extension content scoped to that plugin's channel type, plus a control channel; the plugin does whatever it does — establish a WireGuard or IPsec tunnel, proxy TCP connections sshuttle-style, broker access to a kubernetes API or a database, etc. Only a trivial `echo` reference plugin ships with v1. Detailed in `09-channel-plugin-interface.md`.

## Process boundaries

Each box in the diagram is a separate process. sshd does **not** load the CA, any channel plugin, or any LDAP/AD client into its own address space. The reasons:

- **Privilege separation.** sshd already does this internally (privsep). The same logic extends outward.
- **Plugin safety.** A buggy channel plugin can crash without taking sshd with it.
- **Language freedom.** The CA daemon can be written in Go, Rust, Python, or anything else that speaks mTLS and HTTPS. Channel plugins can be written in anything that speaks JSON-RPC over a Unix socket.
- **Update independence.** The CA can be restarted to pick up policy changes without disturbing active SSH sessions.

The only exception is the embedded CA, which runs in-process for the explicit case of a small deployment where the operator wants a single binary. Even then, it is implemented as if it were external — same API, same code paths — so the in-process variant is a build-time choice, not a separate codebase.

## Data flow: a typical session

1. **User obtains a cert.** Out-of-band, the user authenticates to the CA (some combination of password, 2FA, smartcard PIN, biometric — whatever the CA's policy demands). The CA issues a short-lived cert (hours to days). The cert is stored on the user's smartcard or in a local keystore.

2. **Client connects to server.** Client opens TCP to port 22, performs the SSH-TRANS key exchange (RFC 4253), and during user authentication presents its cert.

3. **Server validates the cert.** sshd checks:
   - Signature chain to a configured trust root.
   - Validity window (not-before / not-after).
   - Source-address binding (the connecting IP must match the cert's allowed sources).
   - Cert profile conformance.
   - Revocation status (CRL or OCSP, depending on configuration).
   - Policy extensions relevant to this server (e.g., is this user authorized for this host?).

4. **Server validates the hop chain (if applicable).** If the connection arrived through one or more mssh hops, the chain attestation from each hop is verified against the trust root, and the destination confirms that delegation through these specific hops was permitted by the cert's hop-delegation extension.

5. **Server presents its own cert.** The client validates it against the configured trust root and verifies host identity (cert subject matches the requested hostname, optionally cross-checked against SSHFP records).

6. **Session opens.** Standard SSH channels (`session`, `direct-tcpip`, `forwarded-tcpip`, SFTP subsystem, etc.) work as in classic SSH. The user's identity is the cert's subject. Authorization decisions (sudo, file access, etc.) are out of scope — they happen at the OS layer as today.

7. **Mid-session rotation (if triggered).** If the cert is approaching expiry, or if the server's policy requires rotation on certain events, either side may initiate a rotation. The party needing a new cert contacts its CA over the REST API and obtains one. The new cert is signaled to the peer via a defined SSH message; the peer revalidates. If validation fails or the user declines, the session terminates cleanly.

8. **Session ends.** Either side closes, or the cert expires and the session is forcibly closed. No grace period beyond what the cert's expiry allows.

## Where state lives

- **Long-term private keys** live on smartcards or in local keystores. Never on disk in plaintext.
- **Issued certs** live in the CA's database (external CA) or in a flat-file store (embedded CA).
- **Revocation state** lives at the CA. Servers consult it via CRL or OCSP.
- **Trust roots** live in a configuration file on each sshd and each client. Adding or removing a trust root is a manual operation.
- **Per-session state** is ephemeral: in-memory in sshd and the client.
- **Policy** lives at the CA. sshd enforces what the cert says, but does not make policy decisions itself.

This last point matters. sshd is intentionally not a policy engine. It validates the cert, checks the cert's extensions, and either lets the connection proceed or refuses. Anything more sophisticated — "this user can access this host only between 9am and 5pm Tuesdays" — is encoded by the CA into a cert's time-window extension. sshd just reads it.

## Configuration surface

sshd configuration adds (relative to OpenSSH):

- `TrustRoot` — path to a root CA cert (one or more).
- `CAEndpoint` — URL of the external CA, or `embedded` for the in-process CA.
- `CACertPath`, `CAKeyPath`, `CAClientCertPath`, `CAClientKeyPath` — mTLS material for talking to the external CA.
- `CertProfile` — `constrained` or `full`. Determines which profile sshd validates against.
- `LegacyHost` — repeatable. Specifies a hostname for which classic SSH fallback is allowed, with associated config. See `08-legacy-bridge.md`.
- `ChannelPlugin` — repeatable. Each entry binds a channel-type identifier (e.g., `vpn-wireguard`, `tcp-proxy`, `echo`) to the Unix socket path where that plugin listens.
- `RotationPolicy` — when to require rotation (time-remaining threshold, source-address change, etc.).

OpenSSH config directives that no longer apply:

- `PasswordAuthentication` — always treated as `no`. Setting it to `yes` is a fatal config error.
- `ChallengeResponseAuthentication`, `KbdInteractiveAuthentication` — likewise.
- `PermitEmptyPasswords` — fatal config error.
- `AuthorizedKeysFile` — only consulted in legacy mode.
- `TrustedUserCAKeys` — replaced by `TrustRoot` (different format, different semantics).
