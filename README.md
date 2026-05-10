# mssh

A certificate-first SSH protocol and reference implementation. mssh keeps everything that works about SSH — transport encryption, channel multiplexing, port forwarding, SFTP — and replaces the parts that haven't aged well: trust on first use, long-lived keys, manual `authorized_keys` distribution, and password authentication.

**Current status: design phase.** This repository contains the protocol specification and design documents. A reference implementation has not yet been started.

## What mssh is

Classic SSH establishes trust through a combination of TOFU host key acceptance and out-of-band public key distribution. Both mechanisms have aged poorly: TOFU means users click through warnings they cannot evaluate, and `authorized_keys` distribution is a configuration management problem disguised as security.

mssh replaces both with X.509 certificate-based mutual authentication anchored to a Certificate Authority. Users and hosts have short-lived certs (hours for users, days for machines). The CA enforces issuance policy, including 2FA, source-address restrictions, time windows, and authorized-channel grants. Cert validity is the principal revocation mechanism — short lifetimes make "did everyone get the memo" stop being the question.

mssh also defines:

- A **hop chain attestation** for multi-hop sessions through jumphosts, with end-to-end identity preservation that classic ProxyJump does not provide.
- **First-class compatibility with existing SSH public keys.** A user's existing `id_ed25519` (or `id_rsa`, etc.) is the credential; the mssh cert is a CA-attested wrapper around it. Users keep their keys, their SSH agents, their tooling, their GitHub access. Servers can be configured to accept either cert-bearing or bare public-key auth during migration.
- An **authenticated channel plugin protocol** (JSON-RPC over Unix socket) for application services like VPN, database proxies, kubernetes API gateways — sshd authenticates, plugins deliver, the security boundary is clean.
- A **conformance test suite** that CAs must pass for their certs to be trusted at runtime, preventing CAs from drifting from the spec.
- A **constrained profile** for embedded targets (Dropbear-class), with full mssh interop in about 360 KB.
- **In-session cert rotation** so sessions can outlive any single cert.
- A **legacy bridge** with mandatory sunset dates for hosts that haven't yet been upgraded from classic SSH.

What mssh does *not* do is also important — see `docs/design/00-overview.md` for the explicit non-goals.

## Where to start reading

For decision-makers and curious readers:

- **[`docs/exec/overview.md`](docs/exec/overview.md)** — Executive overview with diagrams. Start here if you want the gist in 15 minutes.

For implementers and protocol engineers:

- **[`docs/spec/mssh-protocol.md`](docs/spec/mssh-protocol.md)** — Normative wire specification, RFC-style.
- **[`docs/design/`](docs/design/)** — Sixteen design documents covering rationale, architecture, threat model, and edge cases. Read in numerical order, or jump to specific topics.

For operators evaluating adoption:

- **[`docs/design/15-ssh-key-compatibility.md`](docs/design/15-ssh-key-compatibility.md)** — How mssh interoperates with the SSH keys you already have. Probably the most important doc for adoption decisions.
- **[`docs/design/12-threat-model.md`](docs/design/12-threat-model.md)** — What mssh defends against and what it does not.
- **[`docs/design/07-embedded-ca.md`](docs/design/07-embedded-ca.md)** — The minimal in-tree CA for small deployments.
- **[`docs/design/08-legacy-bridge.md`](docs/design/08-legacy-bridge.md)** — Migration from classic SSH (server-side and client-side directions).

## Repository layout

```
mssh/
├── README.md                        # This file
├── LICENSE                          # Apache 2.0
├── LICENSE-NOTE.md                  # Why Apache 2.0 and not GPL
├── CONTRIBUTING.md                  # How to contribute
├── docs/
│   ├── exec/
│   │   ├── overview.md              # Human-readable executive overview
│   │   └── diagrams/                # SVGs embedded in the overview
│   ├── design/                      # Detailed design rationale (16 docs)
│   └── spec/
│       └── mssh-protocol.md         # Normative protocol specification
└── .github/                         # Issue templates, workflows (future)
```

## What's not here yet

- Source code. No reference implementation has been started.
- Test vectors. The conformance suite is specified but not yet codified.
- Production-grade tooling (CA, client, server). Subject of future work.

The design is intentionally implementation-agnostic; multiple reference implementations are welcome.

## Naming and scope

"mssh" is both the protocol name and the implementation name — analogous to "TLS" being both. Where context might be ambiguous, "mssh protocol" or "mssh implementation" is used.

The protocol borrows substantially from the SSH transport layer (RFC 4253) and connection protocol (RFC 4254). What changes is user authentication, plus the new features listed above. Implementers porting from OpenSSH should find most code reusable.

## License

Apache License 2.0. See `LICENSE` and `LICENSE-NOTE.md` for the reasoning and tradeoffs.

The design and specification documents are under the same license at this initial drop; CC-BY-4.0 may be a more appropriate license for the spec documents going forward, to encourage independent implementations.

## Contributing

This is open work in the open. Issues, pull requests, and design discussions all welcome. See `CONTRIBUTING.md`.

The most valuable contributions right now are:

1. **Design review.** Find the holes. Argue with decisions. Propose alternatives.
2. **Threat modeling.** What did we miss? What's understated?
3. **Implementer perspectives.** If you were to build this, what's missing from the spec that you'd want?

Implementation contributions will be welcome once the design has settled and the protocol is more stable.

## Acknowledgments

This project began as a re-imagining of [sshadmin](https://github.com/kurt-cb/sshadmin) — taking its operational insight about cert-based SSH administration and asking what the protocol would look like if cert-first were the default rather than an admin tool layered on top.
