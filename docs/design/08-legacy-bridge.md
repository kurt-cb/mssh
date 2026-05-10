# 08. Legacy Bridge

mssh refuses to talk to non-mssh peers by default. This is the right default — coexistence by default is what makes deprecation impossible. But there are real cases where a fresh deployment must connect to an existing host that does not yet speak mssh: legacy infrastructure mid-migration, third-party appliances, embedded devices awaiting firmware updates, etc.

The legacy bridge addresses this by allowing per-host opt-in to classic SSH. Critically, legacy is an **upgrade ramp**, not a sustaining mode.

## What legacy mode is and is not

Legacy mode is:

- A per-host configuration that allows an mssh client to connect to a specific named classic-SSH peer using classic SSH (public-key) auth.
- An audit-logged operational state — every legacy connection is recorded with a reason.
- A timer — every legacy host has an expiration date in configuration, beyond which connections to it fail.

Legacy mode is not:

- A global setting. There is no "enable legacy" switch. Each legacy peer is individually named.
- A way to enable password authentication. Even in legacy mode, passwords are still refused. Classic public-key auth, host-based auth, or pre-shared-cert auth is the only legacy mechanism.
- A long-term coexistence story. The expiration timer is mandatory and cannot be set to "never".

## Configuration

In `sshd_config` (and the symmetric client config):

```
LegacyHost old-router.example.internal {
    HostKeyFingerprint SHA256:abcdef...
    Until 2026-12-31
    Reason "Awaiting firmware update with mssh support; tracking ticket #1234"
    PermittedUsers admin, monitoring
    AuditTag legacy-router-fleet
}
```

Required fields:

- `HostKeyFingerprint` — the legacy host's classic SSH host key fingerprint. TOFU is forbidden in legacy mode; the fingerprint must be provided out of band and recorded.
- `Until` — date past which connections to this host fail.
- `Reason` — free-form text explaining why this legacy entry exists. Required.

Optional fields:

- `PermittedUsers` — only these users may connect via legacy mode. Default: any user with a valid mssh cert.
- `AuditTag` — tag for filtering audit logs.
- `RequiredCertExtension` — only certs carrying a specific extension OID may connect via legacy mode. Useful for restricting legacy access to specifically-blessed certs (`mssh-legacy-permitted` is a defined OID).

`LegacyHost` is the only way to enable classic SSH for a peer. There is no equivalent of `StrictHostKeyChecking no`, no `Host *` wildcard for legacy, no fallback if `LegacyHost` is absent — the connection simply fails.

## Connection flow

When an mssh client is asked to connect to a host:

1. The client checks its `LegacyHost` config for a matching entry.
2. If no match: mssh-only attempt. If the peer speaks mssh, proceed normally. If the peer offers only classic SSH, the client disconnects immediately with a clear error: "Peer speaks only classic SSH and is not in LegacyHost config."
3. If match: mssh attempt first. If the peer speaks mssh, proceed normally (the legacy config is unused — the peer has been upgraded but the config not yet cleaned up; this is fine and produces a warning).
4. If match and peer is classic-only: classic SSH handshake. Host key checked against `HostKeyFingerprint`. Auth uses the client's mssh cert key as a classic SSH public key (the key portion of the cert is usable directly; the mssh-specific extensions are simply not understood by the legacy peer, which sees only the public key). The connection log records `mode=legacy` with the configured reason.

The reverse direction (mssh server accepting a classic client) follows symmetrically. Classic clients are refused unless their hostname or source-IP is in a `LegacyHost` entry on the server.

## Why public-key works without certs

The classic SSH `publickey` auth method allows a client to authenticate with a raw public key (server-side `authorized_keys` file). An mssh client's cert is built around a keypair; the raw public key can be extracted and used in classic SSH auth.

In legacy mode, the client's cert public key is presented to the legacy peer as a classic `ssh-rsa` or `ssh-ed25519` key. The legacy peer recognizes it (because the admin has added it to `authorized_keys` during legacy onboarding) and accepts the connection. The classic peer never sees the cert envelope; the mssh-specific policy (source-bind, hop delegation, time windows) is enforced only at the mssh end of the connection.

This means a legacy connection has weaker security than an mssh-to-mssh one. The cert's policy is only enforced at the mssh side. The legacy peer sees only "this is the public key we trust" and proceeds. Operators should treat legacy connections as if they were classic SSH — because functionally, they are.

## The upgrade ceremony

When a legacy host is upgraded to mssh, the transition is intentionally explicit:

1. The legacy host's operator runs the mssh server on the host.
2. They generate a CSR for the host, signing it with the existing host key (or a new key — the choice is theirs).
3. They submit the CSR to their CA over the legacy-onboarding endpoint: `POST /v1/csr-legacy-onboard`. This endpoint requires:
   - Mutual TLS with an administrator cert.
   - The legacy host's existing classic SSH host key signature over the CSR. This proves continuity — the same entity that controlled the legacy host is now requesting a cert.
   - A `legacyHostFingerprint` field matching the fingerprint recorded in any peer's `LegacyHost.HostKeyFingerprint` config.
4. The CA issues a machine cert. Audit log records the legacy-onboarding event linking the old fingerprint to the new cert serial.
5. The operator deploys the new cert on the host, updates sshd config to use it, restarts sshd.
6. Peers connect: their mssh attempt now succeeds. The connection log on the peer notes that legacy mode is no longer needed.
7. After some validation period (operator's choice; typically a week), peers remove the `LegacyHost` entry from their configs. From that point, any attempted classic SSH connection from this host fails (which would only happen if the host has regressed — a useful alarm).

The `csr-legacy-onboard` endpoint exists precisely to bridge the trust gap between "this host had a classic SSH key we knew" and "this host now has a CA-issued cert." Without it, every legacy host would require fresh out-of-band enrollment, which is a real friction point in fleet upgrades.

## Hop chain and legacy

When an mssh-to-mssh session traverses a hop chain, every hop must be mssh. A legacy hop is not permitted, because there is no way for a legacy hop to attest its participation in the chain.

When a client uses legacy mode to reach a classic host, the connection is direct — no hops, no chain attestation. If the user needs to reach a classic host that lives behind an mssh jump host, the user connects to the jump host (mssh) and from there to the classic host (legacy mode is configured on the jump host, not on the user's client). This is operationally annoying but architecturally clean: the trust boundary is visible.

## Connection limits and accountability

Every legacy connection is logged with:

- Timestamp.
- Legacy host name and configured reason.
- Client cert subject.
- Source IP.
- Duration.
- `AuditTag` for grouping.

The server (or client) MAY rate-limit legacy connections to make accidentally-permanent legacy hosts more visible: e.g., a `MaxLegacyConnectionsPerDay` limit per `AuditTag`. Exceeding the limit produces a warning, then refusal. The intent is to make sure legacy hosts that should have been upgraded long ago start surfacing in operator pain.

## What legacy mode forbids

Even in legacy mode:

- **Passwords are still refused.** A legacy peer that only accepts passwords is incompatible with mssh, full stop. The peer must speak at least classic `publickey` auth.
- **Keyboard-interactive auth is refused.** Same reasoning.
- **GSSAPI, host-based, and exotic auth methods are refused.** Only `publickey`.
- **No tunneling forwards (`tun`/`tap`) over legacy connections.** Channel plugins do not engage on legacy connections.
- **No mid-session rotation over legacy.** Legacy is a static connection — established with a fixed key, runs until disconnect.
- **No automatic legacy fallback.** A peer that *advertises* mssh but fails the mssh handshake is treated as broken, not legacy. Legacy mode only engages for peers that do not speak mssh at all.

## The non-extension

Note what is intentionally absent: there is no `LegacyMode permanent` setting, no `LegacyHost --until forever`, no global enable. The protocol leaves no comfortable place for legacy to settle in. Every `Until` date is a forcing function — when it expires, the connection breaks, and the operator must either upgrade the host or extend the date with a fresh `Reason`.

This is a deliberate design choice. SSH's longevity is partly because backward compatibility was always available indefinitely; the side effect was that insecure modes lingered for decades. mssh makes backward compatibility a sunset, not an addition.
