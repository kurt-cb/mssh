# Doc fix patch 2: security claims precision

Two corrections to security claims, prompted by reviewer questions about specific imprecision in the existing text.

## Substantive changes

### 1. Cert vs private key, and forward secrecy

The exec overview previously claimed "worst-case exposure of any credential is the cert lifetime — a stolen 8-hour cert is at most 8 hours of damage." This was imprecise on two axes:

- **Wrong noun.** The credential is the private key, not the cert. The cert is the CA-attested wrapper around the public key; both cert and public key are, by design, public. What an attacker steals is the private key.
- **Wrong scope.** The cert lifetime bounds *future authentication* with the stolen key, not "all damage." Previously-recorded session traffic is protected by SSH's forward-secrecy property (ephemeral KEX keys, never derived from the long-term private key) and cannot be decrypted by stealing the long-term key regardless of cert lifetime.

The updated text says, precisely: a stolen private key allows real-time impersonation only until the corresponding cert expires; SSH's forward-secret session encryption is preserved unchanged in mssh.

### 2. Hop chain limits and bypass via non-cooperating transit

The exec overview's hop-chain section previously implied chain attestation was automatic for any multi-hop session. It isn't. Chain integrity is built by cooperating mssh hops; users who route through classic SSH hosts, TCP port forwarders, or arbitrary relays evade chain enforcement for those legs.

This is a real and structural limit, not a bug. The updated text:

- Explicitly names the three bypass cases (classic SSH intermediate, port forwarding, arbitrary TCP relay).
- Describes the two structural defenses (source binding evaluated at the destination's actual TCP peer IP; destination policy requiring chain attestation).
- Notes that both should be configured together where hop-deleg enforcement is load-bearing.

The threat model adds a corresponding adversary entry ("User bypassing hop attestation via non-cooperating transit") and a non-defense entry, plus an expanded "Compromised intermediate hop" entry that distinguishes the protocol property (compromised cooperating hops cannot rewrite identity) from the structural property (non-cooperating intermediates are invisible to the protocol).

Doc 04's "Why this is safe" section was renamed "Why this is safe (and what 'safe' actually means)" and its qualifier was made explicit: the safety property holds *for sessions where every intermediate is a cooperating mssh hop participating in the chain protocol*. The qualifier is load-bearing.

## Files modified

| File                                              | Change            | Topic                                |
|---------------------------------------------------|-------------------|--------------------------------------|
| `docs/exec/overview.md`                           | +15/-2            | Both fixes                           |
| `docs/design/12-threat-model.md`                  | +33/-5            | Stolen key precision + hop chain bypass adversary |
| `docs/design/04-handshake-and-hop-chain.md`       | +14/-4            | "Why this is safe" qualified         |

No new files. No structural changes. Pure text precision updates.

## Recommended commit message

```
Tighten security claims: forward secrecy, hop chain bypass limits

Two precision fixes prompted by review:

1. Distinguish private key (credential) from cert (wrapper), and
   acknowledge SSH's forward-secrecy property: a stolen long-term
   private key enables real-time impersonation only until the cert
   expires; it does not enable decryption of past session traffic
   regardless of when stolen.

2. Acknowledge that mssh-hop-deleg policy only applies when users
   route through cooperating mssh infrastructure. Classic SSH
   intermediates, TCP port forwarding, and arbitrary TCP relays
   are invisible to chain attestation and bypass hop-deleg by
   construction. Mitigations are source binding (evaluated at the
   destination's actual peer IP) and destination policy requiring
   chain attestation; both should be configured together where
   hop-deleg is load-bearing.

Updated: docs/exec/overview.md, docs/design/12-threat-model.md,
docs/design/04-handshake-and-hop-chain.md.
```
