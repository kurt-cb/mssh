# 10. DNSSEC and SSHFP

DNS is the lookup layer SSH depends on. An attacker who can poison DNS responses can redirect an SSH client to a host they control. Classic SSH defends against this with TOFU host keys: the client cached the legitimate host's key on first connection, and rejects mismatched keys later. mssh replaces TOFU with cert validation, which means it must defend DNS lookups at the resolution layer rather than at the host-key layer.

This document defines how. The short version: use the system resolver, require DNSSEC validation, and treat SSHFP records as a defense-in-depth cross-check.

## What mssh does not do

mssh does not embed a DNS resolver. Specifically, no copy of `libunbound`, no Bind embedded mode, no in-process DNSSEC validation. The reasons:

- **Attack surface.** DNS resolvers historically have CVEs at the parsing layer (compressed name pointers, large response handling, the works). Pulling one into sshd inherits that attack surface in the most security-sensitive process on the host.
- **Footprint.** Even slim resolvers are tens of thousands of lines. Dropbear-class targets can't carry them.
- **Operational duplication.** Hosts already have a system resolver. Having two resolvers (one in sshd, one for everything else) means two trust configurations, two sets of nameserver definitions, two failure modes. Operators will get this wrong.
- **System resolvers are improving.** `systemd-resolved`, `unbound`, `dnscrypt-proxy`, recent macOS, recent Windows — all do DNSSEC validation when configured to. The right place to invest is in the system layer, not in sshd's address space.

## What mssh requires

mssh clients and servers:

1. Use the system resolver via the standard `getaddrinfo`-style API (with appropriate flags to request the AD bit).
2. Check the AD (Authenticated Data) flag in DNS responses. The AD bit is set by a validating resolver when the response was DNSSEC-verified.
3. Default to **fail closed**: a response without AD bit set is treated as untrusted. Connection attempts to such names fail with a clear error.
4. Allow per-host opt-out for names known to be in non-DNSSEC zones (configuration, not negotiation).

The reason for fail-closed defaults: a configurable default that ships open is what made HTTPS take 20 years to be the norm. mssh starts strict; deployments that need to operate over non-DNSSEC names explicitly say so per name.

### Configuration

```
# sshd_config or mssh_config

RequireDnssec yes        # default

# Per-host exceptions
DnssecException legacy-isp-router.example.com
DnssecException *.legacy.example.net
```

`RequireDnssec no` is permitted but logged as a warning at startup, every time. Operators turning DNSSEC off should know they did it.

### Behavior when the resolver doesn't support AD

Some platforms' standard resolver APIs don't expose the AD bit. On those platforms, mssh has two options:

- Prefer using a known-good resolver via an alternative API (e.g., `getdns`, `libunbound`'s resolver-side API as a network call, not embedded).
- Fail closed: refuse to resolve names without the AD bit, and require operators to configure their resolver chain to provide it.

The recommended deployment is the former — install a DNSSEC-validating local stub resolver (systemd-resolved, dnsmasq with DNSSEC enabled, local unbound) so that AD bits propagate to applications. The latter is the fallback for hosts that cannot or will not configure their resolver, and effectively means "use IP addresses, not names" on those hosts.

## SSHFP records

[RFC 4255] defines SSHFP records: DNS records containing fingerprints of an SSH host's public key. When DNSSEC-validated, an SSHFP fingerprint is a trustworthy claim about which key a given hostname should be using.

In classic SSH, SSHFP is one of two ways out of the TOFU trap (the other being explicitly distributed `known_hosts` files). In mssh, SSHFP plays a different but related role: it cross-checks the server cert.

### How mssh uses SSHFP

When connecting to a host, the client:

1. Resolves the hostname (with DNSSEC, per above).
2. Fetches SSHFP records for the hostname (also DNSSEC-validated).
3. Negotiates the SSH connection and receives the server's cert.
4. Validates the cert chain (per `04-handshake-and-hop-chain.md`).
5. **Additionally**, computes the SHA-256 fingerprint of the cert's subject public key and looks for a matching SSHFP entry.
6. If an SSHFP entry matches: full confidence. Both the CA *and* the DNS administrator attest to this key.
7. If no SSHFP records present: cert is the sole authority. Connection proceeds.
8. If SSHFP records present but none match the cert's key: connection is refused. This is a strong signal that either the cert or the DNS has been tampered with; refusing to proceed is the safe response.

This makes SSHFP a defense-in-depth signal. An attacker who compromises the CA but not DNS gets caught by SSHFP mismatch. An attacker who compromises DNS but not the CA can't forge a cert chain.

### What about SSHFP record types?

SSHFP records have a key-type field (RSA, ECDSA, Ed25519, etc.) and a fingerprint-type field (SHA-1, SHA-256). mssh only honors SHA-256 fingerprints (SHA-1 SSHFP records are ignored). The key-type field is informational — the cert's actual public key drives the fingerprint computation, and the SSHFP record must match that fingerprint.

For a host that rotates its cert key without rotating DNS, SSHFP records must be updated in lockstep. Operators who use SSHFP commit to keeping it current; stale SSHFP causes hard connection failures. Some deployments will prefer to publish SSHFP records via automation (the CA, on each cert issuance, also pushes an updated SSHFP record to the authoritative DNS server).

## Hop chain and DNS

Each hop in a chain resolves the next hop's name. Each resolution is subject to the same DNSSEC rules. A non-DNSSEC name anywhere in the chain breaks the chain unless explicitly excepted.

This is intentional and slightly inconvenient: if any hop relies on a name in a non-DNSSEC zone, the operator must configure a `DnssecException` for it on every hop that uses it, and the deployment audit should flag this.

## What about `/etc/hosts`?

Names resolved via `/etc/hosts` (or platform equivalents) bypass DNS entirely and therefore bypass DNSSEC. mssh treats `/etc/hosts` entries as trusted because they are explicitly configured by the host administrator — the threat model presumes the local filesystem is not part of the adversary surface. Names resolved via `/etc/hosts` connect normally; no DNSSEC warning is issued.

This is a deliberate trust extension. An operator who wants to short-circuit the DNS path for a specific name can do so by editing `/etc/hosts`, and the connection will work. This is the same model classic SSH uses for `known_hosts` overrides.

## Edge cases

**IPv4-mapped names.** A name resolving to `A` and `AAAA` records may have only some validated. mssh requires all returned addresses for the connection-attempt set to be DNSSEC-validated; partial validation is treated as no validation.

**CNAME chains.** mssh follows CNAMEs; every link in the CNAME chain must be DNSSEC-validated for the final answer to count. A non-DNSSEC CNAME at any point invalidates.

**DNSSEC-aware caches.** Some resolvers cache the validation result; some validate on every query. mssh doesn't care; the AD bit on the response is what counts.

**DNS over HTTPS / DNS over TLS.** Orthogonal to DNSSEC. DoH/DoT defends the resolver→nameserver path against tampering; DNSSEC defends the entire chain back to the root. mssh cares only about the latter. Operators are encouraged to use DoH or DoT *additionally*; mssh neither requires nor forbids it.

## Why fail closed

The most common pushback on requiring DNSSEC is "my domain doesn't have DNSSEC and I can't enable it." This is increasingly rare — major registrars and DNS providers support DNSSEC, and zones that don't are typically legacy. mssh's stance is that the proper response is to enable DNSSEC, not to weaken the protocol.

The `DnssecException` mechanism exists for the cases where this is truly impossible (third-party-controlled domain, deprecated infrastructure, etc.). It works per-name, must be configured explicitly, and surfaces in operational visibility — a regular audit can list all `DnssecException` entries to keep them on the radar for eventual removal.

## What's deliberately out of scope

- **DANE for SSH.** RFC 6698 / RFC 7671 specify DANE TLSA records pinning TLS certs in DNS. The SSH equivalent (a TLSA-style record pinning a cert chain) is interesting but adds complexity for marginal gain over SSHFP + cert validation. Not in v1.
- **Negative caching of DNSSEC failures.** sshd does not maintain a cache of names that failed DNSSEC; each attempt is fresh. The system resolver may cache; that's its job.
- **Compatibility with non-DNS naming.** mDNS, NetBIOS, NBNS, and other LAN naming systems are out of scope. Use addresses or `/etc/hosts` for those.
