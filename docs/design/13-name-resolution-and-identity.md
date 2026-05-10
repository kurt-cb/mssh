# 13. Name Resolution and Identity Binding

In classic SSH, the question "how did I find this host?" is load-bearing for security. The host-key TOFU model relies on the user encountering the same host through the same name over time. Reaching a host by a different name (an alias, an IP literal, a `/etc/hosts` entry) means a different cached host key, or no cached key at all, and the user is left to make a trust decision they aren't equipped to make.

This is why classic SSH usage guides discourage non-DNS host references. It isn't that names from `/etc/hosts` are inherently insecure — it's that TOFU compounds the weakness of any informal resolution path. The recommendation is "use DNS, use DNSSEC, distribute `known_hosts` carefully," and most operators give up halfway and click through warnings.

mssh removes TOFU. Host identity comes from a cert that the host presents at connection time, validated against a CA-anchored trust root. Once the trust model no longer depends on the user remembering which key matched which alias, **the question of how the user found the host becomes orthogonal to the security guarantee**. What matters is whether the cert claims the identity the user typed.

This document defines how that works concretely.

## The four resolution paths

A user reaches a host through one of four paths:

1. **DNSSEC-validated DNS name.** The user types `webserver1.prod.example.com`; the resolver returns an answer with the AD bit set; the connection proceeds to the resulting address.
2. **`/etc/hosts` or platform equivalent.** The user types `webserver1`; the local stub resolver returns an answer from `/etc/hosts` without going to the network.
3. **Direct IP literal.** The user types `ssh 10.0.1.50` or `ssh [2001:db8::1]`. No name resolution involved.
4. **Non-DNS local name systems.** mDNS (`webserver1.local`), NetBIOS, WINS, Tailscale's MagicDNS, Consul DNS, k8s cluster DNS, etc. The user types a name that gets resolved by some non-DNS-but-not-/etc/hosts mechanism.

The mssh design treats all four uniformly: **the cert must bind to whatever the user typed.** No path is privileged; no path is forbidden; the cert is the authority either way.

## What the cert needs to say

For each resolution path, the cert needs the appropriate name binding:

| Path                    | Required cert binding                              |
|-------------------------|----------------------------------------------------|
| DNSSEC DNS name         | `CN` matches name, or SAN `dNSName` matches        |
| `/etc/hosts` name       | Same — `CN` or SAN `dNSName` matches the local name |
| Direct IP literal       | SAN `iPAddress` matches the literal address        |
| mDNS, etc. local name   | SAN `dNSName` matches the local name               |

X.509 Subject Alternative Names support both `dNSName` and `iPAddress` entries [RFC5280]. A cert can carry multiple SANs, so one cert can simultaneously bind to:

- `CN=webserver1.prod.example.com`
- SAN `dNSName: webserver1.prod.example.com`
- SAN `dNSName: webserver1`
- SAN `dNSName: webserver1.local`
- SAN `iPAddress: 10.0.1.50`
- SAN `iPAddress: 2001:db8::1`

A host with this cert validates correctly via any of those names or addresses. The CA decides what to include based on operator intent at issuance time. There's no protocol-level wildcard mode that "accepts any name" — every name must be explicitly claimed by the cert.

This means an operator deploying mssh to a fleet decides up front: how will users address these hosts? FQDN only? Short names too? IP literals? Each answer turns into a cert field. Once issued, the cert is the authoritative answer to "what is this host called?"

## Why this is stronger than classic SSH for non-DNS hosts

Take the example you raised: a host that lives on the network but isn't in DNS. In classic SSH:

- User adds it to `/etc/hosts` as `myrouter` → `192.168.1.1`.
- First connection: host key TOFU. User sees `The authenticity of host 'myrouter (192.168.1.1)' can't be established. Are you sure you want to continue connecting (yes/no)?` They type yes. The key is cached against `myrouter`.
- An attacker on the LAN ARP-spoofs `192.168.1.1`. Next connection: the TOFU'd key doesn't match. SSH warns. User clicks through or curses and re-checks.
- Attacker who's clever enough to get the legitimate host key (extracted from a similar device) presents that key and isn't caught.

In mssh:

- Operator issues `myrouter`'s cert with `CN=myrouter`, SAN `dNSName: myrouter`, SAN `iPAddress: 192.168.1.1`.
- User adds `myrouter` to `/etc/hosts` exactly as before.
- First connection: client resolves `myrouter` to `192.168.1.1` via `/etc/hosts`. Connects. Server presents cert. Client validates cert chain to the configured trust root and checks that `myrouter` matches the cert's `CN` or SAN. Pass: connection proceeds with full assurance.
- ARP-spoofing attacker: presents some cert. Either the cert doesn't chain to the trust root (rejected), or it does but doesn't claim `myrouter` (rejected). The attacker can't forge a valid cert without the CA.
- Attacker with a similar device's cert: the cert claims a different name; the user typed `myrouter`; mismatch; rejected.

The security is stronger, and the user experience is the same — type the name, get connected, no prompts.

The "discouragement" of non-DNS naming in the classic SSH world is downstream of TOFU. With cert-based identity, the discouragement doesn't apply. An operator can run hosts that are entirely outside DNS, accessed only by short name or IP, with security equivalent to (in fact better than) DNSSEC-validated DNS names.

## What about DNSSEC?

The role of DNSSEC shifts. In `10-dnssec-and-sshfp.md` it's framed as defending the name resolution path against tampering. That framing is still correct but secondary in importance:

- DNSSEC ensures that *if* you resolved a name via DNS, the answer wasn't tampered. The cert then provides the identity assurance independently.
- For non-DNS resolution paths, DNSSEC isn't relevant. `/etc/hosts` is admin-controlled; direct IP is direct; mDNS has its own integrity model (or lack of one). The cert handles identity in all cases.

**The fail-closed-on-non-AD default applies only to DNS resolution.** If a name was resolved via DNS and came back without AD, that resolution is suspect — fail. If a name was resolved via `/etc/hosts` (no DNS query happened), there's nothing for DNSSEC to validate; proceed. If a literal IP was typed, no resolution happened; proceed.

This needs to be precisely encoded in implementations:

- The resolver wrapper returns both the address and the *source* of the resolution: `dns-validated`, `dns-unvalidated`, `etc-hosts`, `mdns`, `literal`, `configured-override`.
- The mssh client applies DNSSEC policy only to `dns-unvalidated` (refuse unless excepted).
- The mssh client applies cert name-binding to all sources uniformly — the cert must claim the name or address used.

## Configuration for non-DNS resolution

For mDNS and similar systems, an explicit configuration directive is required:

```
# Permit mDNS resolution for *.local names
NonDnsResolution mdns *.local
NonDnsResolution mdns *.lan

# Permit Tailscale MagicDNS resolution for *.ts.net
NonDnsResolution custom tailscale-magic *.ts.net resolver=100.100.100.100

# Permit Consul DNS resolution
NonDnsResolution custom consul *.service.consul *.node.consul resolver=127.0.0.1:8600
```

Without an explicit `NonDnsResolution` entry, names that don't resolve via the standard DNSSEC-aware resolver fail. This is the safe default — operators decide which alternate resolution mechanisms they trust enough to use.

`/etc/hosts` is always permitted (it's part of the standard resolver chain on every OS and is admin-controlled).

Direct IP literals are always permitted at the client level; the cert validation then determines whether the connection succeeds.

## Machine-to-machine connections

A common operational case: machines connecting to other machines for automated tasks (backups, monitoring, config push). These connections often use IP literals or short names because the script was written years ago and nobody wants to touch it.

In classic SSH this is a security awkwardness — machine accounts with long-lived keys, host-key prompts disabled, scripts that ignore warnings. The "right" way involves bastion hosts, ssh-agent forwarding with careful scoping, and someone remembering to rotate keys.

In mssh, machine-to-machine is straightforward:

- The initiating machine has its own cert (issued via the CA, with appropriate `mssh-channel-policy` if it needs channels and `mssh-source-bind` to its own IP range).
- The target machine has a cert claiming whatever name or IP the initiator will use.
- The script connects normally. Both sides authenticate via cert. No TOFU, no agent forwarding gymnastics, no manual key distribution.

For machines that talk to each other constantly, the certs can be longer-lived than user certs (the `machine` identity type permits validity up to 30 days, `domain` up to 90 days). For sensitive automated paths, shorter validity and more frequent rotation are appropriate; the embedded CA can be configured to issue these automatically.

The "machine knows the user knows the way" point applies here: a script that has historically reached a target by IP literal continues to work, because the target's cert claims that IP. A script that has historically used a short name from `/etc/hosts` continues to work, because the target's cert claims that name. The script doesn't need to be rewritten when migrating from classic SSH to mssh — the cert just needs to claim what the script types.

## Pre-resolved address handling

A subtle case: what if the resolved address itself contains validation evidence?

Example: a Kubernetes cluster's internal DNS resolves a pod name to a stable IP. The pod's mssh cert claims the pod name (`my-pod.my-namespace.svc.cluster.local`) but not the IP (because pod IPs are ephemeral and unpredictable). Client connects, names the pod, resolves to a current IP via k8s DNS, connects, server presents cert. Client validates the cert against the *name*, not the IP. The IP is just the route; the name is the identity.

This is the standard pattern and what TLS does everywhere. mssh follows it. The connection is established to whatever IP the resolver returned; the cert is validated against the name the user (or script) used. The cert claims the name; the IP is incidental.

mssh implementations MUST validate the cert against the original name (or IP literal) the user supplied, not against the IP returned from resolution. The IP is for routing; the name is for identity.

## Edge cases

**Multiple names, one cert.** A host that needs to be reachable by FQDN, short name, and IP literal has all three in its cert. No protocol-level limit on the number of SAN entries (cert size limit caps the practical maximum at a few hundred).

**Name collisions across naming systems.** If `foo` is both a `/etc/hosts` entry and a DNS name pointing to different hosts, the standard resolver-chain order applies: `/etc/hosts` wins on most systems. The cert presented is whichever host actually answers; if its cert doesn't claim `foo`, the connection fails. This is the right behavior — the user typed `foo`, the cert must say `foo`.

**Wildcard SANs.** X.509 permits wildcard SANs (`*.example.com`). mssh permits these for `domain`-type certs but not for `machine`-type. A user typing `subdomain.example.com` connecting to a host with `*.example.com` cert: connection succeeds, identity-type is `domain`. This is suitable for shared-fleet scenarios where many hosts share a cert.

**IP literals in URLs and command-line args.** The mssh client parser must recognize that `ssh 10.0.1.50` is using a literal, and `ssh [2001:db8::1]:2222` is using an IPv6 literal with a port. The resolver returns the literal unchanged, source `literal`, no DNS query made. Cert validation requires SAN `iPAddress` match.

## Implications for the protocol spec

The protocol doesn't itself constrain how clients resolve names — that's a client concern. What the protocol does:

1. Specifies cert validation against the connection target identifier (name or IP) the client used.
2. Permits `iPAddress` SANs as a first-class identity binding.
3. Requires implementations to honor SAN `dNSName` for any name source, not just DNS.

These are noted in `04-handshake-and-hop-chain.md` Section "Mutual authentication" and in the protocol spec's Section 4.3. Nothing more is needed at the wire level — the cert format already supports this.

## What this gives you

The user typing `ssh whatever-they-remember` works. The script connecting to whatever IP it knows works. The host that isn't in DNS works. The machine that's only known by an internal alias works. All of these, with full security, no prompts, no warnings, no exceptions to maintain.

The cost is operational: the CA has to know what names each host should claim, and certs have to be issued with the right SANs. This is a real cost — operators have to decide naming up front rather than relying on whatever the client happens to type. But it's a one-time decision per host (or per host class via the `domain` identity type), and it replaces a permanent ongoing burden of TOFU management.
