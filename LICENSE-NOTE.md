# A note on the license

This project is licensed under Apache 2.0. The protocol specification documents (`docs/spec/`) and design documents (`docs/design/`) are intended for use under CC-BY-4.0 to encourage independent implementations, though as of this initial drop the whole repository is Apache 2.0 by default.

This is a documented decision rather than a default. If you're an early collaborator or considering contributing, you should know why.

## Why Apache 2.0 and not GPL

The original instinct for this project was GPL, with the reasoning that copyleft "forces contribution" — vendors who modify the code must release their modifications, so the project benefits. This is the standard copyleft argument and it has worked well for projects like the Linux kernel and BusyBox.

The argument applies poorly here for several reasons:

**The competition is permissively licensed.** OpenSSH is BSD/ISC. Dropbear is MIT. libssh is LGPL but with a permissive option. Anyone choosing between mssh and the alternatives evaluates license fit, and for the embedded vendors, network appliance manufacturers, cloud platforms, and operating system distributions that ship SSH today, GPL is a non-starter. They would not adopt mssh under GPL terms — they would continue to ship OpenSSH. The "forced contribution" mechanism only works if the vendor is forced to use the code in the first place. With a permissive alternative right there, no one is forced.

**SSH lives where GPL cannot follow.** A meaningful design goal of mssh is to be deployable on embedded systems, in router firmware, in IoT devices, in initramfs recovery shells. These environments use Dropbear specifically because Dropbear is permissively licensed — vendors will not ship GPL code in firmware they distribute. A GPL mssh would be locked out of the same environments classic SSH thrives in, which would undermine one of the project's reasons for existing.

**Protocol adoption matters more than implementation adoption.** The biggest leverage this project has is in influencing the SSH protocol — getting other SSH implementations (OpenSSH, Dropbear, libssh, PuTTY, commercial SSH) to adopt the cert-first model. Protocol adoption happens when the spec is freely usable and reference implementations are easy to study. GPL discourages both: BSD ecosystems are cautious about reading GPL code for fear of contamination, embedded vendors cannot use it, and most commercial implementations have policies against GPL. Apache 2.0 — used by Kubernetes, Vault, Consul, the Tailscale OSS components, mbedTLS, and most modern infrastructure projects — is the standard for permissively-licensed infrastructure software and removes these barriers.

**Patent grant.** Apache 2.0 has an explicit patent grant; BSD/MIT/ISC do not. For a security protocol, this matters: contributors implicitly license any patents they hold to users of the work. This protects everyone — contributors cannot later assert patents against users of their own contributions, and users have clearer confidence in the IP situation. This is a meaningful advantage of Apache 2.0 over the simpler BSD/MIT options.

**The contribution model that works for infrastructure crypto.** Look at where contributions come from for OpenSSH, WireGuard, the Signal protocol, mbedTLS, BearSSL. They come from grants (NLnet, OTF, governments), corporate sponsorships, and engineers contributing on their employer's time because their employer benefits from the work. None of this requires GPL. Permissive licensing has produced flourishing contribution ecosystems for the security infrastructure that matters most.

## What "forces contribution" looks like without copyleft

If the project goal is to encourage contributions back rather than to extract them by force, the practical mechanisms are:

- **A clear contribution model.** `CONTRIBUTING.md` describes what's welcome and how to submit it.
- **A Developer Certificate of Origin (DCO).** `Signed-off-by` lines on every commit, asserting that the contributor has the right to submit under the project license. Lightweight, doesn't require a CLA.
- **An open, responsive maintainer community.** Pull requests get reviewed. Issues get answered. Contributors feel their work matters.
- **Public roadmap and discussion.** Decisions happen in the open. The project's direction is legible.

These produce sustained contribution flow from people who want to contribute. They produce nothing from people who don't, which is the right answer — coerced contributions are low quality anyway.

## On forking OpenSSH

A separate question that came up: whether to fork OpenSSH as a starting point rather than write a new implementation.

Legally, BSD-to-Apache is a one-way street that's permitted. The BSD license requires preserving the original copyright notices on existing files; new files can be Apache 2.0; the combined work as distributed is effectively Apache. The OpenSSH project will not pull mssh's changes back into upstream (their policy is BSD-only), but you don't need them to — you'd be maintaining a fork.

Practically, an OpenSSH fork inherits decades of platform porting work, SFTP, scp, agent, channel multiplexing, pty handling — useful, well-tested code. It also inherits a large C codebase with conventions and structure that don't match what an mssh implementation needs. The protocol changes thread through many files; merging upstream becomes harder over time; the patch surface is large.

The alternative — a clean-room implementation in Go or Rust — is more work up front but produces a smaller, more auditable codebase with no legacy baggage. For an initial proof of concept, the clean-room approach is likely better. For production deployment at scale, an OpenSSH fork may make sense as a follow-on project (or someone else may do it).

Either path is compatible with Apache 2.0.

## If you disagree

If after reading this you still want this project under GPL, fork it. Apache 2.0 → GPL is also a one-way street that's permitted; you can take the Apache code and re-release your derivative under GPL. The original project stays Apache, the GPL fork has its own community and goals. This is fine; the licenses exist to make this possible.

But the case for the original project being permissively licensed is, I think, strong enough that the burden is on the GPL argument, not the other way around.

## Documentation license

The protocol specification and design documents may eventually be re-licensed under CC-BY-4.0 to encourage independent implementations. As of this initial drop, they're under Apache 2.0 along with everything else (Apache 2.0 covers documentation fine — but CC-BY is the convention for protocol specifications and is more obviously the right tool). This is a future cleanup item; flag it if you have an opinion on the timing.
