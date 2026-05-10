# Contributing to mssh

Thanks for your interest. This document describes how the project accepts contributions.

## Current phase

mssh is in **design phase**. The most valuable contributions right now are not code but design feedback. Specifically:

- Read the design documents. Find places where the rationale is thin, where decisions seem wrong, where the threat model has gaps. Open issues to discuss.
- Implement test cases against the protocol spec to find ambiguities. Open issues when the spec is unclear.
- Propose alternative designs for specific subsystems. Open discussions with rationale.
- Review the executive overview for accuracy and tone.

When implementation begins, the contribution model will expand to include code. This document will be updated then.

## How to engage

**Issues** for bug reports against the documentation, spec ambiguities, design questions, proposed changes, or anything else that would benefit from public discussion.

**Pull requests** for documentation improvements, fixes to spec wording, additional design considerations. Substantial changes should be preceded by an issue to ensure direction alignment.

**Discussions** (when enabled) for open-ended design conversations that aren't specific enough to be issues.

## Developer Certificate of Origin

All contributions must be signed off, indicating that you agree to the Developer Certificate of Origin (DCO):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Sign off your commits with `git commit -s`, which appends a `Signed-off-by: Name <email>` line.

No separate CLA is required. The DCO is sufficient.

## Code of conduct

Be a decent human. Disagree on the merits, not on the person. The maintainer reserves the right to moderate discussions that derail into incivility.

## Style

For documentation contributions:

- Sentence case in headings (not Title Case).
- One space after periods.
- Prefer Markdown's native syntax over HTML where possible.
- Code blocks use language tags (` ```go `, ` ```yaml `, etc.).
- Cross-references use relative links.
- New design documents go in `docs/design/` with a numeric prefix indicating reading order.
- Protocol spec changes require explicit rationale, ideally with backward-compatibility analysis.

## What I'm looking for in design feedback

The strongest critiques have shape like:

- "Section X says Y, but in deployment scenario Z, that fails because W. Consider instead..."
- "The threat model assumes A1, but A1 doesn't hold in environment B because..."
- "This design conflicts with C, which mssh otherwise depends on."
- "I implemented a partial X and the spec is ambiguous about Y."

The weakest critiques are:

- "Why not use blockchain / WebAuthn / Kerberos / [thing]?" without engaging with why mssh is structured as it is.
- "GPL would be better." (See `LICENSE-NOTE.md`; this decision was deliberate.)
- "This is too complex." (mssh aims to be smaller than the systems it replaces; specific complexity criticisms are welcome, vague ones less so.)

Concrete, specific, scenario-driven. That's what moves the design forward.

## Maintainers

This project is maintained by [@kurt-cb](https://github.com/kurt-cb) (Kurt Brorson). The initial design documents were developed in collaboration with Claude (Anthropic). Substantial contributions will be credited in commit history and, for design-influencing contributions, in the design documents themselves.
