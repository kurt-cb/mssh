
## §0  Design status, numbering, and tracking

**This document is the FROZEN design for v1.** Once approved, sections below are immutable. Changes do not happen here — they happen by adding a new numbered section at the end, or by superseding an existing one in a new design revision document.

**Numbering scheme** (stable forever — used as `§X.Y.Z` references in code comments, commit messages, the features-todo doc, and the features-complete doc):

- `§N` — top-level chapters (this section is §0).
- `§N.M` — subsystems within a chapter.
- `§N.M.K` — named features within a subsystem.
- `§N.M.K.J` — detail items, when needed to be individually traceable.

Every section heading in this document is prefixed with its stable reference. **Never renumber.** If a section is dropped, leave its reference reserved and write "RESERVED — superseded by §X.Y" in its place.

**Companion documents** (NOT in this file — created separately after this plan is approved, in `/var/lib/totaldns/design/` or the repo root depending on environment):

- **`FEATURES-TODO.md`** — every unbuilt unit of work as a single row, columns `[ref, title, priority, status, branch, notes]`. `ref` is the §N.M.K from this doc. New items added only when this design admits a new §-reference.
- **`FEATURES-COMPLETE.md`** — same row shape, populated when a feature ships. `notes` includes commit hash + verification step (§ from this doc) that passed.

Every commit, PR title, and code comment that implements a piece of this design carries the relevant `§X.Y.Z` reference. Code without a design reference is treated as a bug.

**Priority labels** (P1–P9, attached to each subsystem § in chapter §5):

- **P1** — small + foundational + immediately rewarding. Build first.
- **P2** — small/medium + essential to the MVP demo.
- **P3** — medium + high user-visible value once the foundation works.
- **P4** — medium + needed for the peering story.
- **P5** — large or risky; defer once foundation is solid.
- **P6** — large + advanced; v0.0.5+.
- **P7** — large + niche or experimental.
- **P8** — security-critical but invasive; v1.0 hardening.
- **P9** — speculative / polish-only / future.

Priority is about *when to build*, not how important: a P8 (passkey-on-first-IP) may matter more than a P3, but is sequenced later because it's invasive and the rest of the system has to work first.

---