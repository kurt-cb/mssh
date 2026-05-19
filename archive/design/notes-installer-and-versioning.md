<!-- archived from design/notes-installer-and-versioning.md — captures work that has LANDED. -->

**Status:** LANDED. This note describes a design decision whose
implementation is now in the codebase. Kept verbatim for the
rationale + historical context.

---

# Notes — installer, packaging, versioning

A design observation that surfaced during the round-1/round-2 adhoc
testing of 2026-05-18 / 2026-05-19, and that turned out to explain a
disproportionate share of the bugs found.

## The observation

The adhoc lab provisioned containers by **mounting the repo source
tree** at `/app/src` and running the components via
`PYTHONPATH=/app/src python3 -m mssh.<module>`. That bypassed the
install path that real users hit (`apt install` / `pip install` /
`install_mssh.sh`). Concretely:

- No package metadata. No version stamp. No upgrade transition.
- No postinst hooks. No file-permission validation.
- Two source files in the repo can drift silently and the lab still
  works because they're both mounted from the same tree.
- "Patch and restart" — `lxc file push` then `systemctl restart` —
  became the iteration reflex. It works during debugging but isn't
  what a user does after the bug is fixed.

## How this filtered into the bug list

Round-2 cataloged six new findings. Three were directly downstream of
the missing install path:

- **Bug #7** — docs reference `mssh-admin del`, `mssh-admin server show`,
  etc., but the CLI uses `remove` / has no `show`. Plus the
  `mssh-admin` binary wasn't installed at all (only a Python module).
  An install path that builds a distributable binary catches this at
  release time.

- **Bug #8** — two divergent sshd_config templates lived in two
  separate places (`config/sshd_config.template` and the CA's
  `BUILTIN_OPENSSH_TEMPLATE`) and silently diverged on one critical
  algorithm directive. Per-connection mode was broken from the day it
  landed; the flip script's verify-and-revert silently swept it under
  the rug. A real release flow would have run a smoke test exercising
  both modes before tagging the version. Today's flow doesn't.

- **The `__pycache__` gotcha** (took ~10 min in round 2 to debug):
  `lxc file push` overwrote a `.py` but Python loaded the stale
  `.pyc`. This is *only* a problem because we patch into a running
  install. An apt-style postinst would `rm -rf __pycache__` (or
  install bytecode-free).

The other 3 round-2 findings (#5 encoding, #10 CRL on deny, #11 banner)
are genuine code bugs that would exist in any deployment shape.

## The meta-finding

> We don't really have an installer or versioning.

That's the entire framing. Once we say it out loud, a lot of
collateral observations make sense:

- Hot-patching during debug is fine. **Hot-patching to validate a
  fix is not** — you're not testing the path the user will hit.
- The "real-world" install boundary surfaces *install-time* bugs
  (paths, perms, config templates, dependency mismatches, etc.) that
  patch-and-restart hides.
- A 10-minute lab spin-up is partly *because* there's no installer
  to do it faster (rebuilding pip env, fetching apt deps, generating
  certs). A real packaging path collapses the install phase to
  seconds.

## What landed in v0.1.0

In response, v0.1.0 ships:

### Multi-package layout

Five packages, single source-of-truth versioned by setuptools_scm:

| Package | Ships | Depends on |
|---|---|---|
| `mssh-common` | `mssh.identity`, `mssh.shim`, `mssh.akc_shim`, `mssh._protocol`, `mssh._version` | (only external) |
| `mssh` | `mssh.client` | `mssh-common` |
| `msshd` | `mssh.msshd`, `mssh.debug_sshd` | `mssh-common` |
| `mssh-ca` | `mssh.ca` | `mssh-common` |
| `mssh-admin` | `mssh.admin`, `mssh.mcp` (extra) | `mssh-common`, `mssh-ca` |

PEP 420 namespace packages: there is no `mssh/__init__.py` anywhere;
the four binary wheels each contribute their submodule to the
`mssh.` namespace.

### Versioning via git tags

`setuptools_scm` reads the latest annotated tag (`v0.1.0`) and stamps
all 5 wheels with the same version. Dirty trees get a suffix
(`0.1.0.dev3+gabc123.d20260519`). The version is written into
`mssh/_version.py` at build time; runtime code reads it via
`from mssh._version import __version__`.

### Top-level Makefile

```
make pkg            # builds 5 wheels into dist/
make dev-install    # pip install -e all 5 packages into .venv
make redeploy       # push fresh wheels to a running lab, restart
make clean
```

### Adhoc lab installs from wheels

`tests/lxc/lxc_helpers.install_wheels()` replaces the old
`push_source()`. Per container: build wheels (`make pkg`), `lxc file
push` them, `pip install` them, restart services pointing at the
installed binaries (`/usr/local/bin/msshd`, `/usr/local/bin/mssh-ca`,
etc.). No `PYTHONPATH` overrides anywhere.

The lab now exercises the same install path a real user will. That
catches install-time issues (file paths, permission, dependency
resolution, PEP 668 marker handling) at lab-provision time rather
than letting them slip through to production.

## What still needs to happen

The user-visible install story is still **pip wheels** today, not
**apt/.deb**. The next step is `install_mssh.sh` (future-ideas §15)
followed by real `.deb` packaging (future-ideas §16). Each tier
forces another round of "what does install actually look like" — the
same exercise that v0.1.0 walked through, at a different level.

### Open questions to revisit

1. **PyPI namespace.** The PyPI name `mssh` is taken by an unrelated
   package (0.3.3 there is some SQL tool). We currently install
   wheels by file path to avoid the collision, but if we ever
   publish to PyPI we need a different distribution name (perhaps
   `mssh-cli` while keeping the Python import name `mssh`).

2. **Per-container install subsets.** Today `install_wheels()`
   installs ALL 5 wheels on every container. In production:
   - Workstation: `mssh` only
   - Server: `msshd` + `mssh-common`
   - CA host: `mssh-ca` + `mssh-admin` + `mssh-common`
   The lab could split this to test the minimum-install paths
   directly, but for v0.1.0 simplicity wins.

3. **Where do `config/sshd_config.template` and similar non-Python
   artifacts live in a packaged install?** Today they're at the repo
   root and `install_wheels()` tars them to `/app/config/`. A real
   `apt install mssh-server` would put them at `/usr/share/mssh/` or
   `/etc/mssh/`. The code that reads them
   (`mssh.msshd.inner._template_path()`) already searches multiple
   candidate locations — good — but the lab still uses `/app/config/`.

4. **`mssh-admin` binary deployment.** The round-2 finding was that
   `mssh-admin` was documented but never installed. With v0.1.0's
   wheel install, it's a normal binary. But: in production we may
   not want to install `mssh-ca` (and therefore `mssh-admin`'s
   dependency on `bootstrap_ca`) on operator workstations that
   don't bootstrap the CA. `bootstrap_ca` belongs in `mssh-admin`,
   not in `mssh-ca`, eventually.

5. **Cross-distro install matrix.** Today the lab tests Ubuntu 22.04 +
   Alpine 3.21. The install path needs to work on:
   - Ubuntu 22.04 (pip 22, no PEP 668)
   - Ubuntu 24.04 (pip 24, PEP 668)
   - Debian 12, RHEL 9
   - Alpine 3.19+

   `install_wheels()` handles the PEP 668 marker; the rest is
   untested. Tier-2 of the static-test plan should grow per-distro
   smoke tests.

## Why this matters more than the typical "yes we'll get to packaging"

Without an installer, **every adhoc-test session is partially
testing the dev workflow, not the user experience**. The bug class
"works for the developer but is broken in install" is invisible.
v0.1.0's restructure removes that blind spot. Subsequent rounds of
adhoc testing will produce a higher signal-to-noise ratio per
finding.

And from the user's framing during the discussion:

> The biggest problem with Python is configuration issues. pycache,
> pip changes, dependent libraries, constantly changing APIs. But
> the patching idea is not a real use case. It's a debugging thing.

Right. The fix is to stop debugging through the patching path AS IF
it were the user path. v0.1.0 enforces that distinction.
