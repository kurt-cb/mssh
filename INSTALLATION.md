# mssh — installation

Quick pointer file. For the full operator workflow (install, enrol,
adopt, troubleshoot) see [docs/operations.md](docs/operations.md).

## Quick install

```bash
git clone https://github.com/kurt-cb/ssh-rt-auth.git
cd mssh
python3 -m venv .venv
make dev-install
```

This installs the 6 mssh wheels editable into `.venv` and adds the
following binaries to `.venv/bin/`:

  - `mssh` — the client
  - `msshd` — server-side gateway daemon
  - `mssh-ca` — CA service
  - `mssh-admin` — operator CLI
  - `mssh-passkey` — WebAuthn broker (optional; see [design/mssh-passkey-module.md](design/mssh-passkey-module.md))
  - `mssh-debug-sshd`, `msshd-admin` — diagnostics
  - `mssh-mcp` (optional `[mcp]` extra) — admin API over MCP for
    LLM clients
  - `msshd-admin-web` (optional `[web]` extra) — Flask + Bootstrap 5
    admin portal; see [docs/operations.md § browse from a web UI](docs/operations.md#browse-the-deployment-from-a-web-ui-msshd-admin-web)

For an air-gapped server install via pre-built wheel tarball, see
`scripts/install_mssh.sh` (run `make tarball` to produce the input).

## Bootstrap a CA

```bash
mssh-admin init --ca-dir /etc/mssh-ca
mssh-ca --config /etc/mssh-ca/ca-config.yaml
```

See [docs/operations.md § bootstrap a CA](docs/operations.md#bootstrap-a-ca)
for the full sequence including admin cert custody, where each key
file lives, and the trust hierarchies you should keep separate.

## Try the adhoc lab first

```bash
cd python && ./setup_adhoc.sh
# Source ./adhoc-env.sh in the resulting shell, then:
#   mssh_as alice acct whoami
#   flip_to_fallback / flip_to_enforce
```

Five LXC containers, full Phase-0→Phase-2 adoption journey in
~10–15 minutes (first run prebakes images; subsequent runs faster).
Read [docs/operations.md § adoption journey](docs/operations.md#the-adoption-journey)
for what the three modes mean and why we structure migrations
around them.

For step-by-step walkthroughs against the lab:
  - [docs/TUTORIAL_USER_MANAGEMENT.md](docs/TUTORIAL_USER_MANAGEMENT.md) — day-in-the-life operator
    view, starting from a prebuilt Phase-2 lab.
  - [docs/TUTORIAL_MIGRATION.md](docs/TUTORIAL_MIGRATION.md) —
    walks Phase 0 → 1 → 2 against the lab, matching the production
    migration sequence step-for-step.

## Migrating an existing fleet

For a step-by-step operator playbook (CA setup → msshd in
fallback → user enrollment → flip to enforce → decommission
legacy ssh), see [docs/MIGRATION.md](docs/MIGRATION.md).

## Distro packages

Not yet. `apt install mssh msshd` is on the roadmap; see
[design/future-ideas.md § distro packaging](design/future-ideas.md).
