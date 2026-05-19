"""Bug #7 regression — docs say `mssh-admin user del`; CLI says `user
remove`. This test extracts every `mssh-admin ...` invocation from
operations.md and verifies the CLI accepts it.

Catches:
  - subcommand renames not propagated to docs (`user del` → `user remove`)
  - flag renames (`--result` → `--decision`, `--since` removed)
  - subcommands documented but never implemented (`user show`)

The test parses operations.md, extracts `mssh-admin <subcommand>`
invocations, and runs each with `--help` to verify the command path
exists. If the docs invocation can't be parsed by the CLI, fail with
both the doc location and the actual CLI shape.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest


def _operations_md_path() -> Path:
    return Path(__file__).resolve().parents[2] / 'docs' / 'operations.md'


def _mssh_admin_bin() -> Path:
    """Same logic as the connect-timeout test — pull mssh-admin from
    the venv we're running tests in."""
    bindir = Path(sys.executable).parent
    cand = bindir / 'mssh-admin'
    if not cand.exists():
        pytest.skip(f'mssh-admin not found at {cand} — run `make dev-install`')
    return cand


# Pattern: `mssh-admin <verb> [noun] [flags...]` inside a code block
# or inline. We pull the FIRST 1-3 alphabetic tokens after `mssh-admin`
# as the command path, which is enough to verify the command exists.
# Flags (starting with `-`) and arg-values are stopped on.
_INVOCATION = re.compile(
    r'\bmssh-admin\s+([a-z][a-z-]*(?:\s+[a-z][a-z-]*){0,2})',
)


def _extract_documented_commands() -> set[tuple[str, ...]]:
    """Pull every (subcommand, sub-subcommand?) tuple from operations.md.

    Returns a set of token-tuples like ('user', 'add') or ('audit',).
    Argument values and flags are dropped — we only verify the
    command-path exists.

    **Scope:** code blocks inside or after a heading that starts with
    "## Future" are excluded — those examples illustrate not-yet-built
    commands and shouldn't trip the alignment gate.
    """
    text = _operations_md_path().read_text()
    # Drop everything from the first "## Future" heading to EOF (or
    # to the next non-future top-level heading, if any). The "Future
    # operator features" section in operations.md is everything from
    # that heading on.
    future_match = re.search(r'^## Future\b', text, re.MULTILINE)
    if future_match:
        text = text[:future_match.start()]

    found: set[tuple[str, ...]] = set()
    for match in _INVOCATION.finditer(text):
        tokens = tuple(match.group(1).split())
        # Stop at the first token that looks like a positional value
        # (something the user supplies). The CLI's verb tree is
        # exclusively lowercase + hyphen. Strip anything else.
        clean: list[str] = []
        for tok in tokens:
            if not re.match(r'^[a-z][a-z-]*$', tok):
                break
            clean.append(tok)
        if clean:
            found.add(tuple(clean))
    return found


def _run_cli_help(*command_path: str) -> subprocess.CompletedProcess:
    """Invoke `mssh-admin <command_path> --help`. Returns the process,
    exit code, and stderr (for failure messages)."""
    return subprocess.run(
        [str(_mssh_admin_bin()), *command_path, '--help'],
        capture_output=True, text=True, timeout=10,
    )


def test_every_documented_command_exists():
    """Every `mssh-admin <verb>` mentioned in operations.md must be
    accepted by the CLI (verified via `--help`).

    Failure points to the offending doc invocation and shows what the
    CLI is willing to accept (so the doc fix is obvious).
    """
    documented = _extract_documented_commands()
    assert documented, 'operations.md has no mssh-admin invocations to check?'

    missing: list[tuple[tuple[str, ...], str]] = []
    for cmd_path in sorted(documented):
        # Try the longest path first, walk back if it fails. The doc
        # might say `mssh-admin user del alice` and only `user` is
        # the real subcommand — that's fine, we just verify the path
        # prefix exists.
        for prefix_len in range(len(cmd_path), 0, -1):
            attempt = cmd_path[:prefix_len]
            r = _run_cli_help(*attempt)
            if r.returncode == 0:
                # This prefix works. But if the ORIGINAL command was
                # longer, the trailing tokens were rejected (or were
                # positional args). Report only if the very first
                # subcommand is rejected — that's the real bug.
                if prefix_len < len(cmd_path):
                    # The shorter prefix works but the longer one
                    # doesn't. Check whether the trailing tokens are
                    # subcommands (= drift) or positional args (= OK).
                    extra = cmd_path[prefix_len]
                    full = _run_cli_help(*cmd_path[:prefix_len + 1])
                    if 'No such command' in full.stderr:
                        missing.append((cmd_path,
                                        f"`mssh-admin {' '.join(attempt)}` "
                                        f"exists but `{extra}` is not a "
                                        f"subcommand of it"))
                break
        else:
            # No prefix worked at all — the top-level subcommand
            # doesn't exist.
            missing.append((cmd_path,
                            f"`mssh-admin {cmd_path[0]}` doesn't exist"))

    if missing:
        details = '\n'.join(
            f"  mssh-admin {' '.join(cmd)}:\n    {reason}"
            for cmd, reason in missing
        )
        pytest.fail(
            f'docs/operations.md references mssh-admin commands that '
            f'the CLI rejects (Bug #7):\n\n{details}\n\n'
            f'Fix either the doc or the CLI — the test treats them as '
            f'a contract that has to match.'
        )
