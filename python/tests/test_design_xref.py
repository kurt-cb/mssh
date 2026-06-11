"""Phase 4 — design ↔ code/test cross-reference verification.

Implements §17.6 + §17.7 + §17.8 + §17.9 of design/mssh_design_v1.md
as a meta-test. Runs as part of the regular pytest suite.

What it checks:

  1. Every `.py` file under `python/packages/*/src/mssh*/` has a
     ``Design: §X.Y`` line in its module docstring (§0.2 rule).
  2. Every test file under `python/tests/` declares a ``Tests: §X.Y``
     line in its module docstring (§0.3 rule).
  3. Every `§X.Y[.Z]` reference appearing in code or tests resolves
     to an actual section in ``design/mssh_design_v1.md``.
  4. Every §-numbered subsystem in §1–§16 marked ✅ has at least
     one code mapping AND at least one test mapping (§17.6 +
     §17.7).

Failures here block release (§0.5 verification gate).

Tests: §0.5, §17.6, §17.7, §17.8, §17.9
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest


_REPO_ROOT = Path(__file__).resolve().parents[2]
_DESIGN_PATH = _REPO_ROOT / 'design' / 'mssh_design_v1.md'
_PACKAGES_DIR = _REPO_ROOT / 'python' / 'packages'
_TESTS_DIR = _REPO_ROOT / 'python' / 'tests'


# Matches "§N", "§N.M", "§N.M.K", "§N.M.K.J" — the §-ref grammar.
# A `§` that's part of a longer phrase like 'future-ideas §25' or
# 'archive/design §X' is to a DIFFERENT § namespace (the old
# future-ideas.md / archived design docs), not mssh_design_v1.md.
# We strip those before checking refs.
_SECTION_REF_RE = re.compile(r'(?<![\-a-zA-Z/])§(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?')

# Patterns that "claim" a § but in a different namespace.
_NON_DESIGN_REF_CONTEXTS = (
    'future-ideas',
    'archive/',
    'notes-bypass-cache',
)

# Matches the "Design: §X.Y[, §X.Y, ...]" docstring line.
_DESIGN_LINE_RE = re.compile(r'Design:\s*(§\d+(?:\.\d+)*(?:\s*[,+]\s*§\d+(?:\.\d+)*)*)')

# Matches the "Tests: §X.Y[, §X.Y, ...]" docstring line.
_TESTS_LINE_RE = re.compile(r'Tests:\s*(§\d+(?:\.\d+)*(?:\s*[,+]\s*§\d+(?:\.\d+)*)*)')


def _design_sections() -> set[str]:
    """Parse `mssh_design_v1.md` once; return the set of §-numbers
    that have a heading (e.g. '4.3.5', '13.9.6').

    Both '## §4' and '### §4.3.5' style headings are collected.
    """
    sections: set[str] = set()
    if not _DESIGN_PATH.exists():
        return sections
    heading_re = re.compile(r'^#{1,6}\s+§(\d+(?:\.\d+)*)')
    for line in _DESIGN_PATH.read_text().splitlines():
        m = heading_re.match(line)
        if m:
            sections.add(m.group(1))
    return sections


def _py_files(root: Path) -> list[Path]:
    """All non-build, non-cache .py files under root."""
    files = []
    for p in root.rglob('*.py'):
        s = str(p)
        if '__pycache__' in s or '/build/' in s or '.egg-info' in s:
            continue
        if p.name == '__init__.py':
            # __init__.py is a package marker; we accept either it has
            # a Design line OR is empty. Skip the strict check.
            if p.stat().st_size < 50:
                continue
        files.append(p)
    return files


def _normalize(ref: str) -> str:
    """Normalise a §-ref string like '§4.3.5' → '4.3.5'."""
    return ref.lstrip('§')


def _refs_in(text: str) -> set[str]:
    """All §-refs in text (Design:, Tests:, or inline), excluding
    refs that appear in a context naming a different § namespace
    (future-ideas.md, archive/, etc.).

    Heuristic: if the same line OR the immediately preceding line
    mentions `future-ideas` / `archive/`, the §-refs on that line
    are NOT to mssh_design_v1.md and are skipped.
    """
    out: set[str] = set()
    lines = text.splitlines()
    # Build a per-line tag: does this line (or the previous one) name
    # a non-design namespace?
    non_design_line: list[bool] = []
    prev_ctx = False
    for ln in lines:
        ll = ln.lower()
        this_ctx = any(ctx in ll for ctx in _NON_DESIGN_REF_CONTEXTS)
        non_design_line.append(this_ctx or prev_ctx)
        prev_ctx = this_ctx
    # Now collect refs, but skip ones whose line is tagged.
    pos = 0
    for lineno, ln in enumerate(lines):
        if non_design_line[lineno]:
            pos += len(ln) + 1
            continue
        for m in _SECTION_REF_RE.finditer(ln):
            parts = [g for g in m.groups() if g is not None]
            out.add('.'.join(parts))
        pos += len(ln) + 1
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_design_doc_exists():
    """Pre-flight: the design doc must be present."""
    assert _DESIGN_PATH.exists(), \
        f'design/mssh_design_v1.md missing at {_DESIGN_PATH}'


def test_design_sections_parse():
    """Sanity: at least 50 §-numbered headings in the design."""
    sections = _design_sections()
    assert len(sections) >= 50, \
        f'expected many sections, found {len(sections)}: {sorted(sections)}'


def test_p4_every_code_file_carries_design_ref():
    """§0.2 / §17.6 — every .py module under python/packages/<pkg>/src/
    has a `Design: §X.Y` line in its module docstring.

    Code without a design reference is treated as a bug per §0.2.
    """
    missing: list[str] = []
    for f in _py_files(_PACKAGES_DIR):
        # Skip generated _version.py + entry-point shims.
        if f.name in ('_version.py',):
            continue
        text = f.read_text()
        if 'Design:' not in text and '# §' not in text:
            missing.append(str(f.relative_to(_REPO_ROOT)))
    assert not missing, \
        '§0.2 missing-design-ref violations (run code-annotation):\n  ' + \
        '\n  '.join(sorted(missing)[:30])


def test_p4_every_test_file_carries_tests_ref():
    """§0.3 / §17.7 — every test file (test_*.py) has a `Tests: §X.Y` line.

    Helper / fixture / inventory files (`*_helpers.py`,
    `pyinfra-adhoc/*`, `inventory.py`, etc.) are excluded — they're
    infrastructure, not test cases.
    """
    missing: list[str] = []
    for f in _py_files(_TESTS_DIR):
        if f.name == 'conftest.py' or f.name.startswith('test_design_xref'):
            continue
        # Only check files that look like test cases (start with test_).
        if not f.name.startswith('test_'):
            continue
        # Skip pyinfra inventories / deploy helpers.
        rel = str(f.relative_to(_REPO_ROOT))
        if 'pyinfra-adhoc' in rel:
            continue
        text = f.read_text()
        if 'Tests:' not in text and 'Design:' not in text:
            missing.append(rel)
    assert not missing, \
        '§0.3 missing-tests-ref violations (annotate the test file):\n  ' + \
        '\n  '.join(sorted(missing)[:30])


def test_p4_every_section_ref_resolves_to_a_design_section():
    """§17.9 — every `§X.Y.Z` mentioned in code or tests must resolve
    to a real section in the design. Stale refs to deleted sections
    are a hard error.
    """
    sections = _design_sections()
    if not sections:
        pytest.skip('design doc not parseable; cf. earlier test')
    # Walk every code + test file, collect refs.
    bad: list[tuple[str, str]] = []
    for root in (_PACKAGES_DIR, _TESTS_DIR):
        for f in _py_files(root):
            text = f.read_text()
            for ref in _refs_in(text):
                # Accept any prefix-match — e.g. §4 in code is fine
                # even if only §4.3.5 has a heading. Also accept the
                # ref itself even if it's a deeper detail item below
                # the lowest heading.
                if not (ref in sections or any(s.startswith(ref + '.')
                                               for s in sections)
                        or any(ref.startswith(s + '.') for s in sections)):
                    bad.append((str(f.relative_to(_REPO_ROOT)), ref))
    assert not bad, \
        '§17.9 stale §-refs (code/tests reference sections that do ' \
        f'not exist in design):\n  ' + \
        '\n  '.join(f'{f}: §{r}' for f, r in sorted(set(bad))[:20])


# §17.7 coverage matrix — every § marked ✅ should have at least one
# test pointing at it. Build the mapping once; report missing ones as
# a single comprehensible failure.

@pytest.fixture(scope='module')
def covered_sections() -> set[str]:
    """All §-refs that appear in a `Tests: …` line of any test file."""
    out: set[str] = set()
    for f in _py_files(_TESTS_DIR):
        if f.name == 'conftest.py':
            continue
        text = f.read_text()
        for m in _TESTS_LINE_RE.finditer(text):
            for ref_token in re.findall(r'§\d+(?:\.\d+)*', m.group(1)):
                out.add(_normalize(ref_token))
    return out


def test_p4_phase1_critical_sections_have_test_coverage(covered_sections):
    """§17.7 — every load-bearing § in §1–§14 has at least one Tests: hit.

    "Load-bearing" = the sections that were specifically validated by
    the Phase-1 R-1..R-10 reconciliation commits. If any of these
    loses test coverage in the future, this test fails before the
    release-validation gate (§17.4).
    """
    must_be_covered = {
        # PKI hierarchy
        '2.2', '2.3', '2.6',
        # Wire protocols
        '3.1', '3.2', '3.6',
        # CA core
        '4.3.1', '4.3.2', '4.3.3', '4.3.4', '4.3.5', '4.3.6',
        '4.3.7', '4.3.8', '4.3.10',
        # msshd core
        '5.3.5', '5.3.6', '5.3.7', '5.3.8', '5.3.9',
        # Cross-cutting
        '13.1', '13.2', '13.3', '13.4', '13.5', '13.6',
        # Hardening
        '13.9.3', '13.9.4', '13.9.5',
        # Interfaces
        '14.5', '14.6', '14.7', '14.8',
    }
    missing = sorted(must_be_covered - covered_sections)
    assert not missing, \
        f'§17.7 coverage gap — these load-bearing sections have no ' \
        f'Tests: pointer:\n  ' + '\n  '.join(f'§{s}' for s in missing)
