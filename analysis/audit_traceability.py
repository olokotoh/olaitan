"""Traceability matrix audit (Story 6.9, NFR42 final state, code-auditable portion).

The audit is the machine-checked half of the no-lies rule: it reads the
``## Matrix`` table in ``docs/traceability.md`` and verifies that every row's
``code_package``, ``test_files``, and ``test_ids`` point at EXTANT artefacts in
this tree, and that the matrix is internally self-consistent (unique claim
slugs, the claim_id chapter/section prefix agreeing with ``ch3_section``). It
exits non-zero on any such drift so CI prevents the matrix from drifting away
from the code between chapter freeze and submission.

Two columns are intentionally NOT hard-gated here, for honest reasons recorded
in the Story 6.9 Dev Notes:

* ``eval_run_ids`` is DEFERRED to the cluster phase (Stories 5.9/5.10): no
  cluster runs are committed yet, so an ``n/a`` / ``deferred`` / empty value is
  ALLOWED and reported as "pending cluster phase", never fabricated.
* The full Chapter 3 orphan cross-check (every ``## 3.x`` heading has a row and
  every ``ch3_section`` resolves to a real heading) needs the thesis chapter
  markdown, which lives only in the non-git specs repo and is ABSENT from this
  code repo / any CI checkout. So that cross-check runs only when the chapter
  file is locatable (``--chapter3 <path>`` or auto-discovery of
  ``report/chapter-3-methodology.md``) and is REPORTED, not gated; in CI it
  auto-skips. The in-repo self-consistency + the extant-artefact checks (the
  parts that actually catch a code-to-claim lie) ARE the always-on hard gate.

Usage::

    python analysis/audit_traceability.py
    python analysis/audit_traceability.py --matrix docs/traceability.md \
        --chapter3 ../final-year-project/report/chapter-3-methodology.md

Determinism: sorted iteration over rows / tokens / findings, no wall-clock in
the output, so the report is byte-stable across runs (the analysis-pipeline
discipline). Stdlib only: no third-party dependency is added to the analysis
toolchain.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

# The repo root is this file's parent's parent (analysis/ lives at the root), so
# a direct ``python analysis/audit_traceability.py`` resolves matrix/code paths
# relative to the repo root regardless of the caller's CWD. CI runs from the
# repo root already; a runbook invocation might not.
_REPO_ROOT = Path(__file__).resolve().parent.parent

# Extensions that mark a backticked token as a real file path even when it has
# no slash (a bare top-level file such as ``Makefile`` is handled separately by
# the no-extension known-file rule below).
_PATH_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".go",
        ".py",
        ".yaml",
        ".yml",
        ".json",
        ".md",
        ".tpl",
        ".sh",
        ".txt",
        ".jsonl",
        ".gitignore",
    }
)

# Bare (no extension, no slash) tokens that are nonetheless real repo files and
# so count as path-shaped. Kept explicit so an arbitrary capitalised word in
# prose is not mistaken for a path.
_BARE_FILE_TOKENS: frozenset[str] = frozenset({"Makefile", "NOTICE"})

# A dotted Go-symbol reference such as ``subjects.RawFalco`` has no slash and a
# ``.<Ident>`` tail; it is NOT a path and must be excluded from the extant
# check (it is documenting a code symbol, not a file).
_GO_SYMBOL_RE = re.compile(r"^[A-Za-z_]\w*(\.[A-Za-z_]\w*)+$")

# A Go test/benchmark/fuzz/example function declaration. We parse the file as
# TEXT (not via the Go toolchain) so a ``//go:build integration`` tag does not
# hide the function from the audit: a build-tag-gated test file still defines
# real test ids. All four Go testing-func forms are recognised so a cited
# ``Benchmark*``/``Fuzz*``/``Example*`` id is verified, not silently unaudited.
_TEST_FUNC_RE = re.compile(r"^func ((?:Test|Benchmark|Fuzz|Example)\w+)\(", re.MULTILINE)

# A test identifier cited inside a test_ids cell. Covers the Go forms
# (``Test*``/``Benchmark*``/``Fuzz*``/``Example*``) and the Python pytest form
# (``test_*``), so a Python ``test_*`` id cited against a ``.py`` test file is
# verified against that file rather than skipped.
_TEST_ID_RE = re.compile(r"`((?:Test|Benchmark|Fuzz|Example)\w+|test_\w+)`")

# A Python test function declaration: a module-level ``def test_x(`` or a
# pytest class method ``def test_x(self``. Parsed as text to mirror the Go
# helper; ``\s*`` after the name tolerates a space before the paren.
_PY_TEST_FUNC_RE = re.compile(r"^\s*def (test_\w+)\s*\(", re.MULTILINE)

# A ``.py`` test-file token (used to pick the Python resolver over the Go one).
_PY_FILE_RE = re.compile(r"\.py$")

# The matrix's own column names are backticked in prose (e.g. "every row's
# ``code_package``/``test_files``/``test_ids``"). They match the ``test_*``
# id shape but are NOT cited test functions, so they are excluded from the
# test_id scan to avoid a false missing-test_id finding.
_COLUMN_NAME_TOKENS: frozenset[str] = frozenset({"test_files", "test_ids", "test_id"})

# Any backticked token.
_BACKTICK_RE = re.compile(r"`([^`]+)`")

# The numeric body of a claim_id (the ``c<num>`` prefix) and of a ch3_section
# (the ``§<num>`` body). Used for the self-consistency agreement check.
_CLAIM_NUM_RE = re.compile(r"^c([0-9][0-9.]*)")
_SECTION_NUM_RE = re.compile(r"§([0-9][0-9.]*)")

# A markdown heading in the Chapter 3 source that carries a section number,
# e.g. ``## 3.6 Ring 3: Detection`` or ``### 3.6.3 Tier 3: LLM Analyst``.
_CH3_HEADING_RE = re.compile(r"^#{2,4}\s+([0-9]+(?:\.[0-9]+)*)\b", re.MULTILINE)


@dataclass(frozen=True)
class Row:
    """One parsed matrix row (the six NFR42 columns)."""

    claim_id: str
    ch3_section: str
    code_package: str
    test_files: str
    test_ids: str
    eval_run_ids: str


@dataclass
class Findings:
    """Accumulated audit results. ``hard`` findings fail the build."""

    rows_checked: int = 0
    path_tokens_checked: int = 0
    test_ids_checked: int = 0
    eval_pending: int = 0

    missing_paths: List[Tuple[str, str, str]] = field(default_factory=list)
    missing_test_ids: List[Tuple[str, str]] = field(default_factory=list)
    duplicate_claim_ids: List[str] = field(default_factory=list)
    prefix_mismatches: List[Tuple[str, str]] = field(default_factory=list)
    malformed_rows: List[str] = field(default_factory=list)

    # Informational only (never fails the build): see BI-5 (sort order) and
    # BI-3 (Chapter 3 section granularity).
    sort_warning: Optional[str] = None
    orphan_rows: List[str] = field(default_factory=list)
    orphan_claims: List[str] = field(default_factory=list)
    finer_sections: List[str] = field(default_factory=list)
    ch3_status: str = "skipped (Chapter 3 source not present in this tree)"

    def has_hard_drift(self) -> bool:
        return bool(
            self.missing_paths
            or self.missing_test_ids
            or self.duplicate_claim_ids
            or self.prefix_mismatches
            or self.malformed_rows
        )


def parse_matrix(text: str) -> Tuple[List[Row], List[str]]:
    """Extract the six-column rows from the ``## Matrix`` table.

    Returns ``(rows, malformed)``. The table runs from the header row
    (``| claim_id | ch3_section | ... |``) through to the next ``## `` section.
    The header and the ``|---|`` separator row are dropped. A ``|``-shaped data
    line under the table that does NOT split into exactly six cells (a dropped,
    over-split, or pipe-in-cell row) is collected into ``malformed`` so the
    caller can turn it into a HARD finding: a structurally-broken row FAILS the
    build instead of silently vanishing.
    """
    rows: List[Row] = []
    malformed: List[str] = []
    in_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if not in_table:
            if stripped.startswith("| claim_id") and "ch3_section" in stripped:
                in_table = True
            continue
        # Inside the table: the matrix is loosely formatted and carries blank
        # lines between some rows, so a blank line does NOT end the table. The
        # table ends at the next markdown section header (``## Provenance``).
        if not stripped:
            continue
        if stripped.startswith("#"):
            break
        if not stripped.startswith("|"):
            # A stray non-table, non-heading line: end defensively rather than
            # mis-parse trailing prose.
            break
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if cells and cells[0] == "claim_id":
            continue
        # The ``|---|---|...`` separator row: every cell is only dashes.
        if cells and all(set(c) <= set("-") and c for c in cells):
            continue
        if len(cells) != 6:
            # A pipe-shaped data line that does not yield six cells is a
            # structural break (dropped/extra cell, or an unescaped pipe inside
            # a cell). Record it so it becomes a hard finding.
            malformed.append(stripped)
            continue
        rows.append(
            Row(
                claim_id=cells[0].strip("` "),
                ch3_section=cells[1],
                code_package=cells[2],
                test_files=cells[3],
                test_ids=cells[4],
                eval_run_ids=cells[5],
            )
        )
    return rows, malformed


def _expand_braces(token: str) -> List[str]:
    """Expand a single ``{a,b,c}`` brace group (recursively for nested groups).

    ``deploy/x/{a,b}.yaml`` -> ``[deploy/x/a.yaml, deploy/x/b.yaml]``. A token
    with no brace group returns itself unchanged.
    """
    match = re.search(r"\{([^{}]*)\}", token)
    if match is None:
        return [token]
    pre = token[: match.start()]
    post = token[match.end() :]
    out: List[str] = []
    for option in match.group(1).split(","):
        out.extend(_expand_braces(pre + option + post))
    return out


def _is_path_shaped(token: str) -> bool:
    """True iff a backticked token denotes a file path (not prose / a symbol).

    A path is anything with a slash (after excluding ``//`` build-tag tokens and
    dotted Go symbols), or a bare file with a known extension, or one of the
    explicit bare-file names. CI-step names ("Canonical-name lint"), schema
    annotations ("# @schema"), and Go symbols ("subjects.RawFalco") are all
    rejected here so they are never extant-checked.
    """
    if token.startswith("//"):  # ``//go:build ...`` build tag, not a path.
        return False
    if " " in token:  # multi-word prose such as a CI step name.
        return False
    if "/" in token:
        return True
    if token in _BARE_FILE_TOKENS:
        return True
    # A known file extension wins over the Go-symbol shape (``x_test.go`` and
    # ``pkg.Symbol`` both match the dotted-identifier pattern, but the former is
    # a file). Check the extension first, then fall through to the symbol
    # exclusion for genuine ``pkg.Symbol`` references.
    _, dot, ext = token.rpartition(".")
    if dot and ("." + ext.lower()) in _PATH_EXTENSIONS:
        return True
    if _GO_SYMBOL_RE.match(token):  # ``pkg.Symbol`` reference, not a path.
        return False
    return False


def path_tokens(cell: str) -> List[str]:
    """All path-shaped, brace-expanded tokens in a code_package/test_files cell."""
    out: List[str] = []
    for raw in _BACKTICK_RE.findall(cell):
        token = raw.strip().rstrip("/")
        if not _is_path_shaped(token):
            continue
        out.extend(_expand_braces(token))
    return out


def git_tracked_paths(root: Path) -> Set[str]:
    """The set of repo-relative paths under version control (``git ls-files``).

    Membership in this set, NOT filesystem ``os.path.exists``, is the basis for
    the extant check. A gitignored-but-locally-present file (e.g. a
    ``make helm-prepare`` staged copy under ``deploy/helm/olaitan/files/``)
    therefore does NOT satisfy a path token, so the audit is byte-identical
    between a developer's working tree and a fresh CI checkout. Stdlib only:
    ``git ls-files`` via subprocess, run once at the repo root.

    When ``root`` is not inside a git work tree (a unit test's scratch
    directory), ``git ls-files`` returns nothing useful, so we fall back to a
    filesystem walk: every present file is treated as tracked. The repo / CI
    path always goes through ``git ls-files`` and gets the strict git-tracked
    semantics that catch the gitignored-staged-copy drift.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
            text=True,
        )
        tracked = {p for p in result.stdout.split("\0") if p}
        if tracked:
            return tracked
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return {
        str(p.relative_to(root)).replace("\\", "/")
        for p in root.rglob("*")
        if p.is_file()
    }


def _path_tracked(token: str, tracked: Set[str]) -> bool:
    """True iff a path token names a git-tracked file (or matches one tracked).

    A literal token must be a tracked path. A glob token (``*?[``) matches if at
    least one tracked path matches it. A directory token (no extension, names no
    tracked file directly) matches if some tracked path lives under it; this
    covers the ``internal/foo/`` package-directory idiom in the matrix.
    """
    if any(ch in token for ch in "*?["):
        return any(fnmatch.fnmatch(p, token) for p in tracked)
    if token in tracked:
        return True
    prefix = token + "/"
    return any(p.startswith(prefix) for p in tracked)


def _test_funcs_in(
    files: Sequence[str], root: Path, tracked: Set[str], cache: Dict[str, Set[str]]
) -> Set[str]:
    """Union of test-func names declared across the given (tracked) test files.

    Go files contribute their ``Test*``/``Benchmark*``/``Fuzz*``/``Example*``
    declarations; ``.py`` files contribute their ``def test_*`` declarations
    (module-level or pytest class methods). Globs are expanded against the
    git-tracked set; a file that is not tracked contributes nothing (its absence
    is already a separate missing-path finding). Parsing is textual so
    build-tag-gated Go files still contribute their declarations.
    """
    names: Set[str] = set()
    for token in files:
        if any(ch in token for ch in "*?["):
            resolved_rel = sorted(p for p in tracked if fnmatch.fnmatch(p, token))
        else:
            resolved_rel = [token] if token in tracked else []
        for rel in resolved_rel:
            if rel in cache:
                names |= cache[rel]
                continue
            found: Set[str] = set()
            path = root / rel
            if path.exists():
                contents = path.read_text(encoding="utf-8", errors="replace")
                pattern = _PY_TEST_FUNC_RE if _PY_FILE_RE.search(rel) else _TEST_FUNC_RE
                found = set(pattern.findall(contents))
            cache[rel] = found
            names |= found
    return names


# An allowed eval_run_ids deferral: ``n/a`` or ``deferred`` as a whole token,
# optionally followed by a parenthetical rationale (``n/a (substrate)``). The
# token must be the entire value or be followed by whitespace / ``(`` so a
# real-looking id with a ``deferred`` prefix (``deferred-but-real-123``) is NOT
# mis-accepted as deferred.
_EVAL_DEFERRED_RE = re.compile(r"^(n/a|deferred)(\s|\(|$)")


def _is_eval_deferred(value: str) -> bool:
    """True iff an eval_run_ids cell is an allowed deferred / not-applicable value."""
    low = value.strip().lower()
    if low == "":
        return True
    return _EVAL_DEFERRED_RE.match(low) is not None


def _claim_family_prefix(claim_id: str) -> Optional[str]:
    """The numeric chapter/section prefix of a claim_id, or None for a wildcard.

    ``c3.10.9-foo`` -> ``3.10.9``. The family-wildcard idioms ``c3.7.x-...`` and
    ``c3-meta`` / ``c<n>-...`` (bare chapter, no section) return None so they are
    not held to a numeric-section agreement they intentionally do not assert.
    """
    if claim_id.startswith("c3.7.x-") or "-meta" in claim_id:
        return None
    match = _CLAIM_NUM_RE.match(claim_id)
    if match is None:
        return None
    prefix = match.group(1).rstrip(".")
    if "." not in prefix:  # bare chapter (``c3-...``), no section to agree with.
        return None
    return prefix


def audit(
    rows: Sequence[Row],
    root: Path,
    chapter3: Optional[Path],
    tracked: Optional[Set[str]] = None,
    malformed: Optional[Sequence[str]] = None,
) -> Findings:
    """Run every AC1/AC2 check over the parsed rows; return the findings.

    ``tracked`` is the git-tracked path set the extant check resolves against;
    it is computed from ``root`` via ``git ls-files`` when not supplied. A
    gitignored-but-present file therefore does NOT satisfy a path token, so the
    audit is byte-identical local vs CI. ``malformed`` carries the
    structurally-broken matrix lines ``parse_matrix`` could not parse; each is a
    hard finding.
    """
    findings = Findings()
    if tracked is None:
        tracked = git_tracked_paths(root)
    findings.malformed_rows = sorted(malformed) if malformed else []
    func_cache: Dict[str, Set[str]] = {}
    seen_ids: Set[str] = set()

    for row in rows:
        findings.rows_checked += 1

        # AC2: unique claim_id.
        if row.claim_id in seen_ids:
            findings.duplicate_claim_ids.append(row.claim_id)
        seen_ids.add(row.claim_id)

        # AC2: claim_id prefix agrees with ch3_section numeric part.
        family = _claim_family_prefix(row.claim_id)
        if family is not None:
            sec = _SECTION_NUM_RE.search(row.ch3_section)
            sec_num = sec.group(1).rstrip(".") if sec else ""
            if sec_num != family:
                findings.prefix_mismatches.append((row.claim_id, row.ch3_section))

        # AC1: code_package + test_files paths are extant (git-tracked).
        file_tokens = path_tokens(row.test_files)
        for cell in (row.code_package, row.test_files):
            for token in path_tokens(cell):
                findings.path_tokens_checked += 1
                if not _path_tracked(token, tracked):
                    findings.missing_paths.append((row.claim_id, _col_name(cell, row), token))

        # AC1: every cited test_id is a real func in the row's test files. The
        # matrix's own column-name tokens (``test_files``/``test_ids``) can
        # appear backticked in a row's prose; they are not cited test funcs.
        cited_ids = [t for t in _TEST_ID_RE.findall(row.test_ids) if t not in _COLUMN_NAME_TOKENS]
        if cited_ids:
            available = _test_funcs_in(file_tokens, root, tracked, func_cache)
            for test_id in cited_ids:
                findings.test_ids_checked += 1
                if test_id not in available:
                    findings.missing_test_ids.append((row.claim_id, test_id))

        # AC1: eval_run_ids deferral accounting.
        if _is_eval_deferred(row.eval_run_ids):
            findings.eval_pending += 1

    # AC2 (informational, BI-5): sort order.
    ids = [r.claim_id for r in rows]
    if ids != sorted(ids):
        findings.sort_warning = (
            "matrix rows are not in strict lexicographic claim_id order "
            "(informational only; see Story 6.9 BI-5)"
        )

    # AC2 (optional, BI-2/BI-3): Chapter 3 orphan cross-check.
    if chapter3 is not None and chapter3.exists():
        _cross_check_chapter3(rows, chapter3, findings)

    return findings


def _col_name(cell: str, row: Row) -> str:
    return "code_package" if cell == row.code_package else "test_files"


def _cross_check_chapter3(rows: Sequence[Row], chapter3: Path, findings: Findings) -> None:
    """Report orphan rows / orphan claims against the real Chapter 3 headings.

    Reported, never gated (BI-2: the chapter is absent from CI). Section numbers
    in the matrix that are FINER than any real heading (BI-3: the matrix tracks
    a planned fine-grained decomposition the condensed chapter collapses) are
    listed separately as expected-finer, not as orphans, so the output is honest
    about why a row has no exact heading.
    """
    text = chapter3.read_text(encoding="utf-8", errors="replace")
    headings: Set[str] = set(_CH3_HEADING_RE.findall(text))
    findings.ch3_status = f"cross-checked against {chapter3}"

    row_sections: Set[str] = set()
    for row in rows:
        # ``§3-meta`` (and any ``-meta`` section) is the matrix's own
        # self-reference, not a thesis heading; it is exempt from the orphan
        # check by design.
        if "meta" in row.ch3_section.lower():
            continue
        match = _SECTION_NUM_RE.search(row.ch3_section)
        if match is None:
            continue
        sec = match.group(1).rstrip(".")
        row_sections.add(sec)
        if sec in headings:
            continue
        # A section is "finer" if some real heading is a prefix of it (the
        # matrix decomposes a chapter heading further). Otherwise it is a true
        # orphan row (a section the chapter does not have at any granularity).
        if any(sec.startswith(h + ".") for h in headings):
            findings.finer_sections.append(sec)
        else:
            findings.orphan_rows.append(sec)

    for heading in headings:
        if heading in row_sections:
            continue
        # A heading is covered if some row section sits underneath it (the
        # finer-decomposition case) -- not an orphan claim then.
        if any(rs.startswith(heading + ".") for rs in row_sections):
            continue
        findings.orphan_claims.append(heading)

    findings.finer_sections = sorted(set(findings.finer_sections))
    findings.orphan_rows = sorted(set(findings.orphan_rows))
    findings.orphan_claims = sorted(set(findings.orphan_claims))


def render_report(findings: Findings) -> str:
    """Render a deterministic, human-readable audit report."""
    lines: List[str] = []
    lines.append("Traceability matrix audit (Story 6.9, NFR42)")
    lines.append("=" * 44)
    lines.append(f"rows checked:            {findings.rows_checked}")
    lines.append(f"path tokens checked:     {findings.path_tokens_checked}")
    lines.append(f"test_ids checked:        {findings.test_ids_checked}")
    lines.append(
        f"eval_run_ids pending:    {findings.eval_pending} "
        "(deferred to cluster phase, Stories 5.9/5.10)"
    )
    lines.append(f"chapter 3 cross-check:   {findings.ch3_status}")
    lines.append("")

    lines.append("AC1: extant artefacts")
    if findings.missing_paths:
        lines.append(f"  DRIFT: {len(findings.missing_paths)} missing path(s):")
        for claim, col, token in sorted(findings.missing_paths):
            lines.append(f"    - {claim} [{col}] -> {token}")
    else:
        lines.append("  ok: every path-shaped code_package/test_files token exists")
    if findings.missing_test_ids:
        lines.append(f"  DRIFT: {len(findings.missing_test_ids)} missing test_id(s):")
        for claim, test_id in sorted(findings.missing_test_ids):
            lines.append(f"    - {claim} -> {test_id} (no byte-equal func Test...)")
    else:
        lines.append("  ok: every cited test_id is a real func in its test files")
    lines.append("")

    lines.append("AC2: self-consistency (hard)")
    if findings.malformed_rows:
        lines.append(
            f"  DRIFT: {len(findings.malformed_rows)} malformed matrix row(s) "
            "(not six pipe-delimited cells):"
        )
        for raw in findings.malformed_rows:
            lines.append(f"    - {raw}")
    else:
        lines.append("  ok: every matrix data row has exactly six cells")
    if findings.duplicate_claim_ids:
        lines.append(f"  DRIFT: duplicate claim_id(s): {sorted(set(findings.duplicate_claim_ids))}")
    else:
        lines.append("  ok: every claim_id is unique")
    if findings.prefix_mismatches:
        lines.append(f"  DRIFT: {len(findings.prefix_mismatches)} claim_id/section mismatch(es):")
        for claim, sec in sorted(findings.prefix_mismatches):
            lines.append(f"    - {claim} vs {sec}")
    else:
        lines.append("  ok: every claim_id prefix agrees with its ch3_section")
    lines.append("")

    lines.append("AC2: informational (not gated)")
    lines.append(
        "  sort order: "
        + (findings.sort_warning if findings.sort_warning else "strict lexicographic")
    )
    if findings.finer_sections:
        lines.append(
            "  sections finer than a chapter heading (expected, BI-3): "
            + ", ".join(findings.finer_sections)
        )
    if findings.orphan_rows:
        lines.append("  orphan rows (section absent from chapter at any granularity): "
                     + ", ".join(findings.orphan_rows))
    if findings.orphan_claims:
        lines.append("  orphan claims (chapter heading with no row): "
                     + ", ".join(findings.orphan_claims))
    if findings.ch3_status.startswith("cross-checked") and not (
        findings.orphan_rows or findings.orphan_claims
    ):
        lines.append("  no true orphan rows / orphan claims against the chapter")
    lines.append("")

    lines.append("RESULT: " + ("DRIFT (exit 1)" if findings.has_hard_drift() else "CLEAN (exit 0)"))
    return "\n".join(lines)


def _auto_discover_chapter3(root: Path) -> Optional[Path]:
    """Best-effort locate the Chapter 3 markdown for the optional cross-check.

    It is not in the code repo (BI-2); a developer running locally may have the
    specs repo as a sibling, so try a few conventional locations. CI finds
    nothing here and the cross-check skips.
    """
    candidates = [
        root / "report" / "chapter-3-methodology.md",
        root.parent / "final-year-project" / "report" / "chapter-3-methodology.md",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Audit the NFR42 traceability matrix.")
    parser.add_argument(
        "--matrix",
        default=str(_REPO_ROOT / "docs" / "traceability.md"),
        help="path to docs/traceability.md",
    )
    parser.add_argument(
        "--root",
        default=str(_REPO_ROOT),
        help="repo root the matrix paths resolve against",
    )
    parser.add_argument(
        "--chapter3",
        default=None,
        help="optional Chapter 3 markdown for the orphan cross-check "
        "(auto-discovered if omitted; cross-check skips if absent)",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    matrix_path = Path(args.matrix)
    if not matrix_path.exists():
        print(f"audit: matrix not found at {matrix_path}", file=sys.stderr)
        return 2

    chapter3: Optional[Path]
    if args.chapter3:
        chapter3 = Path(args.chapter3)
    else:
        chapter3 = _auto_discover_chapter3(root)

    rows, malformed = parse_matrix(matrix_path.read_text(encoding="utf-8"))
    findings = audit(rows, root, chapter3, malformed=malformed)
    print(render_report(findings))
    return 1 if findings.has_hard_drift() else 0


if __name__ == "__main__":
    raise SystemExit(main())
