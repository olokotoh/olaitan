"""Unit + end-to-end tests for the traceability matrix audit (Story 6.9, NFR42).

These tests pin the audit's honesty properties: the path-token extractor must
separate real paths from prose / Go symbols / build tags; the test_id matcher
must require a BYTE-EQUAL ``func Test...`` (a renamed-with-suffix test is real
drift, not a silent pass); the self-consistency checks must flag duplicate slugs
and claim/section disagreement; the Chapter 3 cross-check must find orphans when
the chapter is present and skip gracefully when it is not; and the
``eval_run_ids`` deferral must be allowed. The end-to-end test runs the audit
against the REAL committed ``docs/traceability.md`` and asserts a clean exit,
which is the regression guard that keeps the live matrix honest on every push.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from analysis import audit_traceability as audit

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def _row(
    claim_id: str = "c3.4-foo",
    ch3_section: str = "§3.4",
    code_package: str = "`internal/foo/`",
    test_files: str = "`internal/foo/foo_test.go`",
    test_ids: str = "`TestFoo`",
    eval_run_ids: str = "n/a",
) -> audit.Row:
    return audit.Row(
        claim_id=claim_id,
        ch3_section=ch3_section,
        code_package=code_package,
        test_files=test_files,
        test_ids=test_ids,
        eval_run_ids=eval_run_ids,
    )


# --- path-token extraction (AC1 honesty: paths vs prose/symbols) -------------


def test_path_token_extractor_excludes_prose_and_symbols() -> None:
    cell = (
        "`cmd/olaitan-lint/main.go`, `Makefile` (`olaitan-lint` target), "
        "`.github/workflows/ci.yml` (`Canonical-name lint` step), "
        "`internal/eval/scenario/recipes.go` (canonical `subjects.RawFalco`/"
        "`subjects.RawNetwork` references), `deploy/helm/olaitan/values.yaml` "
        "(`# @schema` annotations)"
    )
    tokens = audit.path_tokens(cell)
    # Real paths kept.
    assert "cmd/olaitan-lint/main.go" in tokens
    assert "Makefile" in tokens
    assert ".github/workflows/ci.yml" in tokens
    assert "internal/eval/scenario/recipes.go" in tokens
    assert "deploy/helm/olaitan/values.yaml" in tokens
    # Prose / CI-step names / Go symbols / schema annotations excluded.
    assert "olaitan-lint" not in tokens
    assert "Canonical-name lint" not in tokens
    assert "subjects.RawFalco" not in tokens
    assert "subjects.RawNetwork" not in tokens
    assert "# @schema" not in tokens


def test_path_token_extractor_expands_braces() -> None:
    cell = "`deploy/s/{a,b}.yaml`"
    tokens = audit.path_tokens(cell)
    assert tokens == ["deploy/s/a.yaml", "deploy/s/b.yaml"]


def test_path_token_extractor_keeps_glob_token() -> None:
    cell = "`deploy/helm/testdata/golden/*.golden.yaml`"
    tokens = audit.path_tokens(cell)
    assert tokens == ["deploy/helm/testdata/golden/*.golden.yaml"]


def test_build_tag_token_is_not_a_path() -> None:
    assert audit.path_tokens("`//go:build e2e`") == []


# --- extant-artefact check (AC1) --------------------------------------------


def test_missing_path_is_flagged(tmp_path: Path) -> None:
    row = _row(code_package="`does/not/exist.go`", test_files="`also/missing_test.go`")
    findings = audit.audit([row], tmp_path, chapter3=None)
    missing = {token for _, _, token in findings.missing_paths}
    assert "does/not/exist.go" in missing
    assert "also/missing_test.go" in missing


def test_extant_path_passes(tmp_path: Path) -> None:
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "x_test.go").write_text("func TestX(t *testing.T) {}\n")
    row = _row(code_package="`pkg/`", test_files="`pkg/x_test.go`", test_ids="`TestX`")
    findings = audit.audit([row], tmp_path, chapter3=None)
    assert findings.missing_paths == []
    assert findings.missing_test_ids == []
    assert not findings.has_hard_drift()


# --- test_id matching (AC1: byte-equal, the planted-rename catch) ------------


def test_test_id_matcher_catches_renamed_test(tmp_path: Path) -> None:
    # The file defines TestFooBar; the matrix cites TestFoo. A substring match
    # would FALSE-PASS (TestFooBar contains TestFoo); the audit must require a
    # byte-equal func name and therefore FLAG this as drift.
    (tmp_path / "x_test.go").write_text("func TestFooBar(t *testing.T) {}\n")
    row = _row(code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestFoo`")
    findings = audit.audit([row], tmp_path, chapter3=None)
    flagged = {tid for _, tid in findings.missing_test_ids}
    assert "TestFoo" in flagged
    assert findings.has_hard_drift()


def test_test_id_matcher_passes_byte_equal(tmp_path: Path) -> None:
    (tmp_path / "x_test.go").write_text("func TestFooBar(t *testing.T) {}\n")
    row = _row(code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestFooBar`")
    findings = audit.audit([row], tmp_path, chapter3=None)
    assert findings.missing_test_ids == []


def test_test_id_matcher_reads_build_tagged_file(tmp_path: Path) -> None:
    # A //go:build integration file still defines real test ids; the audit
    # parses it as text so the tag does not hide the function.
    (tmp_path / "x_test.go").write_text(
        "//go:build integration\n\npackage x\n\nfunc TestGated(t *testing.T) {}\n"
    )
    row = _row(code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestGated`")
    findings = audit.audit([row], tmp_path, chapter3=None)
    assert findings.missing_test_ids == []


# --- self-consistency (AC2 hard gate) ---------------------------------------


def test_self_consistency_flags_duplicate_and_prefix_mismatch(tmp_path: Path) -> None:
    (tmp_path / "x_test.go").write_text("func TestX(t *testing.T) {}\n")
    rows = [
        _row(claim_id="c3.4-dup", code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestX`"),
        _row(claim_id="c3.4-dup", code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestX`"),
        # claim prefix 3.6 but section says 3.4 -> mismatch.
        _row(claim_id="c3.6-bad", ch3_section="§3.4", code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestX`"),
    ]
    findings = audit.audit(rows, tmp_path, chapter3=None)
    assert "c3.4-dup" in findings.duplicate_claim_ids
    assert any(cid == "c3.6-bad" for cid, _ in findings.prefix_mismatches)
    assert findings.has_hard_drift()


def test_family_wildcard_slug_not_flagged(tmp_path: Path) -> None:
    # The c3.7.x- family-wildcard idiom maps to a concrete §3.7.N and must NOT
    # be flagged as a prefix mismatch; likewise c3-meta / §3-meta.
    (tmp_path / "x_test.go").write_text("func TestX(t *testing.T) {}\n")
    rows = [
        _row(claim_id="c3.7.x-thing", ch3_section="§3.7.3", code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestX`"),
        _row(claim_id="c3-traceability-bootstrap", ch3_section="§3-meta", code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestX`"),
    ]
    findings = audit.audit(rows, tmp_path, chapter3=None)
    assert findings.prefix_mismatches == []


# --- eval_run_ids deferral (AC1) --------------------------------------------


def test_eval_run_ids_deferral_allowed(tmp_path: Path) -> None:
    (tmp_path / "x_test.go").write_text("func TestX(t *testing.T) {}\n")
    base = dict(code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestX`")
    rows = [
        _row(claim_id="c3.4-a", eval_run_ids="n/a", **base),
        _row(claim_id="c3.4-b", eval_run_ids="deferred", **base),
        _row(claim_id="c3.4-c", eval_run_ids="n/a (substrate/documentation)", **base),
        _row(claim_id="c3.4-d", eval_run_ids="", **base),
    ]
    findings = audit.audit(rows, tmp_path, chapter3=None)
    assert findings.eval_pending == 4
    # A deferred eval_run_ids is allowed and never a hard drift.
    assert not findings.has_hard_drift()


# --- Chapter 3 cross-check (AC2 optional / BI-2 / BI-3) ----------------------


def test_chapter3_cross_check_orphans_and_finer(tmp_path: Path) -> None:
    (tmp_path / "x_test.go").write_text("func TestX(t *testing.T) {}\n")
    chapter = tmp_path / "ch3.md"
    chapter.write_text(
        "# Chapter 3\n\n## 3.4 Collection\n\n### 3.4.1 Schema\n\n## 3.9 Evaluation\n"
    )
    base = dict(code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestX`")
    rows = [
        # A row under a real heading (exact).
        _row(claim_id="c3.4-a", ch3_section="§3.4", **base),
        # A finer row under 3.9 (expected, BI-3), not an orphan.
        _row(claim_id="c3.9.2-b", ch3_section="§3.9.2", **base),
        # A true orphan row: no 3.7 heading at any granularity.
        _row(claim_id="c3.7-c", ch3_section="§3.7", **base),
    ]
    findings = audit.audit(rows, tmp_path, chapter3=chapter)
    assert "3.9.2" in findings.finer_sections
    assert "3.7" in findings.orphan_rows
    # 3.4.1 is a chapter heading with no row -> orphan claim (informational).
    assert "3.4.1" in findings.orphan_claims
    # The cross-check is informational: orphans do NOT make a hard drift.
    assert not findings.has_hard_drift()


def test_chapter3_absent_skips_gracefully(tmp_path: Path) -> None:
    (tmp_path / "x_test.go").write_text("func TestX(t *testing.T) {}\n")
    row = _row(code_package="`x_test.go`", test_files="`x_test.go`", test_ids="`TestX`")
    findings = audit.audit([row], tmp_path, chapter3=tmp_path / "nope.md")
    assert findings.ch3_status.startswith("skipped")
    assert findings.orphan_rows == []
    assert findings.orphan_claims == []


# --- end-to-end against the REAL committed matrix (the regression guard) -----


def test_audit_real_matrix_is_clean() -> None:
    matrix = _REPO_ROOT / "docs" / "traceability.md"
    rows = audit.parse_matrix(matrix.read_text(encoding="utf-8"))
    # Sanity: the parse must see the whole table, not break early.
    assert len(rows) >= 90
    ids = [r.claim_id for r in rows]
    assert "c3.10.9-traceability-audit" in ids  # the Story 6.9 self-row.
    # The Chapter 3 cross-check is intentionally NOT exercised here (the thesis
    # markdown is absent from the code repo / CI checkout, BI-2); the hard gate
    # is the extant-artefact + self-consistency checks against the real tree.
    findings = audit.audit(rows, _REPO_ROOT, chapter3=None)
    assert not findings.has_hard_drift(), audit.render_report(findings)


def test_main_exit_zero_on_real_tree() -> None:
    # The audit's main() must exit 0 against the committed matrix (CI hard gate
    # passes). --chapter3 is pointed at a non-existent path so the optional
    # cross-check skips deterministically regardless of the dev's local layout.
    rc = audit.main(["--chapter3", str(_REPO_ROOT / "no-such-chapter.md")])
    assert rc == 0
