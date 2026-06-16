"""Known-answer tests for the DFIR rubric consumer (Story 5.7, RQ5, OQ1).

Covers the rubric score reader (``io.load_rubric_scores``) and the
Wilcoxon-per-dimension + ICC(2,k) aggregation (``analyse.build_rubric_rows``):
the reader reads the reserved ``runs/rubric/`` sub-tree, and the rows compute the
five Wilcoxon tests + the ICC row WITHOUT crashing and DEGRADE HONESTLY at tiny n
(the helpers SKIP where their preconditions are unmet, never a fabricated
p-value, BI-4). Each pins a hand-verified answer. The Story-5.5
``tests.wilcoxon_signed_rank`` / ``tests.icc_2k`` helpers are FED here, never
re-implemented or modified.
"""

from __future__ import annotations

import json
from pathlib import Path

from analysis import analyse
from analysis.lib import io
from analysis.lib.prereg import parse_registry

_PREREG = "analysis/preregistration.md"

_DIMENSIONS = ("clarity", "completeness", "attack-coverage", "killchain", "actionability")


def _score(
    incident_id: str,
    variant: str,
    rater: str,
    dimension: str,
    score: int,
    *,
    scenario: str = "s1",
    synthetic: bool = True,
) -> dict[str, object]:
    return {
        "schema_version": "rubric.score.v1",
        "incident_id": incident_id,
        "scenario": scenario,
        "variant": variant,
        "rater": rater,
        "dimension": dimension,
        "score": score,
        "synthetic": synthetic,
    }


def _write_rubric_run(
    runs_dir: Path,
    run_id: str,
    scores: list[dict[str, object]],
    *,
    scenario: str = "s1",
    n_incidents: int = 1,
    n_raters: int = 2,
    manifest: str = "rubrichash",
    synthetic: bool = True,
) -> None:
    run_dir = runs_dir / "rubric" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "scores.jsonl").write_text(
        "".join(json.dumps(s) + "\n" for s in scores), encoding="utf-8"
    )
    meta = [
        f"run_id: {run_id}",
        f"manifest_sha256: {manifest}",
        f"scenario: {scenario}",
        f"n_incidents: {n_incidents}",
        f"n_raters: {n_raters}",
        f"synthetic: {str(synthetic).lower()}",
    ]
    (run_dir / "metadata.yaml").write_text("\n".join(meta) + "\n", encoding="utf-8")


def test_load_rubric_scores_absent_subtree_is_empty(tmp_path: Path) -> None:
    # No rubric/ sub-tree -> empty list (the honest n=0 skip stays, BI-4).
    (tmp_path / "fixture-rsl-s1-00").mkdir()
    assert io.load_rubric_scores(str(tmp_path)) == []


def test_load_rubric_scores_reads_records(tmp_path: Path) -> None:
    _write_rubric_run(
        tmp_path,
        "rubric-offline-s1",
        [
            _score("inc-1", "llm", "synthetic-1", "clarity", 4),
            _score("inc-1", "templated", "synthetic-1", "clarity", 3),
        ],
    )
    runs = io.load_rubric_scores(str(tmp_path))
    assert len(runs) == 1
    run = runs[0]
    assert run.scenario == "s1"
    assert run.synthetic is True
    assert len(run.scores) == 2
    assert run.scores[0].incident_id == "inc-1"
    assert run.scores[0].dimension == "clarity"
    assert run.scores[0].score == 4.0


def test_load_rubric_scores_rejects_wrong_schema_version(tmp_path: Path) -> None:
    bad = _score("inc-1", "llm", "synthetic-1", "clarity", 4)
    bad["schema_version"] = "rubric.score.v999"
    _write_rubric_run(tmp_path, "rubric-offline-s1", [bad])
    try:
        io.load_rubric_scores(str(tmp_path))
    except ValueError as exc:
        assert "schema_version" in str(exc)
    else:
        raise AssertionError("expected a ValueError on the wrong schema_version")


def test_load_rubric_scores_rejects_unknown_dimension(tmp_path: Path) -> None:
    # A 6th / unknown dimension is a drift error (BI-5: the 5 canonical dims are
    # fixed; the Go emitter and this reader must agree exactly).
    bad = _score("inc-1", "llm", "synthetic-1", "overall-usefulness", 4)
    _write_rubric_run(tmp_path, "rubric-offline-s1", [bad])
    try:
        io.load_rubric_scores(str(tmp_path))
    except ValueError as exc:
        assert "dimension" in str(exc)
    else:
        raise AssertionError("expected a ValueError on an unknown dimension")


def test_load_rubric_scores_rejects_out_of_range_score(tmp_path: Path) -> None:
    # A score outside the 1-5 Likert range (here 6) is rejected at the trust
    # boundary: an out-of-range hand edit must not load silently into Wilcoxon /
    # ICC. Mirrors the unknown-dimension drift guard.
    bad = _score("inc-1", "llm", "synthetic-1", "clarity", 6)
    _write_rubric_run(tmp_path, "rubric-offline-s1", [bad])
    try:
        io.load_rubric_scores(str(tmp_path))
    except ValueError as exc:
        assert "Likert range" in str(exc)
    else:
        raise AssertionError("expected a ValueError on an out-of-range score")


def test_load_rubric_scores_rejects_unknown_variant(tmp_path: Path) -> None:
    # An unknown variant is dropped from the Wilcoxon pairing but would still
    # enter the ICC frame and corrupt the reliability estimate; reject it (BI-5).
    bad = _score("inc-1", "human", "synthetic-1", "clarity", 4)
    _write_rubric_run(tmp_path, "rubric-offline-s1", [bad])
    try:
        io.load_rubric_scores(str(tmp_path))
    except ValueError as exc:
        assert "variant" in str(exc)
    else:
        raise AssertionError("expected a ValueError on an unknown variant")


def test_build_rubric_rows_skips_when_absent(tmp_path: Path) -> None:
    # No rubric/ sub-tree -> the honest n=0 skip on every row (BI-4), never a
    # fabricated finding.
    run_set = io.RunSet(frame=io._coerce_frame([]), runs_dir=str(tmp_path), is_fixture=False)
    registry = parse_registry(_PREREG)
    rows = analyse.build_rubric_rows(run_set, registry)
    # 5 Wilcoxon rows + 1 ICC row.
    assert len(rows) == 6
    for row in rows:
        assert row.n == 0
        assert "skipped" in row.status
        assert row.p_value is None
    test_ids = {row.test_id for row in rows}
    assert "RQ5-ICC" in test_ids
    for dim in ("CLARITY", "COMPLETENESS", "ATTACK-COVERAGE", "KILLCHAIN", "ACTIONABILITY"):
        assert f"RQ5-RUBRIC-WILCOXON-{dim}" in test_ids


def test_build_rubric_rows_single_incident_runs_without_crashing(tmp_path: Path) -> None:
    # The AC5 data-path proof: a SINGLE synthetic incident scored on both
    # variants by 2 raters across all 5 dimensions. Wilcoxon gets n=1 paired
    # observation per dimension and ICC gets >=2 targets x 2 raters. The rows
    # MUST compute WITHOUT crashing (degrading honestly at tiny n), never a
    # fabricated p-value.
    scores: list[dict[str, object]] = []
    for rater_idx, rater in enumerate(("synthetic-1", "synthetic-2"), start=0):
        for dim in _DIMENSIONS:
            # The LLM placeholder sits one point above the templated baseline (a
            # non-zero paired difference so Wilcoxon does not short-circuit on
            # all-zero differences); the per-rater jitter keeps the ICC frame
            # non-degenerate. Synthetic, never a finding.
            llm = 4 + rater_idx
            templated = 3 + rater_idx
            scores.append(_score("inc-1", "llm", rater, dim, min(llm, 5)))
            scores.append(_score("inc-1", "templated", rater, dim, min(templated, 5)))
    _write_rubric_run(tmp_path, "rubric-offline-s1", scores)
    run_set = io.RunSet(frame=io._coerce_frame([]), runs_dir=str(tmp_path), is_fixture=False)
    registry = parse_registry(_PREREG)
    rows = analyse.build_rubric_rows(run_set, registry)
    assert len(rows) == 6

    wilcoxon_rows = [r for r in rows if r.test == "wilcoxon"]
    assert len(wilcoxon_rows) == 5
    for row in wilcoxon_rows:
        # n=1 paired observation per dimension; the row RAN honestly (a single
        # pair is a degenerate-but-real Wilcoxon, not a fabricated significant p).
        assert row.n == 1
        assert row.status == "run"
        assert row.p_value is not None

    icc_row = next(r for r in rows if r.test_id == "RQ5-ICC")
    # 5 dims x 2 variants x 1 incident = 10 targets, 2 raters per target -> ICC
    # runs (>=2 targets, >=2 raters). 20 rating rows.
    assert icc_row.n == 20
    assert icc_row.status == "run"


def test_build_rubric_rows_unpaired_incident_skips_honestly(tmp_path: Path) -> None:
    # An incident scored on ONLY the llm variant (no templated side) cannot be
    # paired; it is dropped honestly, leaving n=0 paired observations -> Wilcoxon
    # SKIPS, never a fabricated pairing (BI-4).
    scores = [_score("inc-1", "llm", "synthetic-1", dim, 4) for dim in _DIMENSIONS]
    _write_rubric_run(tmp_path, "rubric-offline-s1", scores)
    run_set = io.RunSet(frame=io._coerce_frame([]), runs_dir=str(tmp_path), is_fixture=False)
    registry = parse_registry(_PREREG)
    rows = analyse.build_rubric_rows(run_set, registry)
    wilcoxon_rows = [r for r in rows if r.test == "wilcoxon"]
    for row in wilcoxon_rows:
        assert row.n == 0
        assert "skipped" in row.status
        assert row.p_value is None


def test_build_rubric_rows_single_rater_icc_skips_honestly(tmp_path: Path) -> None:
    # ICC needs >= 2 raters; a single-rater frame SKIPS honestly (BI-4), never a
    # fabricated reliability coefficient.
    scores: list[dict[str, object]] = []
    for inc in ("inc-1", "inc-2"):
        for dim in _DIMENSIONS:
            scores.append(_score(inc, "llm", "synthetic-1", dim, 4))
            scores.append(_score(inc, "templated", "synthetic-1", dim, 3))
    _write_rubric_run(tmp_path, "rubric-offline-s1", scores, n_incidents=2, n_raters=1)
    run_set = io.RunSet(frame=io._coerce_frame([]), runs_dir=str(tmp_path), is_fixture=False)
    registry = parse_registry(_PREREG)
    rows = analyse.build_rubric_rows(run_set, registry)
    icc_row = next(r for r in rows if r.test_id == "RQ5-ICC")
    assert "skipped" in icc_row.status
    assert icc_row.p_value is None
