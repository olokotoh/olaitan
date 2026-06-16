"""Known-answer tests for the FR55 trust-bound consumer (Story 5.6, OQ5).

Covers the FR55 trial reader (``io.load_fr55_runs``) and the bound-proof
aggregation (``analyse.build_fr55_rows``): the reader reads the reserved
``runs/fr55/`` sub-tree, and the row computes the real ``n`` + the
``0 of N past SUSPICIOUS`` count + ``max <= bound`` when trials are present,
and keeps the honest ``n=0`` skip when they are absent (BI-7). Each pins a
hand-verified answer (BI-12).
"""

from __future__ import annotations

import json
from pathlib import Path

from analysis import analyse
from analysis.lib import io
from analysis.lib.prereg import parse_registry

_PREREG = "analysis/preregistration.md"


def _trial(index: int, config: str, fsm_state: str, threat: float) -> dict[str, object]:
    return {
        "schema_version": "fr55.trial.v1",
        "trial_index": index,
        "config": config,
        "provider": "fake",
        "raw_confidence": 100,
        "llm_capped_confidence": 35,
        "threat_score": threat,
        "final_fsm_state": fsm_state,
        "cap_violation_total": 0,
    }


def _write_fr55_run(
    runs_dir: Path,
    run_id: str,
    config: str,
    trials: list[dict[str, object]],
    *,
    bound: float = 10.5,
    manifest: str = "abc123",
    n_past: int = 0,
    max_score: float = 10.5,
    cap_violations: int = 0,
) -> None:
    run_dir = runs_dir / "fr55" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "trials.jsonl").write_text(
        "".join(json.dumps(t) + "\n" for t in trials), encoding="utf-8"
    )
    meta = [
        f"run_id: {run_id}",
        f"manifest_sha256: {manifest}",
        "scenario: benign-adversarial",
        f"config: {config}",
        "provider: fake",
        f"n_trials: {len(trials)}",
        f"max_threat_score: {max_score}",
        f"n_past_suspicious: {n_past}",
        f"cap_violation_total: {cap_violations}",
        f"bound: {bound}",
    ]
    (run_dir / "metadata.yaml").write_text("\n".join(meta) + "\n", encoding="utf-8")


def test_load_fr55_runs_absent_subtree_is_empty(tmp_path: Path) -> None:
    # No fr55/ sub-tree -> empty list (the honest n=0 skip stays, BI-7).
    (tmp_path / "fixture-rsl-s1-00").mkdir()
    assert io.load_fr55_runs(str(tmp_path)) == []


def test_load_fr55_runs_reads_trials(tmp_path: Path) -> None:
    _write_fr55_run(
        tmp_path,
        "fr55-offline-fake-rsl",
        "rsl",
        [_trial(0, "rsl", "CLEAN", 10.5), _trial(1, "rsl", "CLEAN", 10.5)],
    )
    runs = io.load_fr55_runs(str(tmp_path))
    assert len(runs) == 1
    run = runs[0]
    assert run.config == "rsl"
    assert run.provider == "fake"
    assert run.scenario == "benign-adversarial"
    assert run.bound == 10.5
    assert len(run.trials) == 2
    assert run.trials[0].threat_score == 10.5
    assert run.trials[0].final_fsm_state == "CLEAN"


def test_load_fr55_runs_rejects_wrong_schema_version(tmp_path: Path) -> None:
    bad = _trial(0, "rsl", "CLEAN", 10.5)
    bad["schema_version"] = "fr55.trial.v999"
    _write_fr55_run(tmp_path, "fr55-offline-fake-rsl", "rsl", [bad])
    try:
        io.load_fr55_runs(str(tmp_path))
    except ValueError as exc:
        assert "schema_version" in str(exc)
    else:
        raise AssertionError("expected a ValueError on the wrong schema_version")


def test_fr55_is_past_suspicious() -> None:
    assert not io.fr55_is_past_suspicious("CLEAN")
    assert not io.fr55_is_past_suspicious("SUSPICIOUS")
    assert io.fr55_is_past_suspicious("RESTRICTED")
    assert io.fr55_is_past_suspicious("QUARANTINED")
    assert io.fr55_is_past_suspicious("PRESERVED_KILLED")


def test_build_fr55_rows_skips_when_absent(tmp_path: Path) -> None:
    # No fr55/ sub-tree -> the honest n=0 skip (BI-7), never a fabricated proof.
    run_set = io.RunSet(frame=io._coerce_frame([]), runs_dir=str(tmp_path), is_fixture=False)
    registry = parse_registry(_PREREG)
    rows = analyse.build_fr55_rows(run_set, registry)
    assert len(rows) == 1
    row = rows[0]
    assert row.n == 0
    assert row.value is None
    assert "skipped" in row.status
    assert row.test_id == "RQ4-FR55-BOUND"


def test_build_fr55_rows_bound_holds_known_answer(tmp_path: Path) -> None:
    # Two runs (rsl + rslt-full), all trials CLEAN (below SUSPICIOUS), max 10.5.
    _write_fr55_run(
        tmp_path,
        "fr55-offline-fake-rsl",
        "rsl",
        [_trial(i, "rsl", "CLEAN", 10.5) for i in range(3)],
        manifest="hash-rsl",
    )
    _write_fr55_run(
        tmp_path,
        "fr55-offline-fake-rslt-full",
        "rslt-full",
        [_trial(i, "rslt-full", "CLEAN", 10.5) for i in range(3)],
        manifest="hash-rslt",
    )
    run_set = io.RunSet(frame=io._coerce_frame([]), runs_dir=str(tmp_path), is_fixture=False)
    registry = parse_registry(_PREREG)
    rows = analyse.build_fr55_rows(run_set, registry)
    assert len(rows) == 1
    row = rows[0]
    assert row.n == 6  # pooled over the two runs
    assert row.status == "run"
    assert isinstance(row.value, str)
    assert "0/6 past SUSPICIOUS" in row.value
    assert "max=10.5<=10.5" in row.value
    assert "cap_violations=0" in row.value
    # Distinct manifests across the two runs -> mixed (M4/BI-10 honesty).
    assert row.mixed_manifest is True
    assert row.manifest_hash == "mixed"


def test_build_fr55_rows_flags_bound_violation(tmp_path: Path) -> None:
    # A trial that transitions past SUSPICIOUS is a bound violation surfaced
    # honestly as FAILED, never silently dropped (BI-5/BI-7).
    _write_fr55_run(
        tmp_path,
        "fr55-offline-fake-rsl",
        "rsl",
        [_trial(0, "rsl", "RESTRICTED", 45.0)],
        max_score=45.0,
        n_past=1,
    )
    run_set = io.RunSet(frame=io._coerce_frame([]), runs_dir=str(tmp_path), is_fixture=False)
    registry = parse_registry(_PREREG)
    rows = analyse.build_fr55_rows(run_set, registry)
    row = rows[0]
    assert row.n == 1
    assert "FAILED" in row.status
    assert isinstance(row.value, str)
    assert "1/1 past SUSPICIOUS" in row.value


def test_build_fr55_rows_single_run_clean_manifest(tmp_path: Path) -> None:
    # A single run -> a clean (non-mixed) manifest hash on the row.
    _write_fr55_run(
        tmp_path,
        "fr55-offline-fake-rsl",
        "rsl",
        [_trial(i, "rsl", "CLEAN", 7.5) for i in range(2)],
        bound=7.5,
        max_score=7.5,
        manifest="onehash",
    )
    run_set = io.RunSet(frame=io._coerce_frame([]), runs_dir=str(tmp_path), is_fixture=False)
    registry = parse_registry(_PREREG)
    row = analyse.build_fr55_rows(run_set, registry)[0]
    assert row.n == 2
    assert row.mixed_manifest is False
    assert row.manifest_hash == "onehash"
    assert isinstance(row.value, str)
    assert "max=7.5<=7.5" in row.value
