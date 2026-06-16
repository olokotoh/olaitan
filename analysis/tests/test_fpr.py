"""Known-answer unit test for the FPR computation (Story 5.5, BI-5)."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from analysis.lib import metrics


def _benign_run(base: Path, run_id: str, escalations: int) -> None:
    run_dir = base / run_id
    run_dir.mkdir(parents=True)
    lines = "".join(
        '{"schema_version":"audit.transitions.v1","payload":{"after_state":"SUSPICIOUS"}}\n'
        for _ in range(escalations)
    )
    (run_dir / "fsm.jsonl").write_text(lines, encoding="utf-8")


def _cell(run_ids: list[str], start: str, finish: str) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "run_id": run_ids,
            "config": ["rsl"] * len(run_ids),
            "scenario": ["benign"] * len(run_ids),
            "started_at": [start] * len(run_ids),
            "finished_at": [finish] * len(run_ids),
        }
    )


def _cell_rows(rows: list[dict[str, str]]) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "run_id": r["run_id"],
                "config": "rsl",
                "scenario": "benign",
                "started_at": r["started_at"],
                "finished_at": r["finished_at"],
            }
            for r in rows
        ]
    )


def test_fpr_escalations_per_hour(tmp_path: Path) -> None:
    # 3 escalations over a 1-hour window -> 3.0 per hour.
    _benign_run(tmp_path, "b1", escalations=3)
    cell = _cell(["b1"], "2026-06-15T09:00:00Z", "2026-06-15T10:00:00Z")
    result = metrics.fpr(cell, str(tmp_path))
    assert result.value == 3.0
    assert result.escalations == 3
    assert result.window_hours == 1.0
    assert result.n == 1


def test_fpr_no_benign_runs_is_na(tmp_path: Path) -> None:
    cell = _cell([], "2026-06-15T09:00:00Z", "2026-06-15T10:00:00Z")
    result = metrics.fpr(cell, str(tmp_path))
    assert result.value is None
    assert result.n == 0


def test_fpr_clean_only_is_zero(tmp_path: Path) -> None:
    _benign_run(tmp_path, "b1", escalations=0)
    cell = _cell(["b1"], "2026-06-15T09:00:00Z", "2026-06-15T11:00:00Z")
    result = metrics.fpr(cell, str(tmp_path))
    assert result.value == 0.0
    assert result.escalations == 0
    assert result.window_hours == 2.0


def test_fpr_bad_window_run_excluded_from_both(tmp_path: Path) -> None:
    # M2: a run with an UNUSABLE wall-window (zero/negative) is skipped ENTIRELY,
    # so its escalations are NOT counted either. Here b1 has a valid 1-hour window
    # with 1 escalation; b2 has a zero-length window with 5 escalations. The rate
    # must be 1/1 = 1.0 per hour (b2 dropped from BOTH numerator and denominator),
    # NOT (1+5)/1 = 6.0 which would falsely cross the 2/hr bound.
    _benign_run(tmp_path, "b1", escalations=1)
    _benign_run(tmp_path, "b2", escalations=5)
    cell = _cell_rows(
        [
            {
                "run_id": "b1",
                "started_at": "2026-06-15T09:00:00Z",
                "finished_at": "2026-06-15T10:00:00Z",
            },
            {
                "run_id": "b2",
                "started_at": "2026-06-15T09:00:00Z",
                "finished_at": "2026-06-15T09:00:00Z",  # zero-length: unusable
            },
        ]
    )
    result = metrics.fpr(cell, str(tmp_path))
    assert result.value == 1.0
    assert result.escalations == 1  # b2's 5 escalations are NOT counted
    assert result.window_hours == 1.0
    assert result.n == 2  # the cell sample size still reports both benign runs


def test_fpr_all_bad_window_is_na(tmp_path: Path) -> None:
    # M2: a cell whose every run has an unusable window degrades to n/a (BI-7),
    # never a fabricated rate, even though escalations were observed.
    _benign_run(tmp_path, "b1", escalations=3)
    cell = _cell(["b1"], "2026-06-15T09:00:00Z", "2026-06-15T09:00:00Z")
    result = metrics.fpr(cell, str(tmp_path))
    assert result.value is None
    assert result.window_hours == 0.0
