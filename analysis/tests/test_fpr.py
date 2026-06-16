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
