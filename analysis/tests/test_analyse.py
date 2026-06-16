"""Known-answer unit tests for the pipeline-level pairing + reconciliation.

Covers the round-1 review fixes that change output semantics: the shared
scenario-instance-key pairing (H2/BI-8) and the off-grid orphan reconciliation
(M1/BI-7). Each pins a hand-verified answer (BI-12).
"""

from __future__ import annotations

import pandas as pd

from analysis import analyse


def _frame(rows: list[dict[str, object]]) -> pd.DataFrame:
    base = pd.DataFrame(rows)
    base["success_criterion_met"] = base["success_criterion_met"].astype("boolean")
    return base


def test_pair_cells_joins_on_instance_key_not_position() -> None:
    # H2: config A and config B are sorted into DIFFERENT run_id (wall-clock)
    # orders, but the scenario_instance field aligns the SAME instances. A naive
    # positional pairing would mis-pair; the keyed join must pair (i0,i0),(i1,i1).
    cell_a = _frame(
        [
            {"run_id": "zzz-a-i0", "scenario_instance": 0, "success_criterion_met": True},
            {"run_id": "aaa-a-i1", "scenario_instance": 1, "success_criterion_met": False},
        ]
    )
    cell_b = _frame(
        [
            {"run_id": "aaa-b-i0", "scenario_instance": 0, "success_criterion_met": True},
            {"run_id": "zzz-b-i1", "scenario_instance": 1, "success_criterion_met": False},
        ]
    )
    paired = analyse._pair_cells(cell_a, cell_b)
    # Aligned by instance: i0 -> (True, True), i1 -> (False, False).
    assert paired.outcomes_a == [True, False]
    assert paired.outcomes_b == [True, False]
    assert paired.n == 2


def test_pair_cells_drops_unmatched_and_na() -> None:
    # H2/BI-7: an instance present on only one side, or NA on one side, is NOT
    # paired. Only instances non-NA on BOTH sides contribute.
    cell_a = _frame(
        [
            {"run_id": "a-i0", "scenario_instance": 0, "success_criterion_met": True},
            {"run_id": "a-i1", "scenario_instance": 1, "success_criterion_met": None},
            {"run_id": "a-i2", "scenario_instance": 2, "success_criterion_met": True},
        ]
    )
    cell_b = _frame(
        [
            {"run_id": "b-i0", "scenario_instance": 0, "success_criterion_met": False},
            {"run_id": "b-i1", "scenario_instance": 1, "success_criterion_met": True},
            # no instance 2 on side B
        ]
    )
    paired = analyse._pair_cells(cell_a, cell_b)
    # Only instance 0 is non-NA on both sides AND present on both sides.
    assert paired.n == 1
    assert paired.outcomes_a == [True]
    assert paired.outcomes_b == [False]


def test_pair_cells_falls_back_to_run_id_suffix() -> None:
    # H2: with no explicit scenario_instance field, the run_id -NN suffix is the key.
    cell_a = _frame(
        [
            {"run_id": "fixture-rsl-s1-00", "scenario_instance": None, "success_criterion_met": True},
            {"run_id": "fixture-rsl-s1-01", "scenario_instance": None, "success_criterion_met": False},
        ]
    )
    cell_b = _frame(
        [
            {"run_id": "fixture-rslt-full-s1-00", "scenario_instance": None, "success_criterion_met": True},
            {"run_id": "fixture-rslt-full-s1-01", "scenario_instance": None, "success_criterion_met": True},
        ]
    )
    paired = analyse._pair_cells(cell_a, cell_b)
    assert paired.n == 2
    assert paired.outcomes_a == [True, False]
    assert paired.outcomes_b == [True, True]


def test_orphaned_runs_detects_off_grid() -> None:
    # M1: a run with a typo'd scenario (s9) is off-grid and must be reported, and
    # the on-grid reconciliation must show the delta.
    frame = pd.DataFrame(
        {
            "run_id": ["good-1", "typo-1"],
            "config": ["rsl", "rsl"],
            "scenario": ["s1", "s9"],
        }
    )
    orphans = analyse._orphaned_runs(frame)
    assert orphans == ["rsl/s9/typo-1"]
    assert analyse._cell_n_total(frame) == 1  # only the on-grid run counts


def test_orphaned_runs_empty_when_all_on_grid() -> None:
    frame = pd.DataFrame(
        {
            "run_id": ["a", "b"],
            "config": ["rsl", "f"],
            "scenario": ["s1", "benign"],
        }
    )
    assert analyse._orphaned_runs(frame) == []
    assert analyse._cell_n_total(frame) == 2
