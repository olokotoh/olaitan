"""Known-answer unit tests for the metric helpers (Story 5.5, AC5/BI-12).

Each test pins a HAND-COMPUTED answer so a math-breaking refactor fails (BI-12).
"""

from __future__ import annotations

import pandas as pd

from analysis.lib import io, metrics


def _cell(success: list[object], ttd: list[object], source: list[str]) -> pd.DataFrame:
    return pd.DataFrame(
        {
            "run_id": [f"r{i}" for i in range(len(success))],
            "config": ["rsl"] * len(success),
            "scenario": ["s1"] * len(success),
            "success_criterion_met": pd.Series(success, dtype="boolean"),
            "measured_time_to_detect": pd.Series(ttd, dtype="Int64"),
            "fsm_state_source": source,
            "manifest_sha256": ["abc"] * len(success),
            "started_at": ["2026-06-15T09:30:00Z"] * len(success),
            "finished_at": ["2026-06-15T09:31:00Z"] * len(success),
        }
    )


def test_detection_rate_known_answer() -> None:
    # 3 of 4 detected -> 0.75 (consume success_criterion_met as-is, BI-3).
    cell = _cell([True, True, True, False], [10, 20, 30, -1], ["observed_transitions"] * 4)
    result = metrics.detection_rate(cell)
    assert result.value == 0.75
    assert result.n == 4


def test_detection_rate_empty_is_na() -> None:
    cell = _cell([], [], [])
    result = metrics.detection_rate(cell)
    assert result.value is None
    assert result.n == 0


def test_mttd_excludes_never_detected_sentinel() -> None:
    # Values 10, 20, 30, and a -1 sentinel: median/mean over {10,20,30} only (BI-3).
    cell = _cell([True, True, True, False], [10, 20, 30, io.NEVER_DETECTED_SENTINEL], ["none"] * 4)
    result = metrics.mttd(cell)
    assert result.median == 20.0
    assert result.mean == 20.0
    assert result.n_detected == 3
    assert result.n_total == 4


def test_mttd_all_never_detected_is_na() -> None:
    cell = _cell([False], [io.NEVER_DETECTED_SENTINEL], ["none"])
    result = metrics.mttd(cell)
    assert result.median is None
    assert result.mean is None
    assert result.n_detected == 0


def test_fsm_source_partition_counts() -> None:
    # The honesty fence (BI-4): detection_signal_only counted SEPARATELY.
    cell = _cell(
        [True, True, False],
        [10, 20, -1],
        ["observed_transitions", "detection_signal_only", "none"],
    )
    partition = metrics.fsm_source_partition(cell)
    assert partition.n_observed_transitions == 1
    assert partition.n_detection_signal_only == 1
    assert partition.n_none == 1


def test_cohens_kappa_known_answer() -> None:
    # Textbook 2-label case: predicted/truth with partial agreement.
    # 50 A/A, 0 A/B, 10 B/A, 40 B/B over n=100.
    predicted = ["A"] * 50 + ["B"] * 10 + ["B"] * 40
    truth = ["A"] * 50 + ["A"] * 10 + ["B"] * 40
    # po = 90/100 = 0.9; pe = (60/100 * 50/100) + (40/100 * 50/100) = 0.3 + 0.2 = 0.5
    # kappa = (0.9 - 0.5) / (1 - 0.5) = 0.8
    value = metrics.cohens_kappa(predicted, truth)
    assert value is not None
    assert abs(value - 0.8) < 1e-9


def test_cohens_kappa_perfect_single_label() -> None:
    value = metrics.cohens_kappa(["T1611"] * 4, ["T1611"] * 4)
    assert value == 1.0


def test_cohens_kappa_empty_is_none() -> None:
    assert metrics.cohens_kappa([], []) is None


def test_attack_kappa_na_for_non_llm() -> None:
    cell = _cell([True], [10], ["observed_transitions"])
    result = metrics.attack_kappa(cell, ".", is_llm_config=False)
    assert result.value is None
    assert result.n == 0


def test_expected_cell_n() -> None:
    assert metrics.expected_cell_n("rslt-full") == 15
    assert metrics.expected_cell_n("rslt-l1-only") == 10
    assert metrics.expected_cell_n("rslt-l1-l2") == 10
