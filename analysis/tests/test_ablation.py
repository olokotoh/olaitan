"""Known-answer unit tests for the ablation contribution + CI (AC3/BI-9)."""

from __future__ import annotations

from analysis.lib import ablation


def test_contribution_known_difference() -> None:
    # DR(high) = 3/4 = 0.75; DR(low) = 1/4 = 0.25; difference = 0.5.
    high = [True, True, True, False]
    low = [True, False, False, False]
    result = ablation.contribution("l2_contribution", "s1", "T1611", high, low)
    assert result.dr_high == 0.75
    assert result.dr_low == 0.25
    assert result.difference == 0.5
    assert result.n == 4
    assert result.ci_lower is not None
    assert result.ci_upper is not None
    # The bootstrap CI must bracket the point estimate.
    assert result.ci_lower <= 0.5 <= result.ci_upper


def test_contribution_no_pairs_is_na() -> None:
    result = ablation.contribution("l2_contribution", "s1", "T1611", [], [])
    assert result.difference is None
    assert result.ci_lower is None
    assert result.n == 0


def test_bootstrap_ci_deterministic() -> None:
    # Seeded bootstrap (BI-13): identical inputs -> identical CI every time.
    high = [True, True, True, False, True]
    low = [False, False, True, False, False]
    first = ablation.bootstrap_difference_ci(high, low)
    second = ablation.bootstrap_difference_ci(high, low)
    assert first == second


def test_bootstrap_ci_zero_width_for_identical() -> None:
    # Identical arms -> a difference of 0 with a CI pinned at 0.
    high = [True, True, False, False]
    low = [True, True, False, False]
    lower, upper = ablation.bootstrap_difference_ci(high, low)
    assert lower == 0.0
    assert upper == 0.0
