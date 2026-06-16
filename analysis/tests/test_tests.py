"""Known-answer unit tests for the inferential-test helpers (AC5/BI-12).

Each test pins a textbook / hand-computed answer so a refactor that breaks the
statistics fails (BI-12), and asserts the honest-degradation path (BI-7).
"""

from __future__ import annotations

import math

import pandas as pd

from analysis.lib import tests


def test_mcnemar_known_answer() -> None:
    # b/c outcomes: A detects, B misses for some; classic discordant table.
    # outcomes_a = [T,T,T,T,T,F,F,F,F,F]; outcomes_b = [F,F,F,F,F,F,F,F,F,F]
    # discordant: a=T,b=F count = 5 (b cell), a=F,b=T = 0 (c cell).
    a = [True, True, True, True, True, False, False, False, False, False]
    b = [False] * 10
    result = tests.mcnemar_paired("RQ1-DR-MCNEMAR", "s1", "a vs b", a, b, 0.01)
    assert result.status == tests.STATUS_RUN
    assert result.p_value is not None
    # 5 discordant all in one cell -> exact binomial p = 2 * 0.5^5 = 0.0625.
    assert abs(result.p_value - 0.0625) < 1e-9


def test_mcnemar_no_discordant_skips() -> None:
    a = [True, True, False, False]
    b = [True, True, False, False]
    result = tests.mcnemar_paired("RQ1-DR-MCNEMAR", "s1", "a vs b", a, b, 0.01)
    assert "skipped" in result.status
    assert result.p_value is None
    assert result.n == 4


def test_mcnemar_no_pairs_skips() -> None:
    result = tests.mcnemar_paired("RQ1-DR-MCNEMAR", "s1", "a vs b", [], [], 0.01)
    assert "skipped" in result.status
    assert result.n == 0


def test_kruskal_dunn_holm_runs() -> None:
    groups = {"f": [40.0, 41.0, 42.0], "rsl": [18.0, 19.0, 20.0]}
    result = tests.kruskal_dunn_holm("RQ2-MTTD-KW-DUNN-HOLM", "s1", groups, None)
    assert result.status == tests.STATUS_RUN
    assert result.p_value is not None
    assert "dunn_holm" in result.extra


def test_kruskal_single_group_skips() -> None:
    result = tests.kruskal_dunn_holm("RQ2-MTTD-KW-DUNN-HOLM", "s1", {"f": [1.0, 2.0]}, None)
    assert "skipped" in result.status


def test_kruskal_no_variation_skips() -> None:
    groups = {"f": [5.0, 5.0], "rsl": [5.0, 5.0]}
    result = tests.kruskal_dunn_holm("RQ2-MTTD-KW-DUNN-HOLM", "s1", groups, None)
    assert "skipped" in result.status


def test_wilcoxon_runs() -> None:
    llm = [5.0, 4.0, 5.0, 5.0, 4.0]
    templated = [3.0, 2.0, 3.0, 4.0, 2.0]
    result = tests.wilcoxon_signed_rank("RQ5-RUBRIC-WILCOXON-CLARITY", "clarity", llm, templated, 0.01)
    assert result.status == tests.STATUS_RUN
    assert result.p_value is not None


def test_wilcoxon_no_scores_skips() -> None:
    result = tests.wilcoxon_signed_rank("RQ5-RUBRIC-WILCOXON-CLARITY", "clarity", [], [], 0.01)
    assert result.n == 0
    assert "skipped" in result.status


def test_icc_2k_runs() -> None:
    ratings = pd.DataFrame(
        {
            "target": [1, 1, 2, 2, 3, 3, 4, 4],
            "rater": ["a", "b"] * 4,
            "score": [9, 8, 3, 4, 5, 6, 7, 9],
        }
    )
    result = tests.icc_2k("RQ5-ICC", ratings, None)
    assert result.status == tests.STATUS_RUN
    assert result.statistic is not None
    assert "ci95" in result.extra


def test_icc_2k_empty_skips() -> None:
    ratings = pd.DataFrame(columns=["target", "rater", "score"])
    result = tests.icc_2k("RQ5-ICC", ratings, None)
    assert result.n == 0
    assert "skipped" in result.status


def test_fpr_poisson_one_sided_known_answer() -> None:
    # 1 escalation over a 1-hour window, bound 2/hour -> lambda = 2.
    # P(X <= 1 | lambda=2) = e^-2 (1 + 2) = 0.4060058...
    result = tests.fpr_poisson_one_sided("RQ3-FPR-POISSON", "rsl", 1, 1.0, 0.025)
    assert result.status == tests.STATUS_RUN
    assert result.p_value is not None
    assert abs(result.p_value - math.exp(-2.0) * 3.0) < 1e-6


def test_fpr_poisson_no_window_skips() -> None:
    result = tests.fpr_poisson_one_sided("RQ3-FPR-POISSON", "rsl", 0, 0.0, 0.025)
    assert result.n == 0
    assert "skipped" in result.status


def test_bonferroni_correct_known_answer() -> None:
    assert tests.bonferroni_correct([0.01, 0.02, 0.5]) == [0.03, 0.06, 1.0]
    assert tests.bonferroni_correct([]) == []
