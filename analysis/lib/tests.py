"""The pre-registered inferential tests (Story 5.5, AC2/AC3).

The test choices, alphas, and correction families are READ FROM the prereg (BI-2);
this module ENFORCES them, it does NOT re-choose. Each test emits a ``TestResult``
carrying its ``test_id``, p-value (or a ``status: skipped`` with ``n`` when
preconditions are unmet, BI-7), the corrected alpha, and the provenance triad
(attached by the caller).

The tests:

* McNemar's paired + Bonferroni for the four-way / ablation detection-rate
  comparisons, paired over the deterministic scenario-instance index (BI-8).
* Kruskal-Wallis omnibus + Dunn's-with-Holm for MTTD across configs per scenario.
* Wilcoxon signed-rank for the DFIR rubric per dimension (Story 5.7 scores;
  SKIP honestly with ``n`` when absent).
* ICC(2,k) for inter-rater reliability (Story 5.7).
* The one-sided Poisson rate test for the FPR equivalence/non-inferiority check
  against the 2-escalations/hour bound (prereg Section 5; BI-2).

Every test DEGRADES HONESTLY: insufficient data yields ``status="skipped
(insufficient data, n=...)"`` with ``p_value=None``, NEVER a fabricated p-value
(BI-7).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Mapping, Optional, Sequence

import pandas as pd
import pingouin as pg
import scikit_posthocs as sp
from scipy.stats import kruskal, poisson, wilcoxon
from statsmodels.stats.contingency_tables import mcnemar

# The pingouin ICC ``Type`` label for ICC(2,k): a two-way random-effects,
# absolute-agreement, average-of-k-raters model (pingouin spells it ``ICC(A,k)``,
# the conventional ICC(2,k), OQ2). Read by name so a pingouin column reorder
# cannot silently pick the wrong model.
_ICC_2K_TYPE: str = "ICC(A,k)"

# The FPR tolerance bound (preregistration.md Section 5 / RQ3): 2 unsolicited
# state escalations per hour on the benign sweep. The one-sided Poisson rate
# test checks each LLM-bearing config against this bound (BI-2).
FPR_TOLERANCE_PER_HOUR: float = 2.0


@dataclass(frozen=True)
class TestResult:
    """One inferential-test outcome row (AC2/AC3, BI-7/BI-10/BI-14)."""

    test_id: str
    test: str
    scenario: str
    comparison: str
    n: int
    p_value: Optional[float]
    statistic: Optional[float]
    corrected_alpha: Optional[float]
    status: str
    extra: dict[str, object] = field(default_factory=dict)


# The status strings (BI-7). A test with enough data is ``run``; an
# under-resourced test is ``skipped`` with its n, NEVER a fabricated p-value.
STATUS_RUN: str = "run"


def _skipped_status(n: int, reason: str = "insufficient data") -> str:
    """Build the honest skip status string (BI-7)."""
    return f"skipped ({reason}, n={n})"


def mcnemar_paired(
    test_id: str,
    scenario: str,
    comparison: str,
    outcomes_a: Sequence[bool],
    outcomes_b: Sequence[bool],
    corrected_alpha: Optional[float],
) -> TestResult:
    """McNemar's paired test over two binary outcome vectors (BI-8).

    The two vectors are PAIRED over the deterministic scenario-instance index
    (run i of config A paired with run i of config B over the same Story-5.2
    deterministic stimulus, BI-8/OQ7). The caller pre-pairs the two vectors by an
    inner join on the shared scenario-instance key, so they arrive equal-length and
    index-aligned and this function does not re-pair (a partial run-set drops the
    unmatched instances during the join, BI-7). With fewer than one pair, or with no
    discordant pairs (the contingency is degenerate), the test SKIPS honestly
    with its n (BI-7), never a fabricated p-value.

    Uses the exact binomial McNemar for small discordant counts and the
    chi-square approximation otherwise: we apply the conventional <= 25-discordant
    exact / chi-square-with-continuity-correction switch (passing ``exact=True``
    for <= 25 discordant pairs). This is our own defensible choice, NOT a
    statsmodels auto-heuristic (statsmodels has no such automatic switch; its
    ``mcnemar`` honours whatever ``exact`` flag we pass).
    """
    n = min(len(outcomes_a), len(outcomes_b))
    if n < 1:
        return _skip(test_id, "mcnemar", scenario, comparison, n, corrected_alpha)
    a = list(outcomes_a)[:n]
    b = list(outcomes_b)[:n]
    # Build the 2x2 paired contingency: rows = A outcome, cols = B outcome.
    table = [[0, 0], [0, 0]]
    for av, bv in zip(a, b):
        table[0 if av else 1][0 if bv else 1] += 1
    discordant = table[0][1] + table[1][0]
    if discordant == 0:
        # No disagreement between the paired configs: McNemar is undefined
        # (degenerate). Skip honestly rather than emit a fabricated p (BI-7).
        return _skip(
            test_id, "mcnemar", scenario, comparison, n, corrected_alpha,
            reason="no discordant pairs",
        )
    use_exact = discordant <= 25
    result = mcnemar(table, exact=use_exact, correction=not use_exact)
    statistic = None if result.statistic is None else float(result.statistic)
    return TestResult(
        test_id=test_id,
        test="mcnemar",
        scenario=scenario,
        comparison=comparison,
        n=n,
        p_value=float(result.pvalue),
        statistic=statistic,
        corrected_alpha=corrected_alpha,
        status=STATUS_RUN,
        extra={"discordant": discordant, "exact": use_exact},
    )


def kruskal_dunn_holm(
    test_id: str,
    scenario: str,
    groups: Mapping[str, Sequence[float]],
    corrected_alpha: Optional[float],
) -> TestResult:
    """Kruskal-Wallis omnibus + Dunn's-with-Holm for MTTD per scenario (BI-2).

    ``groups`` maps a config name to its MTTD samples (the sentinel already
    excluded by the caller). The omnibus needs at least two groups each with at
    least one observation, and at least one group with variation; otherwise the
    test SKIPS honestly with its n (BI-7). The Dunn pairwise matrix (Holm-
    adjusted) is attached in ``extra`` for the post-hoc detail.
    """
    usable = {name: list(values) for name, values in groups.items() if len(values) >= 1}
    n = sum(len(values) for values in usable.values())
    if len(usable) < 2 or n < 2:
        return _skip(test_id, "kruskal_wallis+dunn(holm)", scenario, "MTTD", n, corrected_alpha)
    samples = [usable[name] for name in sorted(usable)]
    # Kruskal-Wallis requires variation; an all-identical input raises. Guard it
    # and skip honestly rather than crash (BI-7).
    flat = [value for sample in samples for value in sample]
    if len(set(flat)) < 2:
        return _skip(
            test_id, "kruskal_wallis+dunn(holm)", scenario, "MTTD", n, corrected_alpha,
            reason="no variation",
        )
    statistic, p_value = kruskal(*samples)
    dunn = sp.posthoc_dunn(samples, p_adjust="holm")
    dunn.index = sorted(usable)
    dunn.columns = sorted(usable)
    return TestResult(
        test_id=test_id,
        test="kruskal_wallis+dunn(holm)",
        scenario=scenario,
        comparison="MTTD across configs",
        n=n,
        p_value=float(p_value),
        statistic=float(statistic),
        corrected_alpha=corrected_alpha,
        status=STATUS_RUN,
        extra={"dunn_holm": dunn.to_dict()},
    )


def wilcoxon_signed_rank(
    test_id: str,
    dimension: str,
    llm_scores: Sequence[float],
    templated_scores: Sequence[float],
    corrected_alpha: Optional[float],
) -> TestResult:
    """Wilcoxon signed-rank for a rubric dimension (BI-2).

    Runs on the Story-5.7 rubric scores (LLM vs templated, paired). When the
    scores have not been collected (the Story-5.7 input does not yet exist) the
    paired n is 0 and the test SKIPS honestly with ``n=0`` (BI-7); it is NEVER
    fabricated. Wilcoxon needs at least one non-zero paired difference.
    """
    n = min(len(llm_scores), len(templated_scores))
    if n < 1:
        return _skip(test_id, "wilcoxon", dimension, "LLM vs templated", n, corrected_alpha)
    a = list(llm_scores)[:n]
    b = list(templated_scores)[:n]
    differences = [x - y for x, y in zip(a, b)]
    if all(diff == 0 for diff in differences):
        return _skip(
            test_id, "wilcoxon", dimension, "LLM vs templated", n, corrected_alpha,
            reason="all paired differences zero",
        )
    statistic, p_value = wilcoxon(a, b)
    return TestResult(
        test_id=test_id,
        test="wilcoxon",
        scenario=dimension,
        comparison="LLM vs templated",
        n=n,
        p_value=float(p_value),
        statistic=float(statistic),
        corrected_alpha=corrected_alpha,
        status=STATUS_RUN,
    )


def icc_2k(
    test_id: str,
    ratings: pd.DataFrame,
    corrected_alpha: Optional[float],
) -> TestResult:
    """ICC(2,k) inter-rater reliability via pingouin (BI-2, OQ2).

    ``ratings`` is a long-form frame with columns ``target`` (the rated unit),
    ``rater``, and ``score``. When the Story-5.7 ratings have not been collected
    (empty frame) the test SKIPS honestly with ``n=0`` (BI-7). ICC needs at
    least two targets and two raters; otherwise it SKIPS honestly. The 95% CI is
    attached in ``extra``.
    """
    n = int(ratings.shape[0])
    required = {"target", "rater", "score"}
    if n == 0 or not required.issubset(ratings.columns):
        return _skip(test_id, "icc2k", "rater-agreement", "inter-rater", n, corrected_alpha)
    if ratings["target"].nunique() < 2 or ratings["rater"].nunique() < 2:
        return _skip(
            test_id, "icc2k", "rater-agreement", "inter-rater", n, corrected_alpha,
            reason="needs >=2 targets and >=2 raters",
        )
    table = pg.intraclass_corr(
        data=ratings, targets="target", raters="rater", ratings="score"
    )
    row = table.loc[table["Type"] == _ICC_2K_TYPE]
    if row.empty:
        return _skip(
            test_id, "icc2k", "rater-agreement", "inter-rater", n, corrected_alpha,
            reason="ICC(2,k) row absent",
        )
    icc_value = float(row["ICC"].iloc[0])
    ci = row["CI95"].iloc[0]
    return TestResult(
        test_id=test_id,
        test="icc2k",
        scenario="rater-agreement",
        comparison="inter-rater",
        n=n,
        p_value=None,
        statistic=icc_value,
        corrected_alpha=corrected_alpha,
        status=STATUS_RUN,
        extra={"icc2k": icc_value, "ci95": list(ci)},
    )


def fpr_poisson_one_sided(
    test_id: str,
    config: str,
    escalations: int,
    window_hours: float,
    corrected_alpha: Optional[float],
    bound_per_hour: float = FPR_TOLERANCE_PER_HOUR,
) -> TestResult:
    """One-sided Poisson rate test for the FPR equivalence check (BI-2).

    A TOST-style non-inferiority check against the ``bound_per_hour`` tolerance
    (the prereg's RQ3 framing): under H0 the rate is AT OR ABOVE the bound; the
    one-sided p is the probability, under the bound's expected count, of
    observing AT MOST the observed escalations (a left-tail Poisson CDF).
    Rejecting H0 (small p) supports "the FPR is below the bound".

    When no benign window exists (``window_hours <= 0``) the test SKIPS honestly
    with ``n=0`` (BI-7); the FPR equivalence cannot be evaluated without a
    benign sweep.
    """
    if window_hours <= 0.0:
        return _skip(test_id, "poisson_one_sided", "benign-sweep", config, 0, corrected_alpha)
    expected = bound_per_hour * window_hours
    # Left-tail CDF: P(X <= observed | lambda = bound * hours). A low value
    # means the observed escalation count is improbably low for a rate at the
    # bound, i.e. evidence the true rate is below the bound (non-inferiority).
    p_value = float(poisson.cdf(escalations, expected))
    return TestResult(
        test_id=test_id,
        test="poisson_one_sided",
        scenario="benign-sweep",
        comparison=f"{config} vs {bound_per_hour}/hour bound",
        n=escalations,
        p_value=p_value,
        statistic=float(escalations) / window_hours,
        corrected_alpha=corrected_alpha,
        status=STATUS_RUN,
        extra={
            "observed_rate_per_hour": float(escalations) / window_hours,
            "bound_per_hour": bound_per_hour,
            "window_hours": window_hours,
        },
    )


def bonferroni_correct(p_values: Sequence[float]) -> List[float]:
    """Bonferroni-adjust a family of p-values (clamped to <= 1.0).

    A thin, testable wrapper (statsmodels' ``multipletests`` is used at the
    call-site for the full family adjustment; this helper exists for the
    known-answer unit test of the correction arithmetic, BI-12).
    """
    m = len(p_values)
    if m == 0:
        return []
    return [min(1.0, p * m) for p in p_values]


def _skip(
    test_id: str,
    test: str,
    scenario: str,
    comparison: str,
    n: int,
    corrected_alpha: Optional[float],
    reason: str = "insufficient data",
) -> TestResult:
    """Build a skipped TestResult (BI-7): honest n, no fabricated p-value."""
    return TestResult(
        test_id=test_id,
        test=test,
        scenario=scenario,
        comparison=comparison,
        n=n,
        p_value=None,
        statistic=None,
        corrected_alpha=corrected_alpha,
        status=_skipped_status(n, reason),
    )
