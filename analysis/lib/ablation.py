"""The RSLT ablation L2 / Senior contribution with CIs (Story 5.5, AC3).

Per ATT&CK technique (per scenario), reports:

* the **L2 contribution** = DR(L1+L2) - DR(L1-only), and
* the **Senior contribution** = DR(full) - DR(L1+L2),

each with a confidence interval on the paired detection-rate DIFFERENCE (BI-9).
The significance test is the pre-registered ablation McNemar (lib/tests.py); this
module adds the effect-size CI.

The CI is a SEEDED bootstrap on the paired difference (BI-9, BI-13: the seed is
fixed so the smoke test is byte-deterministic). The bootstrap resamples the
paired (a_i, b_i) detection booleans with replacement and reports the empirical
percentile interval of the mean difference.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

# The fixed bootstrap seed (BI-13 determinism). The bootstrap RNG is seeded per
# call so the CI is byte-identical on every run.
BOOTSTRAP_SEED: int = 20260616
BOOTSTRAP_RESAMPLES: int = 2000
CI_LEVEL: float = 0.95


@dataclass(frozen=True)
class Contribution:
    """An ablation contribution: the DR difference plus its CI (AC3, BI-9)."""

    name: str
    scenario: str
    technique: str
    dr_high: Optional[float]
    dr_low: Optional[float]
    difference: Optional[float]
    ci_lower: Optional[float]
    ci_upper: Optional[float]
    n: int


def _detection_rate(outcomes: Sequence[bool]) -> Optional[float]:
    """Mean of a boolean outcome vector, or ``None`` when empty (BI-7)."""
    if not outcomes:
        return None
    return sum(1 for value in outcomes if value) / len(outcomes)


def bootstrap_difference_ci(
    high: Sequence[bool],
    low: Sequence[bool],
    seed: int = BOOTSTRAP_SEED,
    resamples: int = BOOTSTRAP_RESAMPLES,
    level: float = CI_LEVEL,
) -> Tuple[Optional[float], Optional[float]]:
    """Seeded-bootstrap percentile CI for DR(high) - DR(low) (BI-9, BI-13).

    The two vectors are PAIRED over the deterministic scenario-instance index
    (BI-8); resampling is over the paired index so the difference's dependence
    structure is preserved. Returns ``(None, None)`` when there is no pair.
    """
    n = min(len(high), len(low))
    if n < 1:
        return None, None
    pairs: List[Tuple[bool, bool]] = list(zip(list(high)[:n], list(low)[:n]))
    rng = random.Random(seed)
    diffs: List[float] = []
    for _ in range(resamples):
        sample = [pairs[rng.randrange(n)] for _ in range(n)]
        hi = sum(1 for h, _ in sample if h) / n
        lo = sum(1 for _, low_v in sample if low_v) / n
        diffs.append(hi - lo)
    diffs.sort()
    lower_index = int((1.0 - level) / 2.0 * resamples)
    upper_index = int((1.0 + level) / 2.0 * resamples) - 1
    upper_index = max(lower_index, min(upper_index, resamples - 1))
    return diffs[lower_index], diffs[upper_index]


def contribution(
    name: str,
    scenario: str,
    technique: str,
    high: Sequence[bool],
    low: Sequence[bool],
) -> Contribution:
    """Compute one ablation contribution = DR(high) - DR(low) with a CI (AC3).

    ``high`` and ``low`` are the paired detection booleans of the two arms over
    the deterministic scenario-instance index (BI-8). With no pair the
    contribution degrades to ``None`` values with ``n=0`` (BI-7), never a
    fabricated 0 contribution.
    """
    n = min(len(high), len(low))
    dr_high = _detection_rate(list(high)[:n]) if n else None
    dr_low = _detection_rate(list(low)[:n]) if n else None
    difference = None if dr_high is None or dr_low is None else dr_high - dr_low
    ci_lower, ci_upper = bootstrap_difference_ci(high, low)
    return Contribution(
        name=name,
        scenario=scenario,
        technique=technique,
        dr_high=dr_high,
        dr_low=dr_low,
        difference=difference,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        n=n,
    )
