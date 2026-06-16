"""Per-(config, scenario) metric aggregation (Story 5.5, AC1).

CONSUMES the Story-5.4 verdicts; it does NOT re-derive detection from raw
signal (BI-3). The metric -> artefact-field mapping (BI-3):

* Detection Rate = ``mean(success_criterion_met)`` per cell (consume the
  boolean as-is).
* MTTD = median + mean of ``measured_time_to_detect`` EXCLUDING the ``-1``
  never-detected sentinel.
* FPR (BI-5) = benign-sweep escalations/hour from ``fsm.jsonl`` ``after_state``
  past CLEAN over the wall-window; ``n/a`` when no benign runs are present.
* ATT&CK Cohen's kappa (BI-6) = predicted technique vs scenario ground-truth.
* The ``fsm_state_source`` honesty partition (BI-4): ``n_observed_transitions``
  vs ``n_detection_signal_only`` per cell.

Every aggregate reports ``n`` and degrades to ``n/a``/NaN when ``n == 0``
(BI-7); none is fabricated.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import pandas as pd

from analysis.lib import io
from analysis.lib.fsm import escalates_past_clean

# The Story-5.2 deterministic scenario -> ATT&CK technique ground-truth map
# (BI-6; traceability c3.9.2). The kappa ground-truth and the McNemar
# pairing-determinism both derive from this fixed map.
SCENARIO_GROUND_TRUTH: Dict[str, str] = {
    "s1": "T1611",
    "s2": "T1552",
    "s3": "T1613",
    "s4": "T1071",
    "s5": "T1496",
}

# The pre-registered per-cell sample sizes (preregistration.md Section 6): N=15
# for the main four-way cells, N=10 for the ablation cells. A cell with fewer
# than this is flagged ``underpowered: true`` (BI-7), never read as final.
MAIN_CELL_N: int = 15
ABLATION_CELL_N: int = 10
_ABLATION_CONFIGS: frozenset[str] = frozenset({"rslt-l1-only", "rslt-l1-l2"})

# The assessment payload fields searched for the predicted technique, in order
# of preference (OQ6): the explicit MITRE list first, then a single-technique
# field. Read from the committed audit.assessments.v2 shape
# (runs/example/assessments.jsonl); the example payload omits the technique, so
# kappa degrades to n/a honestly until the real LLM arms populate it.
_PREDICTED_TECHNIQUE_FIELDS: tuple[str, ...] = (
    "mitre_techniques",
    "mitre_technique",
    "technique",
    "threat_type",
)


@dataclass(frozen=True)
class DetectionRate:
    """Detection Rate for a cell: the mean over ``n`` contributing runs."""

    value: Optional[float]
    n: int


@dataclass(frozen=True)
class MTTD:
    """MTTD central tendency over DETECTED runs (sentinel excluded, BI-3)."""

    median: Optional[float]
    mean: Optional[float]
    n_detected: int
    n_total: int


@dataclass(frozen=True)
class FSMSourcePartition:
    """The fsm_state_source honesty partition for a cell (BI-4)."""

    n_observed_transitions: int
    n_detection_signal_only: int
    n_none: int


@dataclass(frozen=True)
class FPR:
    """False Positive Rate: benign-sweep escalations/hour (BI-5).

    ``value`` is ``None`` (``n/a``) when no benign runs are present (``n == 0``).
    """

    value: Optional[float]
    escalations: int
    window_hours: float
    n: int


@dataclass(frozen=True)
class Kappa:
    """ATT&CK Cohen's kappa for an LLM cell (BI-6).

    ``value`` is ``None`` (``n/a``) for non-LLM arms or empty assessments.
    """

    value: Optional[float]
    n: int


def detection_rate(cell: pd.DataFrame) -> DetectionRate:
    """Detection Rate = mean(success_criterion_met) over the cell's runs (BI-3).

    CONSUMES the Story-5.4 honest floor-aware verdict; does NOT re-derive. A
    cell with no usable verdicts reports ``value=None`` with ``n=0`` (BI-7).
    """
    column = cell["success_criterion_met"].dropna()
    n = int(column.shape[0])
    if n == 0:
        return DetectionRate(value=None, n=0)
    return DetectionRate(value=float(column.astype(bool).mean()), n=n)


def mttd(cell: pd.DataFrame) -> MTTD:
    """MTTD median + mean over DETECTED runs, EXCLUDING the ``-1`` sentinel (BI-3).

    The never-detected sentinel (``measured_time_to_detect == -1``) is a "never
    detected", not a 0/negative time, so it is dropped before the central
    tendency; ``n_total`` records all runs (so the exclusion is visible).
    """
    column = cell["measured_time_to_detect"].dropna()
    n_total = int(column.shape[0])
    detected = column[column != io.NEVER_DETECTED_SENTINEL]
    n_detected = int(detected.shape[0])
    if n_detected == 0:
        return MTTD(median=None, mean=None, n_detected=0, n_total=n_total)
    return MTTD(
        median=float(detected.astype(float).median()),
        mean=float(detected.astype(float).mean()),
        n_detected=n_detected,
        n_total=n_total,
    )


def fsm_source_partition(cell: pd.DataFrame) -> FSMSourcePartition:
    """Partition the cell by ``fsm_state_source`` (the honesty fence, BI-4).

    Reports ``n_detection_signal_only`` SEPARATELY so the thesis never reads a
    detection-signal floor as a confirmed high-state attainment.
    """
    source = cell["fsm_state_source"].fillna(io.FSM_SOURCE_NONE)
    return FSMSourcePartition(
        n_observed_transitions=int((source == io.FSM_SOURCE_OBSERVED).sum()),
        n_detection_signal_only=int((source == io.FSM_SOURCE_DETECTION_SIGNAL_ONLY).sum()),
        n_none=int((source == io.FSM_SOURCE_NONE).sum()),
    )


def _wall_window_hours(started_at: object, finished_at: object) -> Optional[float]:
    """Return the run wall-window in hours, or ``None`` when unparseable."""
    if not isinstance(started_at, str) or not isinstance(finished_at, str):
        return None
    start = pd.to_datetime(started_at, utc=True, errors="coerce")
    end = pd.to_datetime(finished_at, utc=True, errors="coerce")
    if pd.isna(start) or pd.isna(end):
        return None
    seconds = (end - start).total_seconds()
    if seconds <= 0:
        return None
    return float(seconds) / 3600.0


def fpr(cell: pd.DataFrame, runs_dir: str) -> FPR:
    """FPR = benign-sweep escalations/hour over the wall-window (BI-5).

    For each benign run, count the ``fsm.jsonl`` ``after_state`` values that
    escalate past CLEAN and divide by the summed wall-window hours. A cell with
    NO benign runs reports ``value=None`` (``n/a``) with ``n=0`` (degrade
    honestly, BI-7); FPR is NOT computed on the attack scenarios (an escalation
    there is a TRUE positive).
    """
    n = int(cell.shape[0])
    if n == 0:
        return FPR(value=None, escalations=0, window_hours=0.0, n=0)
    escalations = 0
    total_hours = 0.0
    for _, row in cell.iterrows():
        run_dir = Path(runs_dir) / str(row["run_id"])
        for after_state in io.fsm_after_states(run_dir):
            if escalates_past_clean(after_state):
                escalations += 1
        hours = _wall_window_hours(row["started_at"], row["finished_at"])
        if hours is not None:
            total_hours += hours
    if total_hours <= 0.0:
        return FPR(value=None, escalations=escalations, window_hours=0.0, n=n)
    return FPR(
        value=float(escalations) / total_hours,
        escalations=escalations,
        window_hours=total_hours,
        n=n,
    )


def _predicted_technique(payload: dict[str, object]) -> Optional[str]:
    """Extract the predicted ATT&CK technique from an assessment payload (OQ6).

    Scores the PRIMARY technique: a list field uses its first entry; a scalar
    field is used as-is. Returns ``None`` when no technique field is present (so
    the example/non-LLM payloads degrade to n/a honestly).
    """
    for field in _PREDICTED_TECHNIQUE_FIELDS:
        value = payload.get(field)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, list) and value:
            first = value[0]
            if isinstance(first, str) and first:
                return first
    return None


def cohens_kappa(predicted: List[str], truth: List[str]) -> Optional[float]:
    """Cohen's kappa over paired (predicted, truth) technique labels (BI-6).

    Hand-rolled from the agreement matrix (scipy/numpy primitives, BI-1) so the
    dependency tree stays small and the known-answer test pins the arithmetic.
    Returns ``None`` when there are no pairs. When the observed and expected
    agreement are both perfect (degenerate single-label case), kappa is defined
    as 1.0.
    """
    if not predicted or len(predicted) != len(truth):
        return None
    n = len(predicted)
    labels = sorted(set(predicted) | set(truth))
    index = {label: i for i, label in enumerate(labels)}
    size = len(labels)
    matrix = [[0 for _ in range(size)] for _ in range(size)]
    for pred, true in zip(predicted, truth):
        matrix[index[pred]][index[true]] += 1
    observed = sum(matrix[i][i] for i in range(size)) / n
    row_marginal = [sum(matrix[i][j] for j in range(size)) / n for i in range(size)]
    col_marginal = [sum(matrix[i][j] for i in range(size)) / n for j in range(size)]
    expected = sum(row_marginal[i] * col_marginal[i] for i in range(size))
    if math.isclose(expected, 1.0):
        return 1.0 if math.isclose(observed, 1.0) else 0.0
    return (observed - expected) / (1.0 - expected)


def attack_kappa(cell: pd.DataFrame, runs_dir: str, is_llm_config: bool) -> Kappa:
    """ATT&CK Cohen's kappa for a cell (BI-6).

    Reads the predicted technique from each run's ``assessments.jsonl`` and
    pairs it against the scenario ground-truth (``SCENARIO_GROUND_TRUTH``).
    Returns ``value=None`` (``n/a``) for non-LLM arms (F/RS) or when no
    assessment carries a technique (empty/constrained env), per BI-6.
    """
    if not is_llm_config:
        return Kappa(value=None, n=0)
    predicted: List[str] = []
    truth: List[str] = []
    for _, row in cell.iterrows():
        scenario = str(row["scenario"]).lower()
        ground_truth = SCENARIO_GROUND_TRUTH.get(scenario)
        if ground_truth is None:
            continue
        run_dir = Path(runs_dir) / str(row["run_id"])
        for payload in io.assessment_payloads(run_dir):
            technique = _predicted_technique(payload)
            if technique is None:
                continue
            predicted.append(technique)
            truth.append(ground_truth)
    n = len(predicted)
    if n == 0:
        return Kappa(value=None, n=0)
    return Kappa(value=cohens_kappa(predicted, truth), n=n)


def expected_cell_n(config: str) -> int:
    """The pre-registered N for a cell's config (BI-7): 10 ablation, else 15."""
    return ABLATION_CELL_N if config in _ABLATION_CONFIGS else MAIN_CELL_N
