"""Olaitan statistical analysis pipeline (Story 5.5).

The FIRST Python in an otherwise-Go repo: a pure-Python, NO-CLUSTER, OFFLINE
pipeline that CONSUMES the MERGED Story-5.4 per-run artefacts under
``runs/<run_id>/`` and produces, per ``(config, scenario)`` cell, Detection Rate
/ MTTD / FPR / ATT&CK Cohen's kappa (AC1), runs the pre-registered inferential
tests READ FROM ``analysis/preregistration.md`` (AC2/BI-2), reports the RSLT
ablation L2/Senior contributions with CIs (AC3), attaches the
manifest_hash/n/test provenance triad to every row (AC4/BI-10), and stamps any
non-registry test ``exploratory: true`` (BI-14).

It DEGRADES HONESTLY on the missing/partial run-set (the 400 runs do not exist
yet, BI-7): every cell reports ``n``; ``n == 0`` yields ``n/a``/NaN, never a
fabricated number; ``n`` below the pre-registered N flags ``underpowered:
true``; a test whose preconditions are unmet is ``skipped`` with its n, not a
crash and not a fabricated p-value.

Usage::

    python analysis/analyse.py --runs runs/ --output analysis/output/

Determinism (BI-13): no wall-clock in the output, sorted iteration over
runs/cells/tests, seeded RNG for the bootstrap CI.
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence

# Make ``python analysis/analyse.py`` work standalone: the helper lib imports as
# the ``analysis.*`` package, so the repo root (this file's parent's parent)
# must be on sys.path. pytest/CI already run from the repo root, but a direct
# invocation (``make analysis`` / the runbook command) does not, so add it here.
_REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import pandas as pd  # noqa: E402  (after the sys.path bootstrap above)

from analysis.lib import ablation, io, metrics, provenance, tests  # noqa: E402
from analysis.lib.prereg import Registry, parse_registry  # noqa: E402

# The four primary configs (Story 5.3 arms) + the two ablation arms. Sorted
# iteration over these keys pins the cell order (BI-13).
PRIMARY_CONFIGS: List[str] = ["f", "rs", "rsl", "rslt-full"]
ABLATION_CONFIGS: List[str] = ["rslt-l1-only", "rslt-l1-l2"]
# The configs that carry an LLM analyst chain (assessments -> ATT&CK kappa, BI-6).
LLM_CONFIGS: frozenset[str] = frozenset({"rsl", "rslt-full", "rslt-l1-only", "rslt-l1-l2"})
SCENARIOS: List[str] = ["s1", "s2", "s3", "s4", "s5"]

# The confirmatory ablation test_ids (preregistration.md registry, BI-2).
_ABL_L2_TEST_ID: str = "RQ4-ABL-L2-MCNEMAR"
_ABL_SENIOR_TEST_ID: str = "RQ4-ABL-SENIOR-MCNEMAR"
_DR_MCNEMAR_TEST_ID: str = "RQ1-DR-MCNEMAR"
_MTTD_TEST_ID: str = "RQ2-MTTD-KW-DUNN-HOLM"
_FPR_TEST_ID: str = "RQ3-FPR-POISSON"

# The default prereg path relative to the repo root (Story 5.8 seeded it here).
DEFAULT_PREREG: str = "analysis/preregistration.md"

# The CSV column order (BI-10/BI-14): every row carries the provenance triad +
# the honesty flags + the exploratory flag. Fixed so the byte-deterministic
# golden never reorders columns (BI-13).
_CSV_COLUMNS: List[str] = [
    "section",
    "config",
    "scenario",
    "metric_or_test",
    "value",
    "n",
    "manifest_hash",
    "mixed_manifest",
    "test",
    "test_id",
    "alpha_corrected",
    "p_value",
    "status",
    "fsm_source_partition",
    "underpowered",
    "exploratory",
]


@dataclass
class OutputRow:
    """One CSV/Markdown row (a metric cell or a test result).

    ``section`` is ``metrics``, ``confirmatory``, ``exploratory``, or
    ``ablation``. The provenance triad + honesty flags are columns on every row
    (BI-10, BI-7, BI-14).
    """

    section: str
    config: str
    scenario: str
    metric_or_test: str
    value: object
    n: int
    manifest_hash: str
    mixed_manifest: bool
    test: str
    test_id: str
    alpha_corrected: Optional[float]
    p_value: Optional[float]
    status: str
    fsm_source_partition: str
    underpowered: bool
    exploratory: bool

    def as_csv(self) -> Dict[str, object]:
        """Project onto the fixed CSV column set (BI-13 deterministic order)."""
        return {
            "section": self.section,
            "config": self.config,
            "scenario": self.scenario,
            "metric_or_test": self.metric_or_test,
            "value": _format_value(self.value),
            "n": self.n,
            "manifest_hash": self.manifest_hash,
            "mixed_manifest": self.mixed_manifest,
            "test": self.test,
            "test_id": self.test_id,
            "alpha_corrected": _format_value(self.alpha_corrected),
            "p_value": _format_value(self.p_value),
            "status": self.status,
            "fsm_source_partition": self.fsm_source_partition,
            "underpowered": self.underpowered,
            "exploratory": self.exploratory,
        }


@dataclass
class PipelineResult:
    """The composed pipeline output: the rows + the run-set provenance header."""

    rows: List[OutputRow]
    header: Dict[str, object]
    distinct_manifests: List[str] = field(default_factory=list)


# The "n/a" rendering for an absent metric (BI-7: never a fabricated 0).
_NA: str = "n/a"


# Below this magnitude a fixed-6dp render collapses to ``0.000000`` and loses a
# genuinely tiny (but non-zero) p-value, so we switch to scientific notation
# (L3). A p like 4e-7 must not render byte-identical to a true zero.
_SMALL_MAGNITUDE: float = 1e-4


def _format_value(value: object) -> object:
    """Render a value deterministically (BI-13).

    Floats are formatted to a fixed precision so the byte-deterministic golden
    never drifts on platform float repr; ``None`` becomes the honest ``n/a``
    (BI-7); everything else passes through. A very small non-zero magnitude (e.g.
    a p-value like 4e-7) is rendered with ``%.3g`` scientific notation so it does
    NOT collapse to ``0.000000`` and read as a true zero (L3). ``-0.0`` is
    normalised to ``0.0`` first so the sign bit never makes the golden drift.
    """
    if value is None:
        return _NA
    if isinstance(value, float):
        if value != value:  # NaN guard (an honest gap, BI-7)
            return _NA
        if value == 0.0:  # normalise -0.0 -> 0.0 (sign bit, L3)
            value = 0.0
        if 0.0 < abs(value) < _SMALL_MAGNITUDE:
            return f"{value:.3g}"
        return f"{value:.6f}"
    return value


def _cell(frame: pd.DataFrame, config: str, scenario: str) -> pd.DataFrame:
    """The ``(config, scenario)`` sub-frame, sorted by run_id (BI-13)."""
    cell = frame[(frame["config"] == config) & (frame["scenario"] == scenario)]
    return cell.sort_values(by="run_id", kind="mergesort").reset_index(drop=True)


def _partition_str(partition: metrics.FSMSourcePartition) -> str:
    """Render the fsm_state_source honesty partition compactly (BI-4)."""
    return (
        f"observed={partition.n_observed_transitions};"
        f"detection_signal_only={partition.n_detection_signal_only};"
        f"none={partition.n_none}"
    )


def build_metric_rows(run_set: io.RunSet) -> List[OutputRow]:
    """Build the per-cell metric rows for every (config, scenario) (AC1)."""
    rows: List[OutputRow] = []
    frame = run_set.frame
    for config in PRIMARY_CONFIGS + ABLATION_CONFIGS:
        for scenario in SCENARIOS:
            cell = _cell(frame, config, scenario)
            manifest_hash, mixed = provenance.cell_manifest(cell)
            partition = metrics.fsm_source_partition(cell)
            partition_str = _partition_str(partition)
            expected_n = metrics.expected_cell_n(config)
            dr = metrics.detection_rate(cell)
            underpowered = 0 < dr.n < expected_n
            rows.append(
                OutputRow(
                    section="metrics",
                    config=config,
                    scenario=scenario,
                    metric_or_test="detection_rate",
                    value=dr.value,
                    n=dr.n,
                    manifest_hash=manifest_hash,
                    mixed_manifest=mixed,
                    test=provenance.DESCRIPTIVE,
                    test_id="",
                    alpha_corrected=None,
                    p_value=None,
                    status=tests.STATUS_RUN if dr.n > 0 else "n/a",
                    fsm_source_partition=partition_str,
                    underpowered=underpowered,
                    exploratory=False,
                )
            )
            mt = metrics.mttd(cell)
            rows.append(
                OutputRow(
                    section="metrics",
                    config=config,
                    scenario=scenario,
                    metric_or_test="mttd_median",
                    value=mt.median,
                    n=mt.n_detected,
                    manifest_hash=manifest_hash,
                    mixed_manifest=mixed,
                    test=provenance.DESCRIPTIVE,
                    test_id="",
                    alpha_corrected=None,
                    p_value=None,
                    status=tests.STATUS_RUN if mt.n_detected > 0 else "n/a",
                    fsm_source_partition=partition_str,
                    underpowered=0 < mt.n_detected < expected_n,
                    exploratory=False,
                )
            )
            rows.append(
                OutputRow(
                    section="metrics",
                    config=config,
                    scenario=scenario,
                    metric_or_test="mttd_mean",
                    value=mt.mean,
                    n=mt.n_detected,
                    manifest_hash=manifest_hash,
                    mixed_manifest=mixed,
                    test=provenance.DESCRIPTIVE,
                    test_id="",
                    alpha_corrected=None,
                    p_value=None,
                    status=tests.STATUS_RUN if mt.n_detected > 0 else "n/a",
                    fsm_source_partition=partition_str,
                    underpowered=0 < mt.n_detected < expected_n,
                    exploratory=False,
                )
            )
    # ATT&CK kappa is emitted PER CONFIG (pooled across S1-S5), not per cell: a
    # single-scenario cell has a constant ground-truth label, so its kappa is
    # structurally degenerate (M3). The prereg's RQ1-ATTACK-KAPPA estimates
    # agreement ACROSS the five techniques. Emitted after the per-cell rows so the
    # config grouping reads cleanly; scenario="all" marks the pooled scope.
    for config in PRIMARY_CONFIGS + ABLATION_CONFIGS:
        config_frame = frame[frame["config"] == config]
        manifest_hash, mixed = provenance.cell_manifest(config_frame)
        kappa = metrics.attack_kappa(config_frame, run_set.runs_dir, config in LLM_CONFIGS)
        rows.append(
            OutputRow(
                section="metrics",
                config=config,
                scenario="all",
                metric_or_test="attack_kappa_pooled",
                value=kappa.value,
                n=kappa.n,
                manifest_hash=manifest_hash,
                mixed_manifest=mixed,
                test=provenance.DESCRIPTIVE,
                test_id="",
                alpha_corrected=None,
                p_value=None,
                status=tests.STATUS_RUN if kappa.n > 0 else "n/a",
                fsm_source_partition="",
                underpowered=False,
                exploratory=False,
            )
        )
    return rows


def _benign_cell(frame: pd.DataFrame, config: str) -> pd.DataFrame:
    """The benign-sweep sub-frame for a config (BI-5, OQ5).

    The benign sweep is identified by the reserved ``benign`` scenario id (the
    convention Story 5.6 populates). Until benign runs exist this frame is empty
    and FPR degrades to ``n/a`` (BI-5/BI-7).
    """
    cell = frame[(frame["config"] == config) & (frame["scenario"] == "benign")]
    return cell.sort_values(by="run_id", kind="mergesort").reset_index(drop=True)


def build_fpr_rows(run_set: io.RunSet, registry: Registry) -> List[OutputRow]:
    """FPR metric rows + the one-sided Poisson equivalence test rows (BI-5/BI-2).

    FPR is the benign-sweep escalations/hour; the confirmatory test is the
    one-sided Poisson rate test against the 2/hour bound for the LLM-bearing
    configs (RSL, RSLT-full). Both degrade to ``n/a``/skipped honestly when no
    benign runs are present (BI-7).
    """
    rows: List[OutputRow] = []
    frame = run_set.frame
    fpr_test_alpha = registry.corrected_alpha(_FPR_TEST_ID)
    for config in PRIMARY_CONFIGS:
        cell = _benign_cell(frame, config)
        manifest_hash, mixed = provenance.cell_manifest(cell)
        fpr = metrics.fpr(cell, run_set.runs_dir)
        rows.append(
            OutputRow(
                section="metrics",
                config=config,
                scenario="benign",
                metric_or_test="fpr_per_hour",
                value=fpr.value,
                n=fpr.n,
                manifest_hash=manifest_hash,
                mixed_manifest=mixed,
                test=provenance.DESCRIPTIVE,
                test_id="",
                alpha_corrected=None,
                p_value=None,
                status=tests.STATUS_RUN if fpr.n > 0 else "n/a",
                fsm_source_partition="",
                underpowered=False,
                exploratory=False,
            )
        )
        # The confirmatory one-sided Poisson test is on the LLM-bearing configs
        # only (the prereg's RQ3 family = RSL, RSLT-full; F/RS descriptive, BI-2).
        if config in {"rsl", "rslt-full"}:
            result = tests.fpr_poisson_one_sided(
                test_id=_FPR_TEST_ID,
                config=config,
                escalations=fpr.escalations,
                window_hours=fpr.window_hours,
                corrected_alpha=fpr_test_alpha,
            )
            rows.append(_test_row(result, config, registry, contributing=cell))
    return rows


@dataclass
class _PairedCell:
    """Two configs' verdicts aligned on the SHARED scenario-instance key (H2/BI-8).

    ``outcomes_a`` / ``outcomes_b`` are the success-criterion booleans for the
    paired instances ONLY (an instance present and non-NA on BOTH sides), in
    sorted-key order. ``frame`` is the sub-frame of the contributing runs from
    both configs, threaded into the provenance triad (M4). ``n`` is the paired n.
    """

    outcomes_a: List[bool]
    outcomes_b: List[bool]
    frame: pd.DataFrame
    n: int


def _keyed_verdicts(cell: pd.DataFrame) -> Dict[str, "tuple[bool, pd.Series]"]:
    """Map each run's scenario-instance key -> (verdict, its frame row) for a cell.

    Keyed on the SHARED scenario-instance index (H2/BI-8): the explicit
    ``scenario_instance`` field, else the ``run_id`` ``-NN`` suffix (see
    ``io.scenario_instance_key``). A run with an NA verdict or no derivable key is
    dropped (it cannot enter a pair honestly, BI-7). On the (degenerate) chance two
    runs of one config share a key, the run_id-sorted-last one wins deterministically.
    """
    result: Dict[str, "tuple[bool, pd.Series]"] = {}
    ordered = cell.sort_values(by="run_id", kind="mergesort")
    for _, row in ordered.iterrows():
        verdict = row["success_criterion_met"]
        if pd.isna(verdict):
            continue
        instance = row["scenario_instance"] if "scenario_instance" in row else None
        key = io.scenario_instance_key(row["run_id"], instance)
        if key is None:
            continue
        result[key] = (bool(verdict), row)
    return result


def _pair_cells(cell_a: pd.DataFrame, cell_b: pd.DataFrame) -> _PairedCell:
    """Inner-join two cells on the shared scenario-instance key (H2/BI-8).

    Replaces the old positional ``[:min(n_a, n_b)]`` truncation, which mis-paired
    whenever a verdict was NA AND, because the real ``run_id`` is timestamp-first,
    even with no NAs (positional order is wall-clock order, not instance order). A
    pair is included only when BOTH configs have a non-NA verdict for the SAME
    instance key; the verdicts are emitted in sorted-key order so the pairing is
    deterministic (BI-13). The contributing-run sub-frame is assembled for the
    provenance triad (M4).
    """
    verdicts_a = _keyed_verdicts(cell_a)
    verdicts_b = _keyed_verdicts(cell_b)
    shared = sorted(set(verdicts_a) & set(verdicts_b))
    outcomes_a = [verdicts_a[key][0] for key in shared]
    outcomes_b = [verdicts_b[key][0] for key in shared]
    contributing_rows = [verdicts_a[key][1] for key in shared]
    contributing_rows += [verdicts_b[key][1] for key in shared]
    if contributing_rows:
        frame = pd.DataFrame(contributing_rows)
    else:
        frame = cell_a.iloc[0:0]
    return _PairedCell(outcomes_a=outcomes_a, outcomes_b=outcomes_b, frame=frame, n=len(shared))


def build_dr_mcnemar_rows(run_set: io.RunSet, registry: Registry) -> List[OutputRow]:
    """McNemar four-way detection-rate rows: RSLT-full vs F/RS/RSL per scenario.

    Paired over the deterministic scenario-instance index (BI-8). The family is
    the 5 per-scenario comparisons within a config-pair contrast (corrected
    0.01, BI-2); the corrected alpha is read from the registry.
    """
    rows: List[OutputRow] = []
    frame = run_set.frame
    alpha = registry.corrected_alpha(_DR_MCNEMAR_TEST_ID)
    for reference in ("f", "rs", "rsl"):
        for scenario in SCENARIOS:
            paired = _pair_cells(_cell(frame, "rslt-full", scenario), _cell(frame, reference, scenario))
            result = tests.mcnemar_paired(
                test_id=_DR_MCNEMAR_TEST_ID,
                scenario=scenario,
                comparison=f"rslt-full vs {reference}",
                outcomes_a=paired.outcomes_a,
                outcomes_b=paired.outcomes_b,
                corrected_alpha=alpha,
            )
            rows.append(_test_row(result, "rslt-full", registry, contributing=paired.frame))
    return rows


def build_mttd_rows(run_set: io.RunSet, registry: Registry) -> List[OutputRow]:
    """Kruskal-Wallis + Dunn(Holm) MTTD rows across configs per scenario (BI-2)."""
    rows: List[OutputRow] = []
    frame = run_set.frame
    alpha = registry.corrected_alpha(_MTTD_TEST_ID)
    for scenario in SCENARIOS:
        groups: Dict[str, List[float]] = {}
        contributing_frames: List[pd.DataFrame] = []
        for config in PRIMARY_CONFIGS:
            cell = _cell(frame, config, scenario)
            detected_mask = cell["measured_time_to_detect"].notna() & (
                cell["measured_time_to_detect"] != io.NEVER_DETECTED_SENTINEL
            )
            detected_cell = cell[detected_mask]
            groups[config] = [
                float(value) for value in detected_cell["measured_time_to_detect"].tolist()
            ]
            contributing_frames.append(detected_cell)
        # The KW provenance is over the DETECTED runs that actually contributed an
        # MTTD value across the four configs (M4/BI-10); a mixed manifest surfaces.
        contributing = pd.concat(contributing_frames) if contributing_frames else frame.iloc[0:0]
        result = tests.kruskal_dunn_holm(
            test_id=_MTTD_TEST_ID,
            scenario=scenario,
            groups=groups,
            corrected_alpha=alpha,
        )
        rows.append(_test_row(result, "all", registry, contributing=contributing))
    return rows


def build_ablation_rows(run_set: io.RunSet, registry: Registry) -> List[OutputRow]:
    """The RSLT ablation contribution rows + the confirmatory McNemar (AC3).

    Per scenario: L2 contribution = DR(L1+L2) - DR(L1-only) and Senior
    contribution = DR(full) - DR(L1+L2), each with a seeded-bootstrap CI (BI-9),
    plus the pre-registered ablation McNemar (corrected 0.005, BI-2). Paired
    over the deterministic scenario-instance index (BI-8).
    """
    rows: List[OutputRow] = []
    frame = run_set.frame
    l2_alpha = registry.corrected_alpha(_ABL_L2_TEST_ID)
    senior_alpha = registry.corrected_alpha(_ABL_SENIOR_TEST_ID)
    for scenario in SCENARIOS:
        technique = metrics.SCENARIO_GROUND_TRUTH.get(scenario, _NA)
        # Pair each contrast on the SHARED scenario-instance key (H2/BI-8): the
        # contribution CI and its McNemar consume the SAME aligned (high, low)
        # vectors, so the effect size and the test agree on the paired instances.
        l2_paired = _pair_cells(_cell(frame, "rslt-l1-l2", scenario), _cell(frame, "rslt-l1-only", scenario))
        l2 = ablation.contribution(
            "l2_contribution", scenario, technique, l2_paired.outcomes_a, l2_paired.outcomes_b
        )
        rows.append(_contribution_row(l2, _ABL_L2_TEST_ID, registry, contributing=l2_paired.frame))
        l2_test = tests.mcnemar_paired(
            test_id=_ABL_L2_TEST_ID,
            scenario=scenario,
            comparison="L1+L2 vs L1-only",
            outcomes_a=l2_paired.outcomes_a,
            outcomes_b=l2_paired.outcomes_b,
            corrected_alpha=l2_alpha,
        )
        rows.append(
            _test_row(l2_test, "rslt-l1-l2", registry, section="ablation", contributing=l2_paired.frame)
        )

        senior_paired = _pair_cells(_cell(frame, "rslt-full", scenario), _cell(frame, "rslt-l1-l2", scenario))
        senior = ablation.contribution(
            "senior_contribution", scenario, technique, senior_paired.outcomes_a, senior_paired.outcomes_b
        )
        rows.append(_contribution_row(senior, _ABL_SENIOR_TEST_ID, registry, contributing=senior_paired.frame))
        senior_test = tests.mcnemar_paired(
            test_id=_ABL_SENIOR_TEST_ID,
            scenario=scenario,
            comparison="full vs L1+L2",
            outcomes_a=senior_paired.outcomes_a,
            outcomes_b=senior_paired.outcomes_b,
            corrected_alpha=senior_alpha,
        )
        rows.append(
            _test_row(senior_test, "rslt-full", registry, section="ablation", contributing=senior_paired.frame)
        )
    return rows


def build_rubric_rows(run_set: io.RunSet, registry: Registry) -> List[OutputRow]:
    """Wilcoxon (per rubric dimension) + ICC(2,k) rows (Story 5.7 inputs, BI-7).

    The Story-5.7 rubric scores have not been collected, so every rubric test
    SKIPS honestly with ``n=0`` (BI-7); the rows still appear so the thesis
    sees the test was registered and is pending its input, never fabricated.
    """
    rows: List[OutputRow] = []
    dimensions = {
        "RQ5-RUBRIC-WILCOXON-CLARITY": "clarity",
        "RQ5-RUBRIC-WILCOXON-COMPLETENESS": "completeness",
        "RQ5-RUBRIC-WILCOXON-ATTACK-COVERAGE": "attack-coverage",
        "RQ5-RUBRIC-WILCOXON-KILLCHAIN": "killchain",
        "RQ5-RUBRIC-WILCOXON-ACTIONABILITY": "actionability",
    }
    for test_id, dimension in dimensions.items():
        result = tests.wilcoxon_signed_rank(
            test_id=test_id,
            dimension=dimension,
            llm_scores=[],
            templated_scores=[],
            corrected_alpha=registry.corrected_alpha(test_id),
        )
        rows.append(_test_row(result, "rubric", registry))
    icc = tests.icc_2k(
        test_id="RQ5-ICC",
        ratings=pd.DataFrame(columns=["target", "rater", "score"]),
        corrected_alpha=registry.corrected_alpha("RQ5-ICC"),
    )
    rows.append(_test_row(icc, "rubric", registry))
    return rows


def build_fr55_rows(run_set: io.RunSet, registry: Registry) -> List[OutputRow]:
    """The FR55 trust-bound row (Story 5.6 input, BI-7/BI-16).

    Story 5.6 RUNS the 100 adversarial trials; 5.5 scaffolds the bound-proof
    aggregation. With no trials present the row SKIPS honestly with ``n=0``
    (BI-7), never a fabricated 0/100 bound proof.
    """
    test_id = "RQ4-FR55-BOUND"
    return [
        OutputRow(
            section="confirmatory",
            config="rsl;rslt-full",
            scenario="benign-adversarial",
            metric_or_test="fr55_trust_bound",
            value=None,
            n=0,
            manifest_hash=_NA,
            mixed_manifest=False,
            test="empirical_bound_count",
            test_id=test_id,
            alpha_corrected=registry.corrected_alpha(test_id),
            p_value=None,
            status="skipped (insufficient data, n=0)",
            fsm_source_partition="",
            underpowered=False,
            exploratory=registry.is_exploratory(test_id),
        )
    ]


def _test_row(
    result: tests.TestResult,
    config: str,
    registry: Registry,
    section: str = "confirmatory",
    contributing: Optional[pd.DataFrame] = None,
) -> OutputRow:
    """Convert a TestResult into an OutputRow, stamping exploratory (BI-14).

    The provenance triad (M4/BI-10) is built from the ``contributing`` run
    sub-frame (the paired McNemar / KW group runs) via ``provenance.for_runs`` so
    a test row carries the REAL manifest_hash of its inputs, not a hardcoded
    ``n/a``. A genuinely mixed-manifest paired test surfaces ``mixed_manifest:
    true`` so a cross-envelope pooling is never silent. ``contributing=None``
    (a test with no run inputs, e.g. the pending rubric tests) keeps ``n/a``.
    """
    exploratory = registry.is_exploratory(result.test_id)
    row_section = "exploratory" if exploratory else section
    if contributing is not None and contributing.shape[0] > 0:
        triad = provenance.for_runs(contributing, n=result.n, test=result.test)
        manifest_hash, mixed = triad.manifest_hash, triad.mixed_manifest
    else:
        manifest_hash, mixed = _NA, False
    return OutputRow(
        section=row_section,
        config=config,
        scenario=result.scenario,
        metric_or_test=result.comparison,
        value=result.statistic,
        n=result.n,
        manifest_hash=manifest_hash,
        mixed_manifest=mixed,
        test=result.test,
        test_id=result.test_id,
        alpha_corrected=result.corrected_alpha,
        p_value=result.p_value,
        status=result.status,
        fsm_source_partition="",
        underpowered=False,
        exploratory=exploratory,
    )


def _contribution_row(
    contribution: ablation.Contribution,
    test_id: str,
    registry: Registry,
    contributing: Optional[pd.DataFrame] = None,
) -> OutputRow:
    """Convert an ablation Contribution into an OutputRow (AC3, BI-9, M4).

    The provenance triad is built from the ``contributing`` paired-run sub-frame
    (M4/BI-10) so the ablation effect-size row carries the real manifest_hash of
    its inputs, not a hardcoded ``n/a``; a mixed-manifest pair surfaces ``mixed``.
    """
    ci = _NA
    if contribution.ci_lower is not None and contribution.ci_upper is not None:
        ci = f"[{contribution.ci_lower:.6f}, {contribution.ci_upper:.6f}]"
    exploratory = registry.is_exploratory(test_id)
    status = tests.STATUS_RUN if contribution.n > 0 else "skipped (insufficient data, n=0)"
    if contributing is not None and contributing.shape[0] > 0:
        manifest_hash, mixed = provenance.cell_manifest(contributing)
    else:
        manifest_hash, mixed = _NA, False
    return OutputRow(
        section="ablation",
        config=contribution.name,
        scenario=contribution.scenario,
        metric_or_test=f"{contribution.name} (technique {contribution.technique})",
        value=contribution.difference,
        n=contribution.n,
        manifest_hash=manifest_hash,
        mixed_manifest=mixed,
        test=f"dr_difference;ci95={ci}",
        test_id=test_id,
        alpha_corrected=None,
        p_value=None,
        status=status,
        fsm_source_partition="",
        underpowered=False,
        exploratory=exploratory,
    )


def _known_grid() -> frozenset[tuple[str, str]]:
    """The known ``(config, scenario)`` grid the pipeline aggregates over (M1).

    The five attack scenarios for every primary AND ablation config, plus the
    ``benign`` sweep for the primary configs (the FPR cell). A run whose
    ``(config, scenario)`` is NOT in this set contributes to no cell and is an
    ORPHAN (a silent data drop the grid would otherwise hide, BI-7).
    """
    grid: set[tuple[str, str]] = set()
    for config in PRIMARY_CONFIGS + ABLATION_CONFIGS:
        for scenario in SCENARIOS:
            grid.add((config, scenario))
    for config in PRIMARY_CONFIGS:
        grid.add((config, "benign"))
    return frozenset(grid)


def _orphaned_runs(frame: pd.DataFrame) -> List[str]:
    """List off-grid ``(config, scenario, run_id)`` runs (M1, BI-7 honesty).

    A run whose ``(config, scenario)`` pair is not in the known grid (a typo'd
    config/scenario) is counted in ``total_runs`` but feeds no cell; surfacing it
    here makes the silent drop visible. Sorted for determinism (BI-13).
    """
    grid = _known_grid()
    orphans: List[str] = []
    for _, row in frame.iterrows():
        pair = (str(row["config"]), str(row["scenario"]))
        if pair not in grid:
            orphans.append(f"{row['config']}/{row['scenario']}/{row['run_id']}")
    return sorted(orphans)


def _cell_n_total(frame: pd.DataFrame) -> int:
    """Sum the per-cell run counts over the KNOWN grid (M1 reconciliation).

    Compared against ``total_runs`` in the header: a non-zero delta means runs
    were dropped (orphaned off-grid), the exact silent-drop BI-7 guards against.
    """
    grid = _known_grid()
    total = 0
    for config, scenario in grid:
        total += int(
            ((frame["config"] == config) & (frame["scenario"] == scenario)).sum()
        )
    return total


def run_pipeline(runs_dir: str, prereg_path: str = DEFAULT_PREREG) -> PipelineResult:
    """Compose the full pipeline over ``runs_dir`` (AC1-AC4).

    Loads the run-set, parses the prereg registry, builds the metric rows, the
    inferential-test rows, the ablation rows, and the exploratory section, and
    assembles the deterministic header. The order of the row groups is fixed so
    the output is byte-deterministic (BI-13).
    """
    run_set = io.load_run_set(runs_dir)
    registry = parse_registry(prereg_path)

    rows: List[OutputRow] = []
    rows.extend(build_metric_rows(run_set))
    rows.extend(build_fpr_rows(run_set, registry))
    rows.extend(build_dr_mcnemar_rows(run_set, registry))
    rows.extend(build_mttd_rows(run_set, registry))
    rows.extend(build_ablation_rows(run_set, registry))
    rows.extend(build_rubric_rows(run_set, registry))
    rows.extend(build_fr55_rows(run_set, registry))

    distinct_manifests = provenance._distinct_manifest_hashes(run_set.frame)
    total_runs = int(run_set.frame.shape[0])
    orphaned = _orphaned_runs(run_set.frame)
    on_grid_n = _cell_n_total(run_set.frame)
    header: Dict[str, object] = {
        "runs_dir": run_set.runs_dir,
        "fixture": run_set.is_fixture,
        "total_runs": total_runs,
        "on_grid_runs": on_grid_n,
        # The reconciliation delta (M1): total_runs - sum(per-cell n). A non-zero
        # delta is the count of runs dropped off-grid (orphaned); 0 means every
        # loaded run feeds a cell. Surfaced so a silent data drop is visible (BI-7).
        "orphaned_run_count": total_runs - on_grid_n,
        "orphaned_runs": orphaned,
        "distinct_manifest_count": len(distinct_manifests),
        "prereg": prereg_path,
        "confirmatory_test_ids": sorted(registry.entries),
    }
    return PipelineResult(rows=rows, header=header, distinct_manifests=distinct_manifests)


def write_csv(result: PipelineResult, path: Path) -> None:
    """Write ``summary.csv`` (the fixed column order, BI-13/BI-10/BI-14)."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_CSV_COLUMNS)
        writer.writeheader()
        for row in result.rows:
            writer.writerow(row.as_csv())


def _markdown_table(rows: Sequence[OutputRow]) -> List[str]:
    """Render a Markdown table for a section's rows (deterministic, BI-13)."""
    lines = [
        "| config | scenario | metric_or_test | value | n | test | test_id | "
        "alpha_corrected | p_value | status | manifest_hash | mixed_manifest | "
        "fsm_source_partition | underpowered |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        csv_row = row.as_csv()
        lines.append(
            "| {config} | {scenario} | {metric_or_test} | {value} | {n} | {test} | "
            "{test_id} | {alpha_corrected} | {p_value} | {status} | {manifest_hash} | "
            "{mixed_manifest} | {fsm_source_partition} | {underpowered} |".format(**csv_row)
        )
    return lines


def write_markdown(result: PipelineResult, path: Path) -> None:
    """Write ``summary.md`` with a Confirmatory + Exploratory section (BI-14).

    The header records the run-set provenance (the ``runs/`` dir, distinct
    manifest hashes, total n, ``fixture: true`` when run on the fixtures, BI-7).
    """
    header = result.header
    lines: List[str] = ["# Olaitan analysis summary", ""]
    lines.append("## Run-set provenance")
    lines.append("")
    lines.append(f"- runs_dir: `{header['runs_dir']}`")
    lines.append(f"- fixture: {header['fixture']}")
    lines.append(f"- total_runs: {header['total_runs']}")
    lines.append(f"- on_grid_runs: {header['on_grid_runs']}")
    lines.append(f"- orphaned_run_count: {header['orphaned_run_count']}")
    orphaned = header.get("orphaned_runs") or []
    if isinstance(orphaned, list) and orphaned:
        lines.append(f"- orphaned_runs: {', '.join(str(o) for o in orphaned)}")
    else:
        lines.append("- orphaned_runs: none")
    lines.append(f"- distinct_manifest_count: {header['distinct_manifest_count']}")
    lines.append(f"- prereg: `{header['prereg']}`")
    lines.append("")
    if header["fixture"]:
        lines.append(
            "> NOTE: this is a SYNTHETIC fixture run-set (`fixture: true`). The "
            "numbers below are for the data-path proof + the smoke test only and "
            "are NEVER thesis-final (BI-7). The real 400-run numbers land later "
            "on the cluster (Story 5.9)."
        )
        lines.append("")

    sections = [
        ("Per-cell metrics", "metrics"),
        ("Confirmatory results", "confirmatory"),
        ("RSLT ablation", "ablation"),
        ("Exploratory analyses", "exploratory"),
    ]
    for title, section in sections:
        section_rows = [row for row in result.rows if row.section == section]
        lines.append(f"## {title}")
        lines.append("")
        if not section_rows:
            note = (
                "No exploratory tests emitted (every test_id is in the "
                "confirmatory registry)."
                if section == "exploratory"
                else "No rows."
            )
            lines.append(note)
            lines.append("")
            continue
        lines.extend(_markdown_table(section_rows))
        lines.append("")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_outputs(result: PipelineResult, output_dir: str) -> None:
    """Write ``summary.csv`` + ``summary.md`` under ``output_dir`` (AC1)."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(result, out / "summary.csv")
    write_markdown(result, out / "summary.md")


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="analyse.py",
        description="Olaitan statistical analysis pipeline (Story 5.5).",
    )
    parser.add_argument("--runs", required=True, help="the runs/<run_id>/ directory")
    parser.add_argument("--output", required=True, help="the output directory for the summaries")
    parser.add_argument(
        "--prereg",
        default=DEFAULT_PREREG,
        help="the pre-registration markdown (the confirmatory registry source)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entrypoint: load -> aggregate -> test -> ablation -> classify -> write."""
    args = _parse_args(argv)
    result = run_pipeline(args.runs, args.prereg)
    write_outputs(result, args.output)
    print(
        f"analyse.py: wrote summary.csv + summary.md to {args.output} "
        f"({result.header['total_runs']} runs, "
        f"fixture={result.header['fixture']})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
