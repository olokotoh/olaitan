"""Run-artefact loading for the analysis pipeline (Story 5.5, AC1).

Loads each ``runs/<run_id>/metadata.yaml`` (and, where a metric needs them, the
``.jsonl`` artefacts) the MERGED Story 5.4 capture wrote into a typed pandas
DataFrame keyed by ``(config, scenario, run_id)``. It CONSUMES the Story-5.4
shapes read-only (BI-3, BI-16); it does NOT re-validate or re-shape them.

The honesty contract (BI-7): a run dir that is missing or malformed is reported,
never silently fabricated into a number. Non-run dirs (the ``example/``
skeleton, dotfiles) are skipped honestly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd
import yaml

# The Story-5.4 never-detected sentinel (internal/eval/capture/metadata.go:15,
# NeverDetectedSentinel). measured_time_to_detect == -1 means the run never
# reached a detection signal; it is EXCLUDED from MTTD (BI-3), never treated as
# a 0/negative time.
NEVER_DETECTED_SENTINEL: int = -1

# The Story-5.4 fsm_state_source honesty labels (metadata.go:17-39, BI-4).
FSM_SOURCE_OBSERVED: str = "observed_transitions"
FSM_SOURCE_DETECTION_SIGNAL_ONLY: str = "detection_signal_only"
FSM_SOURCE_NONE: str = "none"

# The metadata.yaml columns the pipeline consumes (BI-3, BI-10). Listed
# explicitly so a typo in a key surfaces as a load error, not a silent NaN.
_METADATA_COLUMNS: List[str] = [
    "run_id",
    "manifest_sha256",
    "scenario",
    "config",
    "started_at",
    "finished_at",
    "success_criterion_met",
    "measured_time_to_detect",
    "measured_final_fsm_state",
    "fsm_state_source",
    # The explicit scenario-instance index over the deterministic Story-5.2
    # stimulus (H2/BI-8/OQ7 pairing key). Story 5.9 must populate it per replicate
    # so the paired McNemar/ablation tests align config A's instance i with config
    # B's instance i over the SAME stimulus, never positional wall-clock order. A
    # run that omits it falls back to the run_id ``-NN`` suffix (see
    # ``scenario_instance_key``); a run with neither is dropped from a pair
    # honestly (BI-7), never positionally mis-paired.
    "scenario_instance",
]

_METADATA_FILE: str = "metadata.yaml"
_FSM_FILE: str = "fsm.jsonl"
_ASSESSMENTS_FILE: str = "assessments.jsonl"

# The synthetic-fixture run_id prefix (BI-13 mandates a ``fixture-`` prefix on
# every committed synthetic run). ``is_fixture`` is driven off THIS per-run
# signal, not a path substring (L1), so a real run-set under a path that happens
# to contain a ``fixtures`` segment is never mislabelled.
_FIXTURE_RUN_ID_PREFIX: str = "fixture-"

# Dir names that are NOT run dirs (skipped honestly, BI-7). ``example`` is the
# committed Story-5.1 layout skeleton; it carries no measured fields to compute.
_NON_RUN_DIRS: frozenset[str] = frozenset({"example"})


@dataclass(frozen=True)
class RunSet:
    """A loaded run-set: the per-run frame plus its provenance.

    ``frame`` is keyed (sorted) by ``(config, scenario, run_id)``. ``runs_dir``
    and ``is_fixture`` record where the runs came from so the output header can
    label a fixture run-set ``fixture: true`` (BI-7, BI-13).
    """

    frame: pd.DataFrame
    runs_dir: str
    is_fixture: bool


def _read_metadata(meta_path: Path) -> dict[str, Any]:
    """Load one metadata.yaml into a plain dict (the keys the pipeline reads)."""
    with meta_path.open("r", encoding="utf-8") as handle:
        loaded: Any = yaml.safe_load(handle)
    if not isinstance(loaded, dict):
        raise ValueError(f"metadata.yaml at {meta_path} did not parse to a mapping")
    return loaded


def _row_from_metadata(meta: dict[str, Any], run_id: str) -> dict[str, Any]:
    """Project a metadata mapping onto the consumed column set.

    A missing key is recorded as ``None`` (an honest NaN downstream, BI-7), NOT
    a fabricated value. ``run_id`` falls back to the directory name when the
    file omits it.
    """
    row: dict[str, Any] = {}
    for column in _METADATA_COLUMNS:
        row[column] = meta.get(column)
    if row["run_id"] is None:
        row["run_id"] = run_id
    return row


def read_jsonl_payloads(path: Path) -> List[dict[str, Any]]:
    """Read a Story-5.4 ``.jsonl`` artefact, returning each line's payload.

    Each line is the self-describing Envelope
    ``{schema_version, published_at, subject, payload}`` (capture.go:79-84); the
    pipeline reads the verbatim ``payload`` body. A missing file yields an empty
    list (an honest empty drain, BI-7), never a fabricated record.
    """
    if not path.is_file():
        return []
    payloads: List[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for i, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            # Re-raise a malformed/truncated line with file + line-number
            # context (mirrors _read_metadata's named-path failure above);
            # a file-anonymous JSONDecodeError gives the operator nothing to
            # find. Honest crash with the culprit located (BI-7).
            try:
                envelope: Any = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed jsonl line {i} in {path}: {exc}") from exc
            if not isinstance(envelope, dict):
                raise ValueError(f"jsonl line in {path} is not an object: {line!r}")
            payload: Any = envelope.get("payload")
            if payload is None:
                continue
            if not isinstance(payload, dict):
                raise ValueError(f"jsonl payload in {path} is not an object: {payload!r}")
            payloads.append(payload)
    return payloads


def fsm_after_states(run_dir: Path) -> List[str]:
    """Return the ordered ``after_state`` values from a run's ``fsm.jsonl``.

    Drives the FPR escalation count (BI-5). An absent/empty fsm.jsonl yields an
    empty list (no escalations observed), never a fabricated escalation.
    """
    states: List[str] = []
    for payload in read_jsonl_payloads(run_dir / _FSM_FILE):
        after = payload.get("after_state")
        if isinstance(after, str):
            states.append(after)
    return states


def assessment_payloads(run_dir: Path) -> List[dict[str, Any]]:
    """Return the ``assessments.jsonl`` payloads (the predicted-technique source).

    Drives the ATT&CK Cohen's kappa (BI-6). An absent/empty file (the F/RS arms
    produce no assessment) yields an empty list, so kappa degrades to ``n/a``
    honestly for those cells.
    """
    return read_jsonl_payloads(run_dir / _ASSESSMENTS_FILE)


def scenario_instance_key(run_id: object, scenario_instance: object) -> Optional[str]:
    """The stable scenario-instance pairing key for a run (H2/BI-8/OQ7).

    The paired tests (McNemar, ablation contributions) MUST align config A's
    instance i with config B's instance i over the SAME deterministic Story-5.2
    stimulus, not positional wall-clock order (the real ``run_id`` is
    timestamp-first, so positional order is arbitrary across configs). The key is,
    in order of preference:

    1. the explicit ``scenario_instance`` metadata field (the canonical Story-5.9
       signal), rendered as a string; else
    2. the trailing ``-NN`` instance index parsed from the ``run_id`` (the
       convention the committed fixtures use, e.g. ``fixture-rsl-s1-03`` -> ``03``).

    Returns ``None`` when neither is available, so the caller drops the run from
    any pair honestly (BI-7) rather than fabricating a positional alignment.

    DETERMINISTIC-STIMULUS ASSUMPTION (documented for round-2 scrutiny): this
    pairing is only valid because instance i of a scenario is the SAME stimulus
    across every config (Story 5.2 seeds the scenario deterministically per
    instance index). If that assumption ever breaks, the paired tests must be
    re-derived; the key here is the contract surface where it is enforced.
    """
    if scenario_instance is not None and not (
        isinstance(scenario_instance, float) and scenario_instance != scenario_instance
    ):
        return str(scenario_instance)
    if isinstance(run_id, str):
        tail = run_id.rsplit("-", 1)
        # Bound the fallback index to a short numeric suffix so a real run_id
        # whose 12-char manifest-hash suffix happens to be all-digits cannot be
        # mis-read as an instance index (it would simply fail to join and drop
        # the run honestly, BI-7, but bounding avoids the rare mis-key). The
        # committed fixtures use a 1-3 digit -NN suffix; real runs carry the
        # explicit scenario_instance field (Story 5.9) and never reach here.
        if len(tail) == 2 and tail[1].isdigit() and len(tail[1]) <= 3:
            return tail[1]
    return None


def _is_run_dir(entry: Path) -> bool:
    """True when ``entry`` is a run dir (a dir with a metadata.yaml, not skel)."""
    if not entry.is_dir():
        return False
    if entry.name.startswith("."):
        return False
    if entry.name in _NON_RUN_DIRS:
        return False
    return (entry / _METADATA_FILE).is_file()


def _coerce_frame(rows: List[dict[str, Any]]) -> pd.DataFrame:
    """Build the typed, sorted per-run frame from the projected rows.

    Determinism (BI-13): the frame is sorted by ``(config, scenario, run_id)``
    so every downstream aggregation iterates in a fixed order. The boolean and
    integer columns are coerced to nullable dtypes so a missing field is a
    pandas NA (an honest gap), not a fabricated ``False``/``0``.
    """
    columns = _METADATA_COLUMNS
    if not rows:
        frame = pd.DataFrame({column: pd.Series(dtype="object") for column in columns})
    else:
        frame = pd.DataFrame(rows, columns=columns)
    frame["success_criterion_met"] = frame["success_criterion_met"].astype("boolean")
    frame["measured_time_to_detect"] = pd.to_numeric(
        frame["measured_time_to_detect"], errors="coerce"
    ).astype("Int64")
    frame = frame.sort_values(
        by=["config", "scenario", "run_id"], kind="mergesort"
    ).reset_index(drop=True)
    return frame


def load_run_set(runs_dir: str) -> RunSet:
    """Load every run dir under ``runs_dir`` into a typed, sorted RunSet.

    A run dir is any sub-directory carrying a ``metadata.yaml`` other than the
    committed ``example/`` skeleton or a dotfile (skipped honestly, BI-7). The
    run-set is flagged ``is_fixture`` when loaded from the committed synthetic
    fixtures (``analysis/fixtures/`` in the path), so the output header can
    stamp ``fixture: true`` (BI-7, BI-13).
    """
    base = Path(runs_dir)
    if not base.is_dir():
        raise FileNotFoundError(f"runs dir {runs_dir!r} does not exist")
    rows: List[dict[str, Any]] = []
    for entry in sorted(base.iterdir(), key=lambda path: path.name):
        if not _is_run_dir(entry):
            continue
        meta = _read_metadata(entry / _METADATA_FILE)
        rows.append(_row_from_metadata(meta, entry.name))
    frame = _coerce_frame(rows)
    is_fixture = _is_fixture_run_set(frame)
    return RunSet(frame=frame, runs_dir=str(base), is_fixture=is_fixture)


def _is_fixture_run_set(frame: pd.DataFrame) -> bool:
    """True when this is a SYNTHETIC fixture run-set, off an explicit per-run signal.

    Driven off the per-run ``run_id`` ``fixture-`` prefix (BI-13 mandates the
    prefix on every synthetic run), NOT a path substring: a real run-set living
    under any directory that happens to contain a ``fixtures`` path segment would
    otherwise be mislabelled ``fixture: true``. A non-empty run-set is a fixture
    set only when EVERY run carries the prefix (a mixed set is not a fixture set).
    """
    if "run_id" not in frame.columns or frame.shape[0] == 0:
        return False
    run_ids = frame["run_id"].dropna().astype(str)
    if run_ids.shape[0] == 0:
        return False
    return bool(run_ids.str.startswith(_FIXTURE_RUN_ID_PREFIX).all())


# ---------------------------------------------------------------------------
# FR55 trust-bound run loading (Story 5.6, OQ1/OQ5).
#
# The FR55 bound-test trials live under a RESERVED ``runs/fr55/`` sub-tree
# (one ``<provider>-<config>/`` dir each, with a ``metadata.yaml`` + a
# ``trials.jsonl``), kept SEPARATE from the main 4x5 grid so the
# ``benign-adversarial`` scenario does not orphan in ``analyse.py:_known_grid``
# (OQ1). ``load_run_set`` above scans only the top-level run dirs and skips the
# ``fr55/`` sub-tree (it carries no metadata.yaml of its own); ``load_fr55_runs``
# reads the sub-tree directly. The emitter is the Go harness
# ``internal/eval/fr55`` (the OFFLINE fake-provider proof set; BI-2). The trials
# DEGRADE HONESTLY: an absent sub-tree yields no runs (the ``n=0`` skip stays,
# BI-7), never a fabricated bound proof.
# ---------------------------------------------------------------------------

# The reserved FR55 sub-tree name under a runs dir (OQ1).
_FR55_SUBTREE: str = "fr55"

# The per-trial schema_version the Go emitter stamps (fr55.trial.v1).
_FR55_TRIAL_SCHEMA: str = "fr55.trial.v1"

# The metadata.yaml scenario join key the FR55 runs carry (BI-7).
FR55_SCENARIO: str = "benign-adversarial"

# The FR55 trials.jsonl filename (sibling of metadata.yaml in each run dir).
_FR55_TRIALS_FILE: str = "trials.jsonl"


@dataclass(frozen=True)
class FR55Trial:
    """One FR55 per-trial record (Story 5.6 AC3), read read-only.

    The Go emitter writes one ``fr55.trial.v1`` JSON line per trial; this is the
    typed projection the bound aggregation reads. ``final_fsm_state`` is the FSM
    state the trial's ThreatScore maps to under the production thresholds.
    """

    trial_index: int
    config: str
    provider: str
    raw_confidence: int
    llm_capped_confidence: int
    threat_score: float
    final_fsm_state: str
    cap_violation_total: int


@dataclass(frozen=True)
class FR55Run:
    """One FR55 run dir: the metadata join keys + the per-trial records.

    ``provider`` is the honest provider label (``fake`` on the OFFLINE set,
    BI-2). ``config`` is ``rsl`` | ``rslt-full``. ``trials`` is the ordered
    per-trial records read from ``trials.jsonl``.
    """

    run_id: str
    manifest_sha256: str
    scenario: str
    config: str
    provider: str
    bound: float
    trials: List[FR55Trial]
    # The bound-summary fields the Go emitter writes into metadata.yaml
    # (max_threat_score, n_past_suspicious, cap_violation_total, bound_holds),
    # carried raw so build_fr55_rows can cross-check them against the values
    # recomputed from the trials (Blind Hunter LOW2). Absent keys are omitted;
    # the consumer treats a missing key as "nothing to cross-check".
    metadata_summary: Dict[str, object]


# The FSM states STRICTLY past SUSPICIOUS (the AC4 bound predicate). Mirrors the
# Go ``fr55.pastSuspicious`` set and ``internal/schema/state.go``; a future state
# rename on the Go side must be mirrored here by hand (the Go file is
# authoritative; same hand-coupling caveat as ``lib/fsm.py``'s state rank).
_FR55_PAST_SUSPICIOUS: frozenset[str] = frozenset(
    {"RESTRICTED", "QUARANTINED", "PRESERVED_KILLED"}
)


def fr55_is_past_suspicious(state: str) -> bool:
    """True when ``state`` is strictly past SUSPICIOUS (the AC4 bound predicate)."""
    return state in _FR55_PAST_SUSPICIOUS


def _read_fr55_trials(path: Path) -> List[FR55Trial]:
    """Read a ``trials.jsonl`` into typed FR55Trial records.

    Each line is a self-describing ``fr55.trial.v1`` object (NOT the Story-5.4
    Envelope shape, so this does not reuse ``read_jsonl_payloads``). A malformed
    line, a wrong ``schema_version``, or a missing required field raises with
    file + line context (an honest crash with the culprit located, BI-7), never a
    silently dropped trial.
    """
    if not path.is_file():
        return []
    trials: List[FR55Trial] = []
    with path.open("r", encoding="utf-8") as handle:
        for i, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                record: Any = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed fr55 trial line {i} in {path}: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"fr55 trial line {i} in {path} is not an object: {line!r}")
            version = record.get("schema_version")
            if version != _FR55_TRIAL_SCHEMA:
                raise ValueError(
                    f"fr55 trial line {i} in {path} has schema_version "
                    f"{version!r}, want {_FR55_TRIAL_SCHEMA!r}"
                )
            try:
                trials.append(
                    FR55Trial(
                        trial_index=int(record["trial_index"]),
                        config=str(record["config"]),
                        provider=str(record["provider"]),
                        raw_confidence=int(record["raw_confidence"]),
                        llm_capped_confidence=int(record["llm_capped_confidence"]),
                        threat_score=float(record["threat_score"]),
                        final_fsm_state=str(record["final_fsm_state"]),
                        cap_violation_total=int(record["cap_violation_total"]),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"fr55 trial line {i} in {path} missing/invalid field: {exc}"
                ) from exc
    return trials


def load_fr55_runs(runs_dir: str) -> List[FR55Run]:
    """Load the FR55 bound-test runs under ``<runs_dir>/fr55/`` (OQ1, BI-7).

    Returns one FR55Run per ``<provider>-<config>/`` sub-dir carrying a
    ``metadata.yaml``, sorted by run dir name for determinism (BI-13). An absent
    ``fr55/`` sub-tree (the real cluster run has not landed yet) yields an EMPTY
    list, so ``build_fr55_rows`` keeps its honest ``n=0`` skip (BI-7), never a
    fabricated bound proof.
    """
    fr55_base = Path(runs_dir) / _FR55_SUBTREE
    if not fr55_base.is_dir():
        return []
    runs: List[FR55Run] = []
    for entry in sorted(fr55_base.iterdir(), key=lambda path: path.name):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        meta_path = entry / _METADATA_FILE
        if not meta_path.is_file():
            continue
        meta = _read_metadata(meta_path)
        trials = _read_fr55_trials(entry / _FR55_TRIALS_FILE)
        raw_bound = meta.get("bound")
        try:
            bound = float(raw_bound) if raw_bound is not None else float("nan")
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"fr55 metadata {meta_path} has non-numeric bound {raw_bound!r}"
            ) from exc
        # The bound-summary self-check fields the Go emitter writes (LOW2): kept
        # raw (yaml.safe_load already coerces int/float/bool) so build_fr55_rows
        # can cross-check them against the values recomputed from the trials. A
        # missing key is simply omitted (nothing to cross-check).
        metadata_summary: Dict[str, object] = {
            key: meta[key]
            for key in (
                "max_threat_score",
                "n_past_suspicious",
                "cap_violation_total",
                "bound_holds",
            )
            if key in meta and meta[key] is not None
        }
        runs.append(
            FR55Run(
                run_id=str(meta.get("run_id", entry.name)),
                manifest_sha256=str(meta.get("manifest_sha256", "")),
                scenario=str(meta.get("scenario", "")),
                config=str(meta.get("config", "")),
                provider=str(meta.get("provider", "")),
                bound=bound,
                trials=trials,
                metadata_summary=metadata_summary,
            )
        )
    return runs


# ---------------------------------------------------------------------------
# Rubric score loading (Story 5.7, RQ5, OQ1/OQ4).
#
# The DFIR rubric study scores live under a RESERVED ``runs/rubric/`` sub-tree
# (one ``rubric-offline-<scenario>/`` dir each, with a ``metadata.yaml`` + a
# ``scores.jsonl``), kept SEPARATE from the main 4x5 grid so the rubric scenario
# does not orphan in ``analyse.py:load_run_set`` (the sub-tree carries no
# top-level metadata.yaml of its own, so ``load_run_set`` skips it;
# ``load_rubric_scores`` reads it directly, mirroring ``load_fr55_runs``). The
# emitter is the Go harness ``internal/eval/rubric`` (the OFFLINE synthetic proof
# set; BI-2). The scores DEGRADE HONESTLY: an absent sub-tree yields no records
# (``build_rubric_rows`` keeps the honest ``n=0`` skip, BI-4), never a fabricated
# rubric finding. The offline records are LABELLED synthetic (``synthetic: true``,
# ``rater: synthetic-*``); they are NEVER a thesis-final RQ5 number (BI-2).
# ---------------------------------------------------------------------------

# The reserved rubric sub-tree name under a runs dir (OQ4).
_RUBRIC_SUBTREE: str = "rubric"

# The per-score schema_version the Go emitter stamps (rubric.score.v1).
_RUBRIC_SCORE_SCHEMA: str = "rubric.score.v1"

# The rubric scores.jsonl filename (sibling of metadata.yaml in each run dir).
_RUBRIC_SCORES_FILE: str = "scores.jsonl"

# The 5 CANONICAL rubric dimensions (BI-5, FIXED by the pre-registration). A
# score record carrying any other dimension key is a drift error (the Go emitter
# and this reader must agree on the exact five). Mirrors the Go
# ``internal/eval/rubric`` CanonicalDimensions and the build_rubric_rows registry.
_RUBRIC_DIMENSIONS: frozenset[str] = frozenset(
    {"clarity", "completeness", "attack-coverage", "killchain", "actionability"}
)

# The two report variants the reader pivots on (paired per incident_id): the
# Story-4.4 LLM report vs the no-LLM templated baseline.
_RUBRIC_VARIANT_LLM: str = "llm"
_RUBRIC_VARIANT_TEMPLATED: str = "templated"

# The canonical variants set: a score record carrying any other variant is a
# drift error. An unknown variant is dropped from the Wilcoxon pairing but would
# otherwise STILL enter the ICC frame and corrupt the reliability estimate, so
# it is rejected at the trust boundary here. Mirrors the Go emitter's Variant
# constants (internal/eval/rubric/variants.go).
_RUBRIC_VARIANTS: frozenset[str] = frozenset(
    {_RUBRIC_VARIANT_LLM, _RUBRIC_VARIANT_TEMPLATED}
)

# The documented Likert scale bounds (1-5) the rubric is collected on, mirroring
# the Go emitter's LikertMin/LikertMax (internal/eval/rubric/schema.go). A score
# outside this inclusive range is rejected here so an out-of-range hand edit
# cannot load silently into the Wilcoxon / ICC estimates (the hand-edit trust
# boundary for the deferred real study).
_RUBRIC_LIKERT_MIN: int = 1
_RUBRIC_LIKERT_MAX: int = 5


@dataclass(frozen=True)
class RubricScore:
    """One rubric.score.v1 record (Story 5.7 AC2/AC3), read read-only.

    The Go emitter writes one ``rubric.score.v1`` JSON line per
    ``(incident_id, variant, rater, dimension)`` Likert score; this is the typed
    projection ``build_rubric_rows`` pivots into the paired Wilcoxon vectors + the
    ICC ratings frame. ``synthetic`` is the honesty marker (``True`` on the
    OFFLINE synthetic set, BI-2), carried through so a consumer never mistakes a
    placeholder score for a real rater score.
    """

    incident_id: str
    scenario: str
    variant: str
    rater: str
    dimension: str
    score: float
    synthetic: bool


@dataclass(frozen=True)
class RubricRun:
    """One rubric run dir: the metadata join keys + the per-score records.

    ``scenario`` is the rubric scenario the scores were collected for; ``scores``
    is the ordered per-score records read from ``scores.jsonl``; ``synthetic`` is
    the run-level honesty flag from metadata.yaml (BI-2).
    """

    run_id: str
    manifest_sha256: str
    scenario: str
    synthetic: bool
    scores: List[RubricScore]


def _read_rubric_scores(path: Path) -> List[RubricScore]:
    """Read a ``scores.jsonl`` into typed RubricScore records.

    Each line is a self-describing ``rubric.score.v1`` object (NOT the Story-5.4
    Envelope shape, so this does not reuse ``read_jsonl_payloads``). A malformed
    line, a wrong ``schema_version``, an unknown dimension, an unknown variant, a
    ``score`` outside the Likert range, or a missing required field raises with
    file + line context (an honest crash with the culprit located, BI-4), never a
    silently dropped or out-of-range score.
    """
    if not path.is_file():
        return []
    scores: List[RubricScore] = []
    with path.open("r", encoding="utf-8") as handle:
        for i, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                record: Any = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed rubric score line {i} in {path}: {exc}") from exc
            if not isinstance(record, dict):
                raise ValueError(f"rubric score line {i} in {path} is not an object: {line!r}")
            version = record.get("schema_version")
            if version != _RUBRIC_SCORE_SCHEMA:
                raise ValueError(
                    f"rubric score line {i} in {path} has schema_version "
                    f"{version!r}, want {_RUBRIC_SCORE_SCHEMA!r}"
                )
            dimension = str(record.get("dimension", ""))
            if dimension not in _RUBRIC_DIMENSIONS:
                raise ValueError(
                    f"rubric score line {i} in {path} has dimension {dimension!r}, "
                    f"not one of the 5 canonical dimensions {sorted(_RUBRIC_DIMENSIONS)}"
                )
            variant = str(record.get("variant", ""))
            if variant not in _RUBRIC_VARIANTS:
                # An unknown variant is dropped from the Wilcoxon pairing but would
                # still enter the ICC frame and corrupt the reliability estimate;
                # reject it at the trust boundary (BI-5).
                raise ValueError(
                    f"rubric score line {i} in {path} has variant {variant!r}, "
                    f"not one of the canonical variants {sorted(_RUBRIC_VARIANTS)}"
                )
            try:
                score = float(record["score"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"rubric score line {i} in {path} missing/invalid field: {exc}"
                ) from exc
            if not _RUBRIC_LIKERT_MIN <= score <= _RUBRIC_LIKERT_MAX:
                # An out-of-range hand edit (e.g. 0 or 6 on the 1-5 scale) would
                # load silently into Wilcoxon / ICC; reject it honestly.
                raise ValueError(
                    f"rubric score line {i} in {path} has score {score!r} outside "
                    f"the Likert range [{_RUBRIC_LIKERT_MIN}, {_RUBRIC_LIKERT_MAX}]"
                )
            try:
                scores.append(
                    RubricScore(
                        incident_id=str(record["incident_id"]),
                        scenario=str(record["scenario"]),
                        variant=variant,
                        rater=str(record["rater"]),
                        dimension=dimension,
                        score=score,
                        synthetic=bool(record.get("synthetic", False)),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(
                    f"rubric score line {i} in {path} missing/invalid field: {exc}"
                ) from exc
    return scores


def load_rubric_scores(runs_dir: str) -> List[RubricRun]:
    """Load the rubric runs under ``<runs_dir>/rubric/`` (OQ1/OQ4, BI-4).

    Returns one RubricRun per ``rubric-offline-<scenario>/`` sub-dir carrying a
    ``metadata.yaml``, sorted by run dir name for determinism. An absent
    ``rubric/`` sub-tree (the real N>=3 x N=10 rater study has not landed yet)
    yields an EMPTY list, so ``build_rubric_rows`` keeps its honest ``n=0`` skip
    (BI-4), never a fabricated rubric finding. Mirrors ``load_fr55_runs``.
    """
    rubric_base = Path(runs_dir) / _RUBRIC_SUBTREE
    if not rubric_base.is_dir():
        return []
    runs: List[RubricRun] = []
    for entry in sorted(rubric_base.iterdir(), key=lambda path: path.name):
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        meta_path = entry / _METADATA_FILE
        if not meta_path.is_file():
            continue
        meta = _read_metadata(meta_path)
        scores = _read_rubric_scores(entry / _RUBRIC_SCORES_FILE)
        runs.append(
            RubricRun(
                run_id=str(meta.get("run_id", entry.name)),
                manifest_sha256=str(meta.get("manifest_sha256", "")),
                scenario=str(meta.get("scenario", "")),
                synthetic=bool(meta.get("synthetic", False)),
                scores=scores,
            )
        )
    return runs
