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
from typing import Any, List, Optional

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
        if len(tail) == 2 and tail[1].isdigit():
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
