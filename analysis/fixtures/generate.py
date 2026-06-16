"""Deterministic synthetic fixture generator for the smoke test (Story 5.5, BI-13).

Writes a small, hand-parameterised, DETERMINISTIC run-set under
``analysis/fixtures/runs/fixture-*/`` spanning the four primary configs + the two
ablation arms x the five scenarios, plus a benign sweep per primary config (so
FPR + the Poisson test produce a non-degenerate result, BI-5). Every run dir is
clearly synthetic (``run_id`` prefixed ``fixture-``) and labelled so the smoke
test asserts the pipeline DEGRADES + COMPUTES honestly without ever fabricating a
thesis-final number (BI-7).

This generator is committed alongside the run dirs it produces so the fixtures
are re-derivable; the run dirs themselves are committed (not gitignored) so the
smoke test runs on a fixed input. Re-run with::

    python analysis/fixtures/generate.py

The detection / MTTD / technique values are HAND-CHOSEN per (config, scenario)
to give a varied but fixed matrix (a detection gradient F < RS < RSL <
RSLT-full), not drawn from any RNG, so the output is byte-deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Tuple

FIXTURE_MANIFEST = "fixture0000000000000000000000000000000000000000000000000000000000"
SCENARIOS = ["s1", "s2", "s3", "s4", "s5"]
PRIMARY = ["f", "rs", "rsl", "rslt-full"]
ABLATION = ["rslt-l1-only", "rslt-l1-l2"]
GROUND_TRUTH = {"s1": "T1611", "s2": "T1552", "s3": "T1613", "s4": "T1071", "s5": "T1496"}
LLM_CONFIGS = {"rsl", "rslt-full", "rslt-l1-only", "rslt-l1-l2"}

# Per-config detection probability gradient (deterministic count of successes
# out of N). A small fixed N keeps the fixtures tiny while giving the inferential
# tests discordant pairs (BI-8). The fraction is realised as the FIRST k runs
# detecting, the rest not, so the paired index is fixed.
N_PER_CELL = 4
DETECT_COUNT: Dict[str, int] = {
    "f": 1,
    "rs": 2,
    "rsl": 3,
    "rslt-full": 4,
    "rslt-l1-only": 2,
    "rslt-l1-l2": 3,
}
# Per-config MTTD seconds for a detected run (fixed; faster as the chain grows).
MTTD_SECONDS: Dict[str, int] = {
    "f": 40,
    "rs": 30,
    "rsl": 22,
    "rslt-full": 18,
    "rslt-l1-only": 28,
    "rslt-l1-l2": 24,
}

NEVER_DETECTED = -1


def _metadata(
    run_id: str, config: str, scenario: str, detected: bool, ttd: int, instance: int
) -> str:
    lines = [
        f"run_id: {run_id}",
        f"manifest_sha256: {FIXTURE_MANIFEST}",
        f"scenario: {scenario}",
        f"config: {config}",
        "runs: 1",
        'started_at: "2026-06-15T09:30:00Z"',
        'finished_at: "2026-06-15T09:31:00Z"',
        "olaitan_eval_version: fixture",
        f"success_criterion_met: {'true' if detected else 'false'}",
        f"measured_time_to_detect: {ttd}",
        f"measured_final_fsm_state: {'QUARANTINED' if detected else 'CLEAN'}",
        f"fsm_state_source: {'observed_transitions' if detected else 'none'}",
        # The scenario-instance pairing key (H2/BI-8): instance i of a scenario is
        # the SAME deterministic Story-5.2 stimulus across every config, so the
        # paired McNemar/ablation tests align config A's instance i with config
        # B's instance i. Story 5.9 must populate this per replicate on real runs.
        f"scenario_instance: {instance}",
        "resource_usage:",
        "  harness_alloc_bytes: 4194304",
        "  cluster_metrics_available: false",
        "size_bytes: 4096",
        "size_cap_exceeded: false",
    ]
    return "\n".join(lines) + "\n"


def _benign_metadata(run_id: str, config: str, escalations: int) -> str:
    lines = [
        f"run_id: {run_id}",
        f"manifest_sha256: {FIXTURE_MANIFEST}",
        "scenario: benign",
        f"config: {config}",
        "runs: 1",
        'started_at: "2026-06-15T09:00:00Z"',
        'finished_at: "2026-06-15T10:00:00Z"',
        "olaitan_eval_version: fixture",
        "success_criterion_met: false",
        f"measured_time_to_detect: {NEVER_DETECTED}",
        "measured_final_fsm_state: CLEAN",
        "fsm_state_source: none",
        # The benign sweep carries a single instance-00 per config (no pairing is
        # done on it); the key is recorded for shape-consistency with attack cells.
        "scenario_instance: 0",
        "resource_usage:",
        "  harness_alloc_bytes: 4194304",
        "  cluster_metrics_available: false",
        "size_bytes: 4096",
        "size_cap_exceeded: false",
    ]
    return "\n".join(lines) + "\n"


def _envelope(schema: str, subject: str, payload: Dict[str, object]) -> str:
    return json.dumps(
        {
            "schema_version": schema,
            "published_at": "2026-06-15T09:30:10Z",
            "subject": subject,
            "payload": payload,
        },
        sort_keys=True,
    )


def _fsm_jsonl(after_states: List[str]) -> str:
    lines = []
    for state in after_states:
        payload: Dict[str, object] = {
            "schema_version": "audit.transitions.v1",
            "after_state": state,
            "decided_at": "2026-06-15T09:30:18Z",
            "package_id": "pkg-fixture",
            "workload_id": "tenant-fixture/Deployment/web",
        }
        lines.append(_envelope("audit.transitions.v1", "AUDIT.transitions", payload))
    return ("\n".join(lines) + "\n") if lines else ""


def _assessments_jsonl(technique: str) -> str:
    payload: Dict[str, object] = {
        "schema_version": "audit.assessments.v2",
        "package_id": "pkg-fixture",
        "workload_id": "tenant-fixture/Deployment/web",
        "mode": "rsl",
        "mitre_techniques": [technique],
    }
    return _envelope("audit.assessments.v1", "AUDIT.assessments", payload) + "\n"


def _write_run(base: Path, run_id: str, files: Dict[str, str]) -> None:
    run_dir = base / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (run_dir / name).write_text(content, encoding="utf-8")


def generate(base: Path) -> None:
    base.mkdir(parents=True, exist_ok=True)
    for config in PRIMARY + ABLATION:
        detect_count = DETECT_COUNT[config]
        ttd = MTTD_SECONDS[config]
        for scenario in SCENARIOS:
            for index in range(N_PER_CELL):
                detected = index < detect_count
                run_id = f"fixture-{config}-{scenario}-{index:02d}"
                effective_ttd = ttd if detected else NEVER_DETECTED
                files = {
                    "metadata.yaml": _metadata(
                        run_id, config, scenario, detected, effective_ttd, index
                    ),
                    "fsm.jsonl": _fsm_jsonl(["QUARANTINED"] if detected else []),
                    "evidence.jsonl": "",
                    "events.jsonl": "",
                    "report.md": "fixture run (synthetic, not thesis data)\n",
                }
                if config in LLM_CONFIGS and detected:
                    # The LLM arms predict the ground-truth technique on detected
                    # runs (a perfect-agreement fixture -> kappa = 1.0, BI-6).
                    files["assessments.jsonl"] = _assessments_jsonl(GROUND_TRUTH[scenario])
                else:
                    files["assessments.jsonl"] = ""
                _write_run(base, run_id, files)

    # Benign sweep per primary config: a fixed escalation count over a 1-hour
    # window so FPR (escalations/hour) + the Poisson test produce a fixed,
    # non-degenerate result (BI-5). The LLM arms show a slightly higher (but
    # still below-bound) benign escalation count than the deterministic arms.
    benign_escalations = {"f": 0, "rs": 0, "rsl": 1, "rslt-full": 1}
    for config in PRIMARY:
        escalations = benign_escalations[config]
        run_id = f"fixture-{config}-benign-00"
        states = ["SUSPICIOUS"] * escalations
        files = {
            "metadata.yaml": _benign_metadata(run_id, config, escalations),
            "fsm.jsonl": _fsm_jsonl(states),
            "evidence.jsonl": "",
            "events.jsonl": "",
            "assessments.jsonl": "",
            "report.md": "fixture benign run (synthetic)\n",
        }
        _write_run(base, run_id, files)


if __name__ == "__main__":
    generate(Path(__file__).resolve().parent / "runs")
    print("fixtures regenerated under analysis/fixtures/runs/")
