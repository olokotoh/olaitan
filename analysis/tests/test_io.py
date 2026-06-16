"""Known-answer unit tests for the run-artefact loader (Story 5.5, AC1/BI-7)."""

from __future__ import annotations

from pathlib import Path

from analysis.lib import io


def _write_run(base: Path, run_id: str, config: str, scenario: str, detected: bool) -> None:
    run_dir = base / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "metadata.yaml").write_text(
        "\n".join(
            [
                f"run_id: {run_id}",
                "manifest_sha256: abc123",
                f"scenario: {scenario}",
                f"config: {config}",
                'started_at: "2026-06-15T09:30:00Z"',
                'finished_at: "2026-06-15T09:31:00Z"',
                f"success_criterion_met: {'true' if detected else 'false'}",
                f"measured_time_to_detect: {18 if detected else -1}",
                "measured_final_fsm_state: QUARANTINED",
                "fsm_state_source: observed_transitions",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def test_load_run_set_skips_example_and_dotfiles(tmp_path: Path) -> None:
    _write_run(tmp_path, "run-a", "rsl", "s1", True)
    _write_run(tmp_path, "example", "rsl", "s1", True)  # the skeleton: skipped
    (tmp_path / ".hidden").mkdir()
    run_set = io.load_run_set(str(tmp_path))
    assert run_set.frame.shape[0] == 1
    assert run_set.frame["run_id"].iloc[0] == "run-a"
    assert run_set.is_fixture is False


def test_load_run_set_sorted_deterministic(tmp_path: Path) -> None:
    _write_run(tmp_path, "run-z", "rsl", "s1", True)
    _write_run(tmp_path, "run-a", "rsl", "s1", False)
    run_set = io.load_run_set(str(tmp_path))
    # Sorted by (config, scenario, run_id) for byte-determinism (BI-13).
    assert list(run_set.frame["run_id"]) == ["run-a", "run-z"]


def test_load_run_set_typed_columns(tmp_path: Path) -> None:
    _write_run(tmp_path, "run-a", "rsl", "s1", True)
    run_set = io.load_run_set(str(tmp_path))
    row = run_set.frame.iloc[0]
    assert bool(row["success_criterion_met"]) is True
    assert int(row["measured_time_to_detect"]) == 18


def test_fixture_flagged_off_run_id_prefix(tmp_path: Path) -> None:
    # L1: is_fixture is driven by the per-run ``fixture-`` run_id prefix, not the
    # path. Every run carrying the prefix -> fixture: true.
    runs = tmp_path / "runs"
    _write_run(runs, "fixture-a", "rsl", "s1", True)
    _write_run(runs, "fixture-b", "rsl", "s2", False)
    run_set = io.load_run_set(str(runs))
    assert run_set.is_fixture is True


def test_real_run_under_fixtures_path_not_flagged(tmp_path: Path) -> None:
    # L1: a REAL run-set (no ``fixture-`` prefix) under a path that contains a
    # ``fixtures`` segment must NOT be mislabelled fixture: true.
    fixtures = tmp_path / "fixtures" / "runs"
    _write_run(fixtures, "20260615T093000.000Z-s1-rsl-abc123", "rsl", "s1", True)
    run_set = io.load_run_set(str(fixtures))
    assert run_set.is_fixture is False


def test_scenario_instance_key_prefers_explicit_field() -> None:
    # H2: the explicit scenario_instance field wins; else the run_id -NN suffix.
    assert io.scenario_instance_key("20260615T093000.000Z-s1-rsl-abc", 3) == "3"
    assert io.scenario_instance_key("fixture-rsl-s1-02", None) == "02"
    # A real run_id (hash-suffixed) with no explicit field has no parseable index.
    assert io.scenario_instance_key("20260615T093000.000Z-s1-rsl-abc123", None) is None


def test_fsm_after_states(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-a"
    run_dir.mkdir()
    (run_dir / "fsm.jsonl").write_text(
        '{"schema_version":"audit.transitions.v1","payload":{"after_state":"SUSPICIOUS"}}\n'
        '{"schema_version":"audit.transitions.v1","payload":{"after_state":"QUARANTINED"}}\n',
        encoding="utf-8",
    )
    assert io.fsm_after_states(run_dir) == ["SUSPICIOUS", "QUARANTINED"]


def test_fsm_after_states_missing_file_is_empty(tmp_path: Path) -> None:
    assert io.fsm_after_states(tmp_path / "absent") == []
