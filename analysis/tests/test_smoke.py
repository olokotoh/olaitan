"""Deterministic full-pipeline smoke test on the committed fixtures (BI-13).

Runs the FULL ``analyse.py`` pipeline on the committed synthetic
``analysis/fixtures/runs/`` and asserts BYTE-DETERMINISTIC output against the
committed golden (``analysis/fixtures/golden/``): the same ``summary.csv`` +
``summary.md`` every run. It also asserts the honesty + structural invariants
(BI-7, BI-10, BI-14): the metrics compute, the inferential tests run-or-skip
honestly (never a fabricated p-value), the provenance triad is present on every
row, the fixture header is labelled ``fixture: true``, and the Exploratory
section exists. If the pipeline or the fixtures change intentionally, regenerate
the golden with ``python analysis/analyse.py --runs analysis/fixtures/runs/
--output analysis/fixtures/golden/``.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from analysis import analyse
from analysis.lib import tests as test_helpers

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_GOLDEN = _REPO_ROOT / "analysis" / "fixtures" / "golden"

# The relative paths the pipeline is invoked with (so the ``runs_dir`` recorded
# in the output header is the stable repo-relative form the golden was generated
# with, machine-independent for CI determinism, BI-13). The smoke test chdirs to
# the repo root so these resolve identically on any checkout.
_FIXTURES_REL = "analysis/fixtures/runs"
_PREREG_REL = "analysis/preregistration.md"


@contextmanager
def _at_repo_root() -> Iterator[None]:
    """Run with the repo root as CWD so the relative paths resolve stably."""
    previous = Path.cwd()
    os.chdir(_REPO_ROOT)
    try:
        yield
    finally:
        os.chdir(previous)


def _run(tmp_path: Path) -> tuple[str, str]:
    with _at_repo_root():
        result = analyse.run_pipeline(_FIXTURES_REL, _PREREG_REL)
        analyse.write_outputs(result, str(tmp_path))
    csv_text = (tmp_path / "summary.csv").read_text(encoding="utf-8")
    md_text = (tmp_path / "summary.md").read_text(encoding="utf-8")
    return csv_text, md_text


def _pipeline() -> analyse.PipelineResult:
    """Run the pipeline at the repo root and return its in-memory result."""
    with _at_repo_root():
        return analyse.run_pipeline(_FIXTURES_REL, _PREREG_REL)


def test_smoke_matches_golden_csv(tmp_path: Path) -> None:
    csv_text, _ = _run(tmp_path)
    golden = (_GOLDEN / "summary.csv").read_text(encoding="utf-8")
    assert csv_text == golden


def test_smoke_matches_golden_md(tmp_path: Path) -> None:
    _, md_text = _run(tmp_path)
    golden = (_GOLDEN / "summary.md").read_text(encoding="utf-8")
    assert md_text == golden


def test_smoke_byte_deterministic_across_two_runs(tmp_path: Path) -> None:
    # BI-13: the pipeline is byte-identical on a second invocation (seeded RNG,
    # sorted iteration, no wall-clock).
    first = _run(tmp_path / "a")
    second = _run(tmp_path / "b")
    assert first == second


def test_smoke_header_is_fixture_labelled() -> None:
    result = _pipeline()
    assert result.header["fixture"] is True
    assert result.header["total_runs"] == 124


def test_smoke_provenance_triad_on_every_row() -> None:
    result = _pipeline()
    for row in result.rows:
        # The AC4/BI-10 triad: manifest_hash + n + test on every row.
        assert row.manifest_hash != ""
        assert isinstance(row.n, int)
        assert row.test != ""


def test_smoke_inferential_tests_run_or_skip_honestly() -> None:
    result = _pipeline()
    test_rows = [r for r in result.rows if r.test_id]
    assert test_rows, "expected at least one inferential-test row"
    for row in test_rows:
        # BI-7: a test either ran (p present) or skipped honestly (no fabricated p).
        if row.status == test_helpers.STATUS_RUN:
            continue
        assert "skipped" in row.status
        assert row.p_value is None


def test_smoke_exploratory_section_present_and_empty() -> None:
    # Every emitted test_id is in the registry, so the exploratory section is
    # present but empty (BI-14): the contract is enforced even with no members.
    result = _pipeline()
    exploratory = [r for r in result.rows if r.section == "exploratory"]
    assert exploratory == []
    _, md_text = _run_to_text()
    assert "## Exploratory analyses" in md_text


def _run_to_text() -> tuple[str, str]:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        return _run(Path(tmp))


def test_smoke_confirmatory_tests_are_registry_members() -> None:
    result = _pipeline()
    for row in result.rows:
        if row.section in {"confirmatory", "ablation"} and row.test_id:
            assert row.exploratory is False
