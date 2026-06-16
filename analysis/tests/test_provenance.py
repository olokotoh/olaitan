"""Unit tests for the provenance triad attachment (Story 5.5, AC4/BI-10)."""

from __future__ import annotations

import pandas as pd

from analysis.lib import provenance


def _cell(hashes: list[object]) -> pd.DataFrame:
    return pd.DataFrame({"manifest_sha256": hashes, "run_id": [f"r{i}" for i in range(len(hashes))]})


def test_single_manifest_not_mixed() -> None:
    cell = _cell(["abc", "abc", "abc"])
    manifest_hash, mixed = provenance.cell_manifest(cell)
    assert manifest_hash == "abc"
    assert mixed is False


def test_mixed_manifest_flagged_not_averaged() -> None:
    # >1 distinct hash -> record ALL, flag mixed (never silently pool, BI-10).
    cell = _cell(["abc", "def"])
    manifest_hash, mixed = provenance.cell_manifest(cell)
    assert mixed is True
    assert "abc" in manifest_hash
    assert "def" in manifest_hash
    assert ";" in manifest_hash


def test_empty_cell_is_na() -> None:
    cell = _cell([])
    manifest_hash, mixed = provenance.cell_manifest(cell)
    assert manifest_hash == "n/a"
    assert mixed is False


def test_for_cell_triad() -> None:
    cell = _cell(["abc", "abc"])
    triad = provenance.for_cell(cell, n=2, test="mcnemar")
    assert triad.manifest_hash == "abc"
    assert triad.n == 2
    assert triad.test == "mcnemar"
    assert triad.mixed_manifest is False
