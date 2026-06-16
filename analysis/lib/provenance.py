"""The manifest_hash / n / test provenance triad (Story 5.5, AC4/BI-10).

Every metric row AND every test-result row carries the triad:

* ``manifest_hash`` = the distinct ``manifest_sha256`` of the contributing runs
  (read from each run's ``metadata.yaml``).
* ``n`` = the sample size (contributing runs, or the paired n for a test).
* ``test`` = the statistical test name, or ``descriptive`` for a raw metric.

When a cell's contributing runs span MORE THAN ONE ``manifest_sha256`` (distinct
reproducibility envelopes) this is a violation of the single-envelope
assumption: record ALL distinct hashes and flag ``mixed_manifest: true`` (never
silently pool across envelopes, BI-10).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

import pandas as pd

# The provenance triad's ``test`` value for a raw (non-inferential) metric.
DESCRIPTIVE: str = "descriptive"

# The display value for an absent manifest hash (a cell with no runs).
_NO_MANIFEST: str = "n/a"

# The separator between distinct manifest hashes in the mixed-manifest case.
_HASH_SEP: str = ";"


@dataclass(frozen=True)
class Provenance:
    """The AC4/BI-10 provenance triad attached to every output row."""

    manifest_hash: str
    n: int
    test: str
    mixed_manifest: bool


def _distinct_manifest_hashes(cell: pd.DataFrame) -> List[str]:
    """The sorted distinct, non-null ``manifest_sha256`` values in a cell."""
    if "manifest_sha256" not in cell.columns:
        return []
    series = cell["manifest_sha256"].dropna().astype(str)
    distinct = sorted({value for value in series if value})
    return distinct


def cell_manifest(cell: pd.DataFrame) -> tuple[str, bool]:
    """Return the cell's manifest-hash display string and the mixed flag (BI-10).

    A single-envelope cell returns its one hash with ``mixed=False``. A cell
    spanning >1 distinct hash returns ALL of them (sorted, ``;``-joined) with
    ``mixed=True`` so the envelope mix is disclosed, never silently pooled. An
    empty cell returns ``n/a``.
    """
    hashes = _distinct_manifest_hashes(cell)
    if not hashes:
        return _NO_MANIFEST, False
    if len(hashes) == 1:
        return hashes[0], False
    return _HASH_SEP.join(hashes), True


def for_cell(cell: pd.DataFrame, n: int, test: str) -> Provenance:
    """Build the provenance triad for a metric/test row over ``cell`` (BI-10)."""
    manifest_hash, mixed = cell_manifest(cell)
    return Provenance(manifest_hash=manifest_hash, n=n, test=test, mixed_manifest=mixed)


def for_runs(frame: pd.DataFrame, n: int, test: str) -> Provenance:
    """Build the provenance triad over an arbitrary run subset (e.g. a test).

    Used for inferential rows whose contributing runs span more than one cell
    (the paired McNemar/KW inputs); the same mixed-manifest discipline applies.
    """
    return for_cell(frame, n=n, test=test)
