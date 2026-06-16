"""Pre-registration registry parsing + the exploratory classifier (Story 5.5).

Parses the confirmatory test registry from ``analysis/preregistration.md``
Section 8a (the canonical Markdown table keyed by ``test_id`` in the first
column, BI-14) into an allow-list plus the per-test correction family / corrected
alpha. 5.5 ENFORCES this; it does NOT re-choose the tests/alphas (BI-2).

The registry's first cell now looks like::

    <a id="rq1-dr-mcnemar"></a>`RQ1-DR-MCNEMAR`

so the parser strips the HTML anchor tag and the backticks to recover the bare
``test_id`` (BI-14). Membership is EXACT-STRING match on the whole ``test_id``;
the suffix is never field-parsed (``RQ4-FR55-BOUND`` and ``RQ5-ICC`` do not
split).

Any emitted ``test_id`` NOT in the registry is ``exploratory: true`` (BI-14);
registry members are ``exploratory: false``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

# Strip a leading ``<a id="..."></a>`` anchor then a backticked id from the
# registry's first cell (BI-14). The id itself is captured between backticks.
_ANCHOR_RE = re.compile(r"^\s*(?:<a\s+id=\"[^\"]*\"\s*>\s*</a>\s*)?`([^`]+)`\s*$")

# The fenced marker line proving the registry table is present (the Story-5.8
# committed marker). Used to fail LOUD if the table cannot be located, rather
# than silently treating every test as exploratory (BI-14, no-fabrication).
_REGISTRY_MARKER = "prereg-registry-marker"

# Match a "X / Y = Z" or "0.05 / 5 = 0.01" corrected-alpha inside the family
# cell so the per-test corrected alpha is read from the registry, not the prose.
_CORRECTED_ALPHA_RE = re.compile(r"=\s*([0-9]*\.?[0-9]+)\s*$")


@dataclass(frozen=True)
class RegistryEntry:
    """One confirmatory test: its id, RQ, and correction family / alpha cell."""

    test_id: str
    rq: str
    family_cell: str
    corrected_alpha: Optional[float]


@dataclass(frozen=True)
class Registry:
    """The parsed confirmatory registry: the allow-list keyed by ``test_id``."""

    entries: Dict[str, RegistryEntry]

    def is_confirmatory(self, test_id: str) -> bool:
        """Exact-string membership of ``test_id`` in the registry (BI-14)."""
        return test_id in self.entries

    def is_exploratory(self, test_id: str) -> bool:
        """A test is exploratory iff it is NOT a registry member (BI-14)."""
        return not self.is_confirmatory(test_id)

    def corrected_alpha(self, test_id: str) -> Optional[float]:
        """The registry's corrected alpha for ``test_id`` (``None`` when n/a)."""
        entry = self.entries.get(test_id)
        return entry.corrected_alpha if entry is not None else None


def _parse_table_id(cell: str) -> Optional[str]:
    """Recover the bare ``test_id`` from a registry first-cell (BI-14)."""
    match = _ANCHOR_RE.match(cell)
    if match is None:
        return None
    return match.group(1).strip()


def _parse_corrected_alpha(family_cell: str) -> Optional[float]:
    """Read the corrected alpha from a family cell, or ``None`` when n/a."""
    match = _CORRECTED_ALPHA_RE.search(family_cell.strip())
    if match is None:
        return None
    return float(match.group(1))


def parse_registry(prereg_path: str) -> Registry:
    """Parse the confirmatory registry from ``preregistration.md`` (BI-14).

    Reads only the Markdown table whose first column carries the backticked
    ``test_id`` (Section 8a). Fails LOUD (raises) when the registry marker is
    absent, so a mis-located registry can never silently degrade every
    confirmatory test to exploratory.
    """
    text = Path(prereg_path).read_text(encoding="utf-8")
    if _REGISTRY_MARKER not in text:
        raise ValueError(
            f"prereg {prereg_path!r} is missing the {_REGISTRY_MARKER} marker; "
            "cannot locate the confirmatory registry (BI-14)"
        )
    entries: Dict[str, RegistryEntry] = {}
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 5:
            continue
        test_id = _parse_table_id(cells[0])
        if test_id is None:
            continue
        family_cell = cells[4]
        entries[test_id] = RegistryEntry(
            test_id=test_id,
            rq=cells[1],
            family_cell=family_cell,
            corrected_alpha=_parse_corrected_alpha(family_cell),
        )
    if not entries:
        raise ValueError(
            f"prereg {prereg_path!r} registry parsed to zero test_ids (BI-14)"
        )
    return Registry(entries=entries)
