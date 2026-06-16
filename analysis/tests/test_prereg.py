"""Unit tests for the prereg registry parser + exploratory classifier (BI-14)."""

from __future__ import annotations

from pathlib import Path

import pytest

from analysis.lib import prereg

_PREREG = "analysis/preregistration.md"


def test_parse_registry_strips_anchor_and_backticks() -> None:
    registry = prereg.parse_registry(_PREREG)
    # The exact-string member ids (BI-14): the anchor + backticks are stripped.
    expected = {
        "RQ1-DR-MCNEMAR",
        "RQ1-ATTACK-KAPPA",
        "RQ2-MTTD-KW-DUNN-HOLM",
        "RQ3-FPR-POISSON",
        "RQ4-ABL-L2-MCNEMAR",
        "RQ4-ABL-SENIOR-MCNEMAR",
        "RQ4-FR55-BOUND",
        "RQ5-RUBRIC-WILCOXON-CLARITY",
        "RQ5-ICC",
    }
    assert expected.issubset(set(registry.entries))


def test_exact_string_membership_not_field_parsed() -> None:
    registry = prereg.parse_registry(_PREREG)
    # The opaque ids (BI-14) do not split into metric/test fields.
    assert registry.is_confirmatory("RQ4-FR55-BOUND") is True
    assert registry.is_confirmatory("RQ5-ICC") is True
    # A non-member is exploratory.
    assert registry.is_confirmatory("RQ9-MADE-UP") is False
    assert registry.is_exploratory("RQ9-MADE-UP") is True


def test_corrected_alpha_read_from_registry() -> None:
    registry = prereg.parse_registry(_PREREG)
    # The four-way DR family corrects to 0.05 / 5 = 0.01 (BI-2).
    assert registry.corrected_alpha("RQ1-DR-MCNEMAR") == 0.01
    # The ablation family corrects to 0.05 / 10 = 0.005.
    assert registry.corrected_alpha("RQ4-ABL-L2-MCNEMAR") == 0.005
    # The FPR equivalence family corrects to 0.05 / 2 = 0.025 (the updated framing).
    assert registry.corrected_alpha("RQ3-FPR-POISSON") == 0.025


def test_missing_marker_fails_loud(tmp_path: Path) -> None:
    bad = tmp_path / "bad.md"
    bad.write_text("# no registry here\n", encoding="utf-8")
    with pytest.raises(ValueError):
        prereg.parse_registry(str(bad))
