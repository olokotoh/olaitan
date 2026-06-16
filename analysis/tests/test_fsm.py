"""Known-answer unit tests for the FSM escalation predicate (BI-5)."""

from __future__ import annotations

from analysis.lib import fsm


def test_clean_does_not_escalate() -> None:
    assert fsm.escalates_past_clean("CLEAN") is False


def test_states_past_clean_escalate() -> None:
    for state in ("SUSPICIOUS", "RESTRICTED", "QUARANTINED", "PRESERVED_KILLED"):
        assert fsm.escalates_past_clean(state) is True


def test_unknown_state_does_not_escalate() -> None:
    # Honest under-count over a fabricated escalation (BI-7).
    assert fsm.escalates_past_clean("NONSENSE") is False


def test_case_insensitive() -> None:
    assert fsm.escalates_past_clean("suspicious") is True
