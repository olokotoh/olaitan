"""The FSM escalation ordering the FPR count uses (Story 5.5, BI-5).

Mirrors the single canonical ordering the Go FSM enforces
(``internal/schema/state.go`` StateRank: CLEAN < SUSPICIOUS < RESTRICTED <
QUARANTINED < PRESERVED_KILLED). The pipeline only needs the "is this state
past CLEAN" predicate for the benign-sweep escalation count (BI-5); it does NOT
re-implement the FSM, it reads the ``after_state`` the Story-5.4 ``fsm.jsonl``
already recorded.
"""

from __future__ import annotations

from typing import Dict

# The canonical FSM escalation ranks (CLEAN is the non-escalated baseline). An
# unknown state name is treated as NOT-an-escalation (rank below CLEAN) so a
# malformed after_state can never inflate the FPR count (BI-5, BI-7 honesty).
_STATE_RANK: Dict[str, int] = {
    "CLEAN": 0,
    "SUSPICIOUS": 1,
    "RESTRICTED": 2,
    "QUARANTINED": 3,
    "PRESERVED_KILLED": 4,
}

_CLEAN_RANK: int = _STATE_RANK["CLEAN"]


def escalates_past_clean(after_state: str) -> bool:
    """True when ``after_state`` ranks strictly above CLEAN (an escalation).

    Drives the FPR escalation count on the benign sweep (BI-5). An unknown
    state name is NOT counted as an escalation (honest under-count over a
    fabricated escalation, BI-7).
    """
    rank = _STATE_RANK.get(after_state.upper())
    if rank is None:
        return False
    return rank > _CLEAN_RANK
