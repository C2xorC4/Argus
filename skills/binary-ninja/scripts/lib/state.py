"""Finding state machine.

Reconciles LIFECYCLE.md (DETECTED / CONFIRMED / PROVEN) and
Methodology.md (DETECTED / CONFIRMED / IMPACT_VERIFIED) under one
unified four-state model plus a terminal DISMISSED state.

External output is gated to IMPACT_VERIFIED (alias PROVEN). Theoretical
findings stay in CONFIRMED or earlier and never appear in vendor
submissions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class FindingState(str, Enum):
    """Finding lifecycle state.

    Order of progression (most common path):
        DETECTED -> CONFIRMED -> IMPACT_PENDING -> IMPACT_VERIFIED

    DISMISSED is terminal and reachable from any non-terminal state.
    IMPACT_VERIFIED is terminal (PROVEN; alias preserved for
    LIFECYCLE.md vocabulary compatibility).
    """

    DETECTED = "detected"
    CONFIRMED = "confirmed"
    IMPACT_PENDING = "impact_pending"
    IMPACT_VERIFIED = "impact_verified"
    DISMISSED = "dismissed"

    # ----- Aliases / convenience -----

    @property
    def is_terminal(self) -> bool:
        return self in (FindingState.IMPACT_VERIFIED, FindingState.DISMISSED)

    @property
    def is_proven(self) -> bool:
        """LIFECYCLE.md vocabulary: PROVEN == IMPACT_VERIFIED."""
        return self is FindingState.IMPACT_VERIFIED

    @property
    def is_external_reportable(self) -> bool:
        """External output gate. Only IMPACT_VERIFIED reaches vendors."""
        return self is FindingState.IMPACT_VERIFIED


# Allowed transitions. Source state -> set of legal target states.
# Anything not listed is rejected by `transition()`.
_ALLOWED_TRANSITIONS: dict[FindingState, set[FindingState]] = {
    FindingState.DETECTED: {
        FindingState.CONFIRMED,
        FindingState.DISMISSED,
    },
    FindingState.CONFIRMED: {
        FindingState.IMPACT_PENDING,
        FindingState.IMPACT_VERIFIED,  # direct PROVEN when isolated PoC == launch-chain test
        FindingState.DISMISSED,
    },
    FindingState.IMPACT_PENDING: {
        FindingState.IMPACT_VERIFIED,
        FindingState.CONFIRMED,         # verification regressed — back to CONFIRMED
        FindingState.DISMISSED,
    },
    FindingState.IMPACT_VERIFIED: set(),
    FindingState.DISMISSED: set(),
}


class IllegalTransition(ValueError):
    """Raised when a state transition is not in the allowed set."""


@dataclass
class StateTransition:
    """One row of the Finding state-history audit trail."""

    from_state: FindingState
    to_state: FindingState
    timestamp: datetime
    actor: str                  # which agent / module / operator drove the transition
    evidence_ref: Optional[str] = None  # pointer into Finding.evidence list
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "timestamp": self.timestamp.isoformat(),
            "actor": self.actor,
            "evidence_ref": self.evidence_ref,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "StateTransition":
        return cls(
            from_state=FindingState(d["from_state"]),
            to_state=FindingState(d["to_state"]),
            timestamp=datetime.fromisoformat(d["timestamp"]),
            actor=d["actor"],
            evidence_ref=d.get("evidence_ref"),
            notes=d.get("notes", ""),
        )


def transition(
    current: FindingState,
    target: FindingState,
    actor: str,
    evidence_ref: Optional[str] = None,
    notes: str = "",
    history: Optional[list[StateTransition]] = None,
) -> tuple[FindingState, StateTransition]:
    """Apply a state transition with audit-trail bookkeeping.

    Returns the new state and the StateTransition record. Caller is
    responsible for appending the record to the Finding's
    `state_history` list.

    Raises IllegalTransition if the transition is not allowed.
    """
    if target not in _ALLOWED_TRANSITIONS.get(current, set()):
        raise IllegalTransition(
            f"{current.value} -> {target.value} is not an allowed transition. "
            f"From {current.value}, legal targets are: "
            f"{sorted(s.value for s in _ALLOWED_TRANSITIONS.get(current, set()))}"
        )

    record = StateTransition(
        from_state=current,
        to_state=target,
        timestamp=datetime.now(timezone.utc),
        actor=actor,
        evidence_ref=evidence_ref,
        notes=notes,
    )
    if history is not None:
        history.append(record)
    return target, record


def can_transition(current: FindingState, target: FindingState) -> bool:
    """Predicate version of `transition()` — does not raise."""
    return target in _ALLOWED_TRANSITIONS.get(current, set())


def legal_targets(current: FindingState) -> set[FindingState]:
    """Set of states reachable from `current` in one transition."""
    return frozenset(_ALLOWED_TRANSITIONS.get(current, set()))
