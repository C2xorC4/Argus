"""Phase 5 — Triage.

Promotes findings DETECTED → CONFIRMED (or DISMISSED) per the
seven-stage pipeline. Per `docs/PIPELINE.md`, Triage runs between
Identification and Exploitation; its job is "true-positive
verification (path is reachable, no mitigating controls between
source and sink), mitigation-weighted exploitability scoring,
reachability validation, dismissal of heuristic false positives."

This scaffolding ships a **confidence-threshold auto-triage** as
the default. Findings whose `confidence` meets `min_confidence`
(default 0.0 — promote everything) advance to CONFIRMED. Findings
below threshold remain in DETECTED. Real triage will layer on
reachability + mitigation-bypass analysis per the `triage/` skill
module description in PIPELINE.md.

State transitions are recorded on each finding's `state_history`
audit trail with `actor="triage.auto_triage"`. Already-CONFIRMED
findings are not re-transitioned.

Public API:
- `auto_triage(findings, *, min_confidence=0.0, actor="triage.auto_triage")`
   → number of findings promoted.
"""

from __future__ import annotations

from typing import Iterable

from ..lib.state import (
    FindingState,
    IllegalTransition,
    transition,
)


def auto_triage(findings: Iterable, *,
                min_confidence: float = 0.0,
                actor: str = "triage.auto_triage") -> int:
    """Promote DETECTED findings to CONFIRMED per a confidence
    threshold.

    Returns the count of promotions. Findings already in CONFIRMED
    or downstream states are left untouched. Findings whose
    confidence is strictly below `min_confidence` are also left at
    DETECTED — caller can dismiss them in a separate pass.
    """
    promoted = 0
    for f in findings:
        state = getattr(f, "state", FindingState.DETECTED)
        if state != FindingState.DETECTED:
            continue
        conf = float(getattr(f, "confidence", 0.0) or 0.0)
        if conf < min_confidence:
            continue
        try:
            new_state, _rec = transition(
                f.state, FindingState.CONFIRMED,
                actor=actor,
                notes=f"auto-triaged at confidence {conf:.2f}",
                history=getattr(f, "state_history", None),
            )
            f.state = new_state
            promoted += 1
        except IllegalTransition:
            continue
        except Exception:
            continue
    return promoted


__all__ = ["auto_triage"]
