"""Phase 5 — Triage.

Promotes findings DETECTED → CONFIRMED (or DISMISSED) per the
seven-stage pipeline. Per `docs/PIPELINE.md`, Triage runs between
Identification and Exploitation; its job is "true-positive
verification (path is reachable, no mitigating controls between
source and sink), mitigation-weighted exploitability scoring,
reachability validation, dismissal of heuristic false positives."

This module ships TWO entry points:

1. **`auto_triage`** — confidence-threshold promotion DETECTED →
   CONFIRMED. Default `min_confidence=0.0` promotes everything.
2. **`phase4_triage`** — declarative bridge from Phase-4 harness
   output (JSON) into IMPACT_PENDING / IMPACT_VERIFIED states.
   Walks each matching finding forward through any required
   intermediate states (DETECTED → CONFIRMED → IMPACT_PENDING →
   IMPACT_VERIFIED), emitting a StateTransition record per hop.

State transitions are recorded on each finding's `state_history`
audit trail with `actor="triage.auto_triage"` (auto path) or
`actor="triage.phase4:<harness>"` (Phase-4 path). Already-terminal
findings (IMPACT_VERIFIED, DISMISSED) are not re-transitioned.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Optional, Union

from ..lib.state import (
    FindingState,
    IllegalTransition,
    transition,
)


# Forward-walk path on the state machine: each entry maps
# `target_state` → list of intermediate states that must be passed
# through if the finding is currently at DETECTED.
_FORWARD_PATH: dict[FindingState, tuple[FindingState, ...]] = {
    FindingState.CONFIRMED: (FindingState.CONFIRMED,),
    FindingState.IMPACT_PENDING: (
        FindingState.CONFIRMED,
        FindingState.IMPACT_PENDING,
    ),
    FindingState.IMPACT_VERIFIED: (
        FindingState.CONFIRMED,
        FindingState.IMPACT_PENDING,
        FindingState.IMPACT_VERIFIED,
    ),
    FindingState.DISMISSED: (FindingState.DISMISSED,),
}


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


# ─────────────────────────────────────────────────────────────────
# Phase-4 declarative bridge
# ─────────────────────────────────────────────────────────────────


def _coerce_state(value: Union[str, FindingState]) -> FindingState:
    if isinstance(value, FindingState):
        return value
    s = str(value).lower().strip()
    return FindingState(s)


def _finding_matches(f, criteria: dict) -> bool:
    """A criteria dict can specify any combination of:
    `function`, `category`, `binary`, `detector`, `address` (int hex
    string or int), `id`. Empty criteria match all findings (caller
    filtering responsibility)."""
    if not criteria:
        return False  # safety: don't blanket-promote

    if "id" in criteria and getattr(f, "id", None) != criteria["id"]:
        return False
    if "function" in criteria and getattr(f, "function", None) != criteria["function"]:
        return False
    if "category" in criteria and getattr(f, "category", None) != criteria["category"]:
        return False
    if "detector" in criteria and getattr(f, "detector", None) != criteria["detector"]:
        return False
    if "binary" in criteria:
        # Allow substring match on binary path so callers can write
        # `"binary": "esp4.ko"` instead of the full path.
        binary = getattr(f, "binary", "") or ""
        if criteria["binary"] not in binary:
            return False
    if "address" in criteria:
        want = criteria["address"]
        if isinstance(want, str):
            want = int(want, 0)  # accepts "0x..." or decimal
        if int(getattr(f, "address", -1)) != int(want):
            return False
    return True


def phase4_triage(findings: list,
                  declaration: Union[str, Path, dict],
                  *,
                  actor_prefix: str = "triage.phase4") -> dict:
    """Apply a Phase-4 transition declaration to `findings`.

    The declaration is either:
    - A path / Path object to a JSON file
    - A dict with the same shape as the JSON file

    Schema (`schema_version: "1.0"`):
    {
      "schema_version": "1.0",
      "harness": "<harness-name>",                  // e.g. "verify_dirtyfrag.sh"
      "timestamp_utc": "<ISO 8601 UTC>",            // optional, audit trail
      "transitions": [
        {
          "match": {                                 // any subset of fields
            "function": "esp_input",                 // exact match
            "category": "decrypt_into_external_pages",
            "binary": "esp4.ko",                     // substring match
            "detector": "analysis.decrypt_external_pages",
            "address": "0x4010d5",                   // hex or int
            "id": "<finding-id>"
          },
          "target_state": "impact_verified",         // detected | confirmed | impact_pending | impact_verified | dismissed
          "reason": "free-text rationale",           // appended to history.notes
          "evidence_ref": "exp_esp.stderr:3"         // optional pointer
        },
        ...
      ]
    }

    For each transition entry, all matching findings are walked
    forward to `target_state`. Walking goes through the canonical
    intermediate states (e.g., DETECTED → CONFIRMED →
    IMPACT_PENDING → IMPACT_VERIFIED) so the audit trail captures
    every hop. Already-at-target findings are left untouched. The
    DISMISSED target is allowed but only as a single hop from the
    current state, never via a forward walk.

    Returns a summary dict:
    {
      "harness": "<harness>",
      "transitions_applied": int,
      "findings_walked": int,
      "skipped_already_target": int,
      "skipped_no_match": int,
      "errors": [
        {"match": {...}, "error": "..."},
        ...
      ]
    }
    """
    if isinstance(declaration, (str, Path)):
        with open(declaration, "r", encoding="utf-8") as fp:
            decl = json.load(fp)
    else:
        decl = dict(declaration)

    schema_version = str(decl.get("schema_version", ""))
    if schema_version not in ("", "1.0"):
        raise ValueError(
            f"phase4_triage: unsupported schema_version={schema_version!r}; "
            f"expected 1.0"
        )
    harness = str(decl.get("harness", "<unknown>"))
    actor = f"{actor_prefix}:{harness}"
    timestamp = decl.get("timestamp_utc")
    transitions_decl = decl.get("transitions", []) or []

    summary = {
        "harness": harness,
        "timestamp_utc": timestamp,
        "transitions_applied": 0,
        "findings_walked": 0,
        "skipped_already_target": 0,
        "skipped_no_match": 0,
        "errors": [],
    }

    for entry in transitions_decl:
        match = entry.get("match", {}) or {}
        try:
            target = _coerce_state(entry.get("target_state"))
        except Exception as e:
            summary["errors"].append({"match": match, "error": f"bad target_state: {e}"})
            continue
        reason = entry.get("reason", "") or ""
        evidence_ref = entry.get("evidence_ref")

        matched = [f for f in findings if _finding_matches(f, match)]
        if not matched:
            summary["skipped_no_match"] += 1
            continue
        summary["transitions_applied"] += 1

        for f in matched:
            cur = getattr(f, "state", FindingState.DETECTED)
            if cur == target:
                summary["skipped_already_target"] += 1
                continue
            try:
                _walk_forward(f, target, actor=actor,
                              reason=reason, evidence_ref=evidence_ref)
                summary["findings_walked"] += 1
            except IllegalTransition as e:
                summary["errors"].append({
                    "match": match,
                    "finding": _summarise_finding(f),
                    "error": f"illegal transition: {e}",
                })
            except Exception as e:
                summary["errors"].append({
                    "match": match,
                    "finding": _summarise_finding(f),
                    "error": f"{type(e).__name__}: {e}",
                })

    return summary


def _walk_forward(f, target: FindingState, *, actor: str,
                  reason: str, evidence_ref: Optional[str]) -> None:
    """Walk a single finding from its current state to `target` via
    the canonical forward path. Raises IllegalTransition if any hop
    along the way is rejected (e.g., target unreachable from
    current).
    """
    if target == FindingState.DETECTED:
        # Backward target — not supported via forward walk.
        raise IllegalTransition(
            "phase4_triage cannot transition findings BACK to DETECTED"
        )
    cur = getattr(f, "state", FindingState.DETECTED)
    if cur == FindingState.IMPACT_VERIFIED or cur == FindingState.DISMISSED:
        # Terminal — no transitions out.
        raise IllegalTransition(
            f"{cur.value} is terminal; cannot walk to {target.value}"
        )

    # DISMISSED is a single-hop target from any non-terminal state.
    if target == FindingState.DISMISSED:
        new_state, _rec = transition(
            cur, FindingState.DISMISSED, actor=actor,
            notes=reason, evidence_ref=evidence_ref,
            history=getattr(f, "state_history", None),
        )
        f.state = new_state
        return

    path = _FORWARD_PATH.get(target)
    if path is None:
        raise IllegalTransition(f"no forward path defined for target {target.value}")

    # Skip path entries we've already passed.
    started = False
    for next_state in path:
        if not started:
            if cur == next_state:
                started = True
                continue
            # If we haven't started AND `next_state` is "before" `cur`
            # in the forward path, we've already passed it; skip.
            ordering = (FindingState.DETECTED, FindingState.CONFIRMED,
                        FindingState.IMPACT_PENDING,
                        FindingState.IMPACT_VERIFIED)
            try:
                cur_idx = ordering.index(cur)
                next_idx = ordering.index(next_state)
            except ValueError:
                cur_idx = next_idx = 0
            if next_idx <= cur_idx:
                continue
            started = True
        # Hop from cur → next_state.
        new_state, _rec = transition(
            cur, next_state, actor=actor,
            notes=reason, evidence_ref=evidence_ref,
            history=getattr(f, "state_history", None),
        )
        f.state = new_state
        cur = new_state
        if cur == target:
            return


def _summarise_finding(f) -> dict:
    return {
        "id": getattr(f, "id", None),
        "category": getattr(f, "category", None),
        "function": getattr(f, "function", None),
        "binary": getattr(f, "binary", None),
        "address": hex(int(getattr(f, "address", 0))) if hasattr(f, "address") else None,
    }


# ─────────────────────────────────────────────────────────────────
# Convenience: load harness JSON + apply
# ─────────────────────────────────────────────────────────────────


def apply_phase4_evidence(findings: list, evidence_path: Union[str, Path],
                          *, actor_prefix: str = "triage.phase4") -> dict:
    """Convenience wrapper for the common pattern: read a harness's
    transition declaration from `evidence_path` and apply it to the
    in-memory findings list. Returns the same summary dict as
    `phase4_triage`.
    """
    return phase4_triage(findings, Path(evidence_path),
                         actor_prefix=actor_prefix)


__all__ = ["auto_triage", "phase4_triage", "apply_phase4_evidence",
           "_FORWARD_PATH"]
