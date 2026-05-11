# `triage/__init__.py` — Manual-Workflow Companion

## Purpose

Phase 5 (Triage) stage of the seven-stage Argus pipeline. Promotes
findings DETECTED → CONFIRMED so downstream stages (Exploitation,
Verification) have eligible work to consume.

Per `docs/PIPELINE.md`, real triage validates true-positiveness via
reachability + mitigation analysis. The current scaffolding is a
**confidence-threshold auto-triage** as the default policy; all
findings whose `confidence` ≥ `min_confidence` advance.

## Programmatic invocation

```python
from scripts.triage import auto_triage, phase4_triage, apply_phase4_evidence

# Phase-5: DETECTED → CONFIRMED via confidence threshold.
promoted = auto_triage(findings, min_confidence=0.5)

# Phase-4 bridge: CONFIRMED → IMPACT_PENDING / IMPACT_VERIFIED via
# a declarative harness output. Walks each finding forward through
# any required intermediate states, emitting one StateTransition
# record per hop.
summary = apply_phase4_evidence(
    findings,
    evidence_path='vulntest/known-positive/dirty-frag/impact-verification/phase4-transitions.json',
)
# summary['findings_walked'] = N, summary['errors'] = [...]
```

Wired into `dev/validate.py` and `vulntest/runner.py` between the
chain-match step and `compose_pocs` (auto-triage). The
`phase4_triage` bridge is consumed by Phase-4 verification harnesses
(e.g. `verify_dirtyfrag.sh`) that emit a `phase4-transitions.json`
declaration alongside the raw evidence files.

### Phase-4 transition declaration schema

```json
{
  "schema_version": "1.0",
  "harness": "<harness-name>",
  "timestamp_utc": "<ISO 8601 UTC>",
  "transitions": [
    {
      "match": {
        "function": "<name>",          // exact match
        "category": "<category>",      // exact match
        "binary": "<substring>",       // substring match
        "detector": "<dotted-name>",   // exact match
        "address": "0x...",            // hex string or int
        "id": "<finding-id>"           // exact match
      },
      "target_state": "impact_verified",  // detected | confirmed | impact_pending | impact_verified | dismissed
      "reason": "free-text rationale",
      "evidence_ref": "<file>:<line>"     // optional pointer
    }
  ]
}
```

Any subset of `match` fields can be specified; multiple findings
matching the same criteria are all walked. Target state walks the
canonical forward path (DETECTED → CONFIRMED → IMPACT_PENDING →
IMPACT_VERIFIED) so the audit trail captures every intermediate hop.

## Manual workflow

This stage's "manual" form is operator triage review: examine each
DETECTED finding's evidence, confirm reachability + impact, and
explicitly transition state. The auto-triage shortcut is appropriate
for scaffolding-level operation; production runs should layer on
reachability gates.

1. For each DETECTED finding, examine `f.evidence` and
   `f.description` against the cited Knowledge entries.
2. Confirm reachability: is the finding's address reachable from a
   user-controllable input? (Network handler, file parser, IOCTL
   handler, etc.)
3. Confirm absence of mitigating controls: does the path to the
   sink avoid existing bounds checks, access controls,
   sanitisers?
4. **Transition decisions:**
   - True positive, reachable, no mitigation → `CONFIRMED`.
   - False positive (heuristic noise, code clearly safe) →
     `DISMISSED`.
   - Reachability or impact unclear → leave at `DETECTED` and
     flag for further analysis.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/argus_detector_design_principles]]` — the
  finding-state machine and why DETECTED→CONFIRMED triage is
  separate from detection.

## Divergence policy

- **Auto-triage for:** scaffolding runs against VulnTest cells
  where every emission corresponds to a real expected finding.
- **Manual triage for:** real-world targets where detector
  precision is sub-100%. Auto-triage at confidence-threshold-only
  promotes too many findings; reachability + mitigation gates
  belong in a future v2 of this module.
- **Never auto-promote** to `IMPACT_VERIFIED` — that transition
  belongs to Phase 7 (Verification).

## Operator-validation checklist

- [ ] After detector pipeline runs, `auto_triage(findings)`
      promotes all DETECTED findings to CONFIRMED.
- [ ] `compose_pocs(findings)` consumes CONFIRMED primitives and
      transitions them to IMPACT_PENDING.
- [ ] State transitions logged via `lib/state.transition()` —
      audit trail in `Finding.state_history` reflects the actor
      `triage.auto_triage`.
