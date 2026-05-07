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
from scripts.triage import auto_triage

# Promote findings whose confidence meets the threshold
promoted = auto_triage(findings, min_confidence=0.5)
```

Wired into `dev/validate.py` and `vulntest/runner.py` between the
chain-match step and `compose_pocs`.

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
