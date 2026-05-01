# Manual-Workflow Companion Doc Index

Every Argus analysis module ships a companion document that maps the
programmatic flow to an equivalent human Binary-Ninja-UI sequence.

These docs serve three functions:

1. **Teaching artefact** for operators learning the methodology
   underlying each detector.
2. **Audit trail** explaining what the programmatic skill is
   approximating — useful when results need to be defended in a
   vendor report or peer review.
3. **Correctness check** — when the programmatic skill and the
   manual workflow disagree, the per-doc divergence policy decides
   which is authoritative for that vulnerability class.

## Template

[`_template.md`](manual_workflows/_template.md) — copy this when
authoring a new companion doc.

## Phase 1 deliverables

| Doc | Module | Status |
|---|---|---|
| [`analysis-surface.md`](manual_workflows/analysis-surface.md) | `scripts/analysis/surface.py` | done |
| [`analysis-mitigations.md`](manual_workflows/analysis-mitigations.md) | `scripts/analysis/mitigations.py` | done |
| [`analysis-taint.md`](manual_workflows/analysis-taint.md) | `scripts/analysis/taint.py` | done |
| [`analysis-heap.md`](manual_workflows/analysis-heap.md) | `scripts/analysis/heap.py` | done |
| [`analysis-crypto.md`](manual_workflows/analysis-crypto.md) | `scripts/analysis/crypto.py` | done |
| [`analysis-obfuscation.md`](manual_workflows/analysis-obfuscation.md) | `scripts/analysis/obfuscation.py` | done |
| [`analysis-chains.md`](manual_workflows/analysis-chains.md) | `scripts/analysis/chains.py` | done |
| [`analysis-attack_surface.md`](manual_workflows/analysis-attack_surface.md) | `scripts/analysis/attack_surface.py` | done |

## Later-phase deliverables

| Doc family | Phase | Notes |
|---|---|---|
| `exploit-*.md` | Phase 3 | Primitive construction (gadgets, shellcode, primitives, chain) |
| `verify-*.md` | Phase 4 | Sanitizer / debugger / triage |
| `differ-*.md` | Phase 5 | HLIL diff, fix-pattern recognition, 1-day workflow |
| `patch-*.md` | Phase 5 | Code-cave / detour / metadata fixup / VM-protector handling |

## Authoring guidelines

- Each doc starts with the **programmatic invocation** (the exact
  Python or CLI command that runs the module).
- The **manual workflow** section is a numbered Binja-UI sequence —
  every step a real keystroke or click. Reproducible by a human
  who has never seen the binary before.
- The **reference material** section lists the LJM Knowledge entries
  and reference-book chapters that ground the methodology. This is
  also the source material that flows into Phase 6 vendor-report
  templates per the
  [VulnTest README cross-link contract](../vulntest/README.md).
- The **divergence policy** section states who's authoritative
  (programmatic vs manual) per vulnerability class, with reasoning.
  Default: manual is authoritative for semantic-class bugs (logic,
  TOCTOU, business logic); programmatic is authoritative for
  mechanical-class bugs (hardcoded byte sequences, instruction-level
  patterns, hardening flag detection).
