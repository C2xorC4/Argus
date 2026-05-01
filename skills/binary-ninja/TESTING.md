# Argus Binary-Ninja Skill — Testing Status

Records LIFECYCLE.md quality-gate results per phase. All six gates
must pass before promotion to `~/.claude/`. A single failure blocks
promotion.

## Gates (per LIFECYCLE.md §4)

| Gate | Criteria |
|---|---|
| Detection | 100% TP on applicable VulnTest programs |
| No FPs | 0 false positives against test corpus + clean controls |
| PoC validation | generated PoCs trigger their target vulnerability |
| Output contract | Finding v2 + SARIF 2.1.0 conformance |
| Pipeline integration | end-to-end run passes against real + synthetic targets |
| Documentation | TESTING.md + MANUAL_WORKFLOWS.md + per-Finding Knowledge citations complete |

## Phase 0 — Architecture + shared infrastructure

**Status: complete (2026-04-30).** Phase 0 is foundational; the
gates that apply at this phase are a subset:

| Gate | Status | Notes |
|---|---|---|
| Detection | n/a | No detectors land in Phase 0 |
| No FPs | n/a | No detectors land in Phase 0 |
| PoC validation | n/a | No detectors land in Phase 0 |
| **Output contract** | **PASS (smoke)** | Finding v2 schema implemented; SARIF + markdown renderers smoke-tested round-trip; `FINDING_V2_SCHEMA` exported for validators. Full JSON-Schema validator integration deferred to Phase 1. |
| **Pipeline integration** | **PASS (smoke)** | Construct Finding → transition through state machine → render SARIF + markdown → round-trip via `to_dict`/`from_dict`. End-to-end import + smoke verified 2026-04-29; re-verified 2026-04-30 after VulnTest corpus + cookbook integration. |
| **Documentation** | **PASS** | This file, README, PIPELINE.md, SKILL.md, MANUAL_WORKFLOWS.md, manual_workflows/_template.md, docs/binja-cookbook-reference.md all written. Per-module manual-workflow docs deferred to Phase 1 (no analysis modules to document yet). |

### Phase 0 deliverable inventory (2026-04-30)

| Item | Location | Status |
|---|---|---|
| Pipeline architecture | `docs/PIPELINE.md` | done |
| Finding v2 schema | `skills/binary-ninja/scripts/output/finding.py` | done |
| State machine | `skills/binary-ninja/scripts/lib/state.py` | done |
| Knowledge integration helper | `skills/binary-ninja/scripts/lib/knowledge.py` | done |
| Bash equivalent | `skills/binary-ninja/scripts/lib/jm-helper.sh` | done |
| Binja headless wrapper | `skills/binary-ninja/scripts/lib/binja.py` | done |
| SARIF renderer | `skills/binary-ninja/scripts/output/sarif.py` | done |
| Markdown renderer | `skills/binary-ninja/scripts/output/markdown.py` | done |
| Orchestrator agent | `agents/binary-research-orchestrator.md` | done |
| Manual-workflow template + index | `skills/binary-ninja/manual_workflows/_template.md`, `MANUAL_WORKFLOWS.md` | done |
| Binja cookbook reference | `skills/binary-ninja/docs/binja-cookbook-reference.md` | done (2026-04-30) |
| VulnTest corpus — Tier 1 | `vulntest/tier1-single/` | done — 60 cells (C+C++ baseline, headline-four C#/Rust/Go, Win-specific) |
| VulnTest corpus — Tier 2 skeletons | `vulntest/tier2-chains/` | done — 2 chains (EAC, UE5) |
| VulnTest corpus — Tier 3 demo | `vulntest/tier3-obfuscated/` | done — symbol-strip variant |
| INDEX.md populated | `vulntest/INDEX.md` | done |

### Phase 0 smoke test (2026-04-30 closeout)

Run from `D:\Repos\Security\Argus\skills\binary-ninja`:

```python
from scripts.output import Finding, Severity, DisclosureAltitude
from scripts.lib import FindingState, transition

f = Finding(
    id="",
    category="direct_syscall_stub",
    severity=Severity.HIGH,
    address=0x401000,
    function="sub_401000",
    binary="/tmp/sample.exe",
    arch="x86_64",
    platform="windows",
    detector="heuristics.syscalls",
    knowledge_refs=["[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]"],
)
ns, rec = transition(f.state, FindingState.CONFIRMED, actor="triage-analyst")
f.state, _ = transition(ns, FindingState.IMPACT_VERIFIED, actor="poc-validator")
```

Verifies: Finding construction, deterministic id hashing, state-machine
transitions (DETECTED→CONFIRMED→IMPACT_VERIFIED), illegal-transition
rejection (CONFIRMED→DETECTED), `to_dict`/`from_dict` round-trip,
SARIF rendering, markdown rendering. All passed 2026-04-29; re-run
2026-04-30 to confirm corpus / cookbook integration didn't regress.

### Cookbook reference parity check

`docs/binja-cookbook-reference.md` mirrors
<https://docs.binary.ninja/dev/cookbook.html> as of 2026-04-30.

Re-fetch + diff at minor-version bumps of Binary Ninja
(`core_version_info()` jumps in major or minor). Update the local
mirror and the LJM Knowledge entry (`binja_python_api_cookbook`)
together — they should not drift apart.

## Phase 1 — Identification stage rebase

**Status: ready to start.** All Phase-0 inputs in place. Phase 1
populates `analysis/` modules and `heuristics/` pattern tables;
runs gates against the Phase-0 VulnTest corpus.

Expected gate-by-gate plan:

- **Detection / FPs:** measured against `vulntest/` Tier 1 corpus.
  C and C++ columns must achieve 100% TP / 0 FP for every Phase 1
  detection category before any module promotes. C#/Rust/Go variants
  for the headline-four classes progress in parallel; lower bar for
  Phase 1 promotion (≥ 80% TP, 0 FP).
- **PoC validation:** Phase 1 ships trigger-only stubs (full
  exploitation is Phase 3). Trigger-only PoCs must reach the bug
  on every exploitable VulnTest program.
- **Output contract:** every emitted Finding validates against
  `FINDING_V2_SCHEMA`; SARIF renders against schemastore SARIF 2.1.0.
- **Pipeline integration:** orchestrator + recon + identification +
  triage on at least one VulnTest program and one real-world target.
- **Documentation:** per-module manual-workflow companion doc;
  every Finding category cites its source Knowledge entry; substrate-
  coherence check passes (`jm associate` surfaces the cited entry as
  a top match).

## Promotion log

No promotions yet. Phase 0 lays the foundation in
`D:\Repos\Security\Argus\` only; promotion to `~/.claude/` waits for
Phase 1 gate clearance per LIFECYCLE.md §5.
