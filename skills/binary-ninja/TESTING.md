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

**Status: substantially complete (Run 14, 2026-05-04 onward).**
E1–E7 enhancements landed; 13/13 BYOVD multi-driver detection;
CVE-2026-31431 (Linux kernel `algif_aead`/`authencesn` page-cache
OOB write) detected on stripped `authencesn.ko` with 6 TP call
sites. Per-seed visited tracking + generalised visited-key principle
in `analysis/_DETECTOR_CHECKLIST.md` (Run 14 fix). Phase-1 detector
modules in tree: `analysis/{taint,heap,crypto,obfuscation,
windows_drivers,uninit,types,race,mitigations,surface,source_surface}.py`.

Phase-1 gates have been measured per-detector during the dogfood
runs but no module has been formally promotion-cleared (Gate 6
TESTING.md was the gating artefact — this update reopens that
cleanup path).

## Phase 2 — Source-Guided enrichment

**Status: substantially complete (closed 2026-05-07).** All three
Epic-submission coverage gaps now have implementing detectors with
end-to-end Tier-1 cell validation:

- Gap 1 (SDDL/ACE) → `analysis/sddl.py`
- Gap 2 (write-then-verify) → `analysis/integrity_check_order.py` v3
  with verify-call-dominates-commit order check
- Gap 3 (PRNG provenance) → `analysis/crypto.py` Path A/B/C +
  `find_iv_reuse` + custom-cipher patterns

| Gate | Status | Evidence |
|---|---|---|
| Detection | ✅ | All three Phase-2 Tier-1 cells PASS clean (`permissive-sddl/c`, `null-dacl/c`, `pre-verify-write/c`). PRNG cells PASS clean (`prng-security-path/c`, `prng-security-path/cpp`). IV-reuse cell PASS clean. |
| No FPs | ✅ | Clean controls (`remediation/`) emit zero findings of the expected category. Sweep against `utilman.exe`, `sethc.exe`, `osk.exe`, `notepad.exe`, `calc.exe`, `xcopy.exe`, `where.exe`, `whoami.exe` (8 binaries) — zero `permissive_sddl` / `null_dacl` / `pre_verification_write` / `weak_prng_in_security_path` / `iv_reuse` FPs. |
| PoC validation | ⚠️ deferred | Phase 3 scaffolding in tree but no PoC has been independently triggered against a live target (Phase 4 verification scope). |
| Output contract | ✅ | All emissions are Finding v2; SARIF + markdown renderers consume them. |
| Pipeline integration | ✅ | `dev/validate.py` + `vulntest/runner.py` invoke detection → chain match → triage → PoC compose end-to-end. |
| Documentation | ⚠️ this file | Per-module manual_workflows/*.md companion docs partially present; need refresh for the Phase-2 calibration changes. |

## Phase 3 — Exploitation (scaffolding)

**Status: scaffolding shipped (2026-05-07).** Modules:

- `exploit/primitives.py` — `Primitive` dataclass + 24 finding-
  category-to-kind mappings + canonical minimised-shape call
  sequences per `argus_poc_minimization_as_bug_essence_isolation`.
- `exploit/chain.py` — `PoC` dataclass + `compose_pocs(findings)`
  with CONFIRMED → IMPACT_PENDING transition + `poc_primitive`
  Evidence accumulation; round-trips into `ChainPattern` shape.
- `exploit/gadgets.py` — x86 / x86_64 gadget finder, RET + JOP
  (`jmp reg`, `call reg`) terminators, smallest-prefix-wins per site.
  Smoke test on iv-reuse binary: 117 gadgets (116 ROP + 1 JOP).
- `exploit/shellcode.py` — payload table:
  x86 / x86_64 / aarch64 Linux execve_sh (canonical shellstorm bytes,
  nul-free); x86 / x86_64 Windows winexec_calc (canonical msfvenom
  bytes; verify against current msf rev before live use).

Gate verdicts (Phase 3 is scaffolding — most gates N/A or partial):

| Gate | Status | Evidence |
|---|---|---|
| Detection | N/A | Not a detector module. |
| No FPs | N/A | Not a detector module. |
| PoC validation | ⚠️ skeleton | `compose_pocs` produces structural skeletons; live triggering deferred to Phase 4. |
| Output contract | ✅ | `PoC.to_chain_template_payload` matches `ChainPattern` shape. |
| Pipeline integration | ✅ | Wired into `dev/validate.py` + `vulntest/runner.py` after triage. |
| Documentation | ⚠️ this file | Per-submodule docs not yet authored. |

## Phase 5 — Triage + Differ + Patcher (scaffolding)

**Status: triage functional; differ + patcher are stubs.**

- `triage/__init__.py` — `auto_triage(findings, min_confidence=0.0)`
  promotes DETECTED → CONFIRMED so Phase 3 PoC composition has
  eligible primitives. Wired into pipeline.
- `differ/__init__.py` — `BinaryDiff` + `FunctionDelta` +
  `StringDelta` + `ImportDelta` dataclasses + `diff(bv_a, bv_b)`
  entry. Skeleton — submodule implementations
  (`byte_diff`, `hlil_diff`, `callgraph_diff`, `string_diff`,
  `fix_patterns`) deferred.
- `patch/__init__.py` — `Patch` + `PatchPlan` + `PatchResult` +
  `apply_patch(bv, plan, dry_run=True)` with operator-authorisation
  gate. Skeleton — bytewise apply / ELF-PE-Mach-O metadata fixup
  deferred.

| Gate | Status | Evidence |
|---|---|---|
| Detection | N/A | Not detector modules. |
| No FPs | N/A | |
| PoC validation | N/A | |
| Output contract | ✅ | Dataclasses round-trip via `to_dict`. |
| Pipeline integration | ✅ triage / ❌ differ + patch | Triage wired; differ + patch await caller integration. |
| Documentation | ⚠️ this file | |

## Phase 6 — Reporting (vendor renderers)

**Status: vendor renderers shipped (2026-05-07).**

- `output/vendor.py` — `render(finding, vendor=...)` with renderers
  for HackerOne / MSRC / Bugcrowd / Epic Games. PROVEN-only emission
  gate enforced by `enforce_proven_only=True`. `render_bundle` for
  multi-finding reports.

| Gate | Status | Evidence |
|---|---|---|
| Detection | N/A | Not a detector module. |
| No FPs | N/A | |
| PoC validation | N/A | |
| Output contract | ✅ | All four renderers produce non-empty markdown / template strings; PROVEN-gate refuses non-reportable altitude. |
| Pipeline integration | ⚠️ operator-invoked | Renderers are not auto-called by `dev/validate.py` — by design (rendering is a triage-and-export decision). |
| Documentation | ⚠️ this file | |

## Per-detector clean-corpus FP sweep (2026-05-07)

`analysis/cleanup_dominance.py` and `analysis/trusted_path.py` are
v1 / coarse-recall detectors. Sweep against eight Windows system
binaries:

| Target | `cleanup_dominance` | `trusted_path_cache_load` |
|---|---|---|
| utilman.exe | 0 | 0 |
| sethc.exe | 0 | 0 |
| osk.exe | 0 | 0 |
| notepad.exe | **1** | 0 |
| calc.exe | 0 | 0 |
| xcopy.exe | 0 | 0 |
| where.exe | 0 | 0 |
| whoami.exe | 0 | 0 |
| **TOTAL** | **1** | **0** |

The `cleanup_dominance` finding on `notepad.exe` is a known v1 FP
class — notepad calls `WriteFile` without `DeleteFileW`, which
matches the structural heuristic but isn't a security issue
(notepad isn't a privileged write-then-verify pattern). Documented
in the module docstring; Phase 2 V2 will tighten with a verify-
call-presence gate (commit + no rollback + verify call elsewhere
in function ⇒ EAC-class; commit + no rollback + no verify ⇒
benign-write — no emit).

`trusted_path_cache_load` is clean against this corpus; the coarse
v1 form (binary-scope path-string + load-API combo) didn't match any
of the eight system binaries.

## Promotion-readiness summary

No module has all six gates clean today. Promotion path per module:

| Module | Clean | Blocking |
|---|---|---|
| `analysis/sddl` | 1, 2, 4, 5 | 3 (no PoC infra), 6 (per-module TESTING.md / manual_workflow update) |
| `analysis/integrity_check_order` | 1, 2, 4, 5 | 3, 6 |
| `analysis/crypto` (PRNG paths + iv_reuse) | 1, 2, 4, 5 | 3, 6 |
| `analysis/cleanup_dominance` | 1, 4, 5 | 2 (1 FP on notepad — known v1; v2 tightens), 3, 6 |
| `analysis/trusted_path` | 1, 2, 4, 5 | 3, 6 |
| `heuristics/chains` (chain composition) | 1, 2, 4, 5 | 3, 6 |
| `triage/auto_triage` | 4, 5 | 1+2+3 (not detector), 6 |
| `exploit/*` (PoC scaffolding) | 4, 5 | 3 (live PoC trigger needs Phase 4 verification), 6 |
| `differ/`, `patch/` | 4 | scaffolding-only — no caller integration; needs full implementation + 6 |
| `output/vendor` | 4 | 5 (operator-invoked by design), 6 |

**Universal blocker:** Gate 6 (per-module TESTING.md or manual_workflow
companion). This file aggregates session-level test data; LIFECYCLE.md
§4 specifies per-module documentation. Producing per-module
manual_workflow files is the natural next step for promotion.

## Promotion log

No modules have been promoted to `~/.claude/`. Phase 0 deliverables
remain in `D:\Repos\Security\Argus\`; promotion gates clarified
above. Full-corpus FP sweep (clean Windows binaries) on the v1
detectors (`cleanup_dominance`, `trusted_path`) ran 2026-05-07
with results recorded above.
