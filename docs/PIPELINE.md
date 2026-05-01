# Argus Pipeline — Authoritative Spec

The Argus toolset is a **seven-stage pipeline**. Each stage is owned
by one or two named agents and backed by a Python skill package.
An orchestrator agent (`binary-research-orchestrator`) drives the
pipeline; each stage agent is callable directly when the operator
wants only that stage.

## The seven stages

```
[1. Acquisition]   →   [2. Recon]   →   [3. Source-Guided (optional)]   →
[4. Identification]   →   [5. Triage]   →   [6. Exploitation]   →
[7. Verification]   →   [Reporting]
```

Reporting is treated as a sub-stage of Verification + a final
output stage; it does not introduce new analysis.

### 1. Acquisition

**Goal:** produce a target manifest describing what we're analysing
and how.

| Agent | Skill |
|---|---|
| `binary-acquisition` (Phase 1+) | `acquire/` |

Activities: source clone (if applicable), binary download, packer
identification, hardening summary, build-system reconnaissance.

Output: target manifest JSON (path, hash, arch, platform, format,
linkage, packer, source-availability flag).

### 2. Recon

**Goal:** produce a target profile that downstream stages key off.

| Agent | Skill module |
|---|---|
| `binary-recon` (Phase 1) | `analysis/surface.py` |

Activities: hardening detection (`/GS`, CFG, ASLR, CET, PAC, MTE,
NX, RELRO, PIE, FORTIFY); import / export / linkage tables; section
entropy + packer signatures; string extraction and pattern fingerprint;
architecture and platform profile.

Output: target profile JSON consumed by all downstream stages.

### 3. Source-Guided (optional)

**Goal:** when source is available, produce a source-level attack
surface map that points downstream stages at the right code paths.

| Agent | Skill module |
|---|---|
| `source-attack-surface-mapper` (Phase 2) | `analysis/source_surface.py` |

Activities: parse build system; extract network handlers,
serialisation boundaries, asset loaders, RPC dispatch points; map
trust boundaries (client ↔ server, user content ↔ engine).

Output: source-level attack-surface map JSON; in-engine harness
scaffolding when the target is engine-built.

This stage is the
[Methodology.md grey-box pipeline](../../Research/BinaryBounty/Methodology.md)
realised. Highest ROI for engine-built targets (Unreal, Source,
licensee games).

### 4. Identification

**Goal:** detect candidate vulnerabilities. All emitted findings
start in state `DETECTED`.

| Agent | Skill modules |
|---|---|
| `vuln-class-analyzer` (Phase 1) | `analysis/{taint,heap,crypto,mitigations,obfuscation,chains}.py` |
| `malware-analyzer` (Phase 1, rebased) | `analysis/surface.py` + `heuristics/{evasion,injection,rootkit,syscalls,obfuscation}.py` |

Per-module behaviour:

| Module | Detects | Knowledge anchors |
|---|---|---|
| `taint.py` | inter-procedural flow source → sink (MLIL SSA) | `wnapi_syscall_mechanics`, `legacy/deep_analysis.py` baseline |
| `heap.py` | UAF, double-free, heap overflow, unchecked allocation | `wnapi_heap_internals` |
| `crypto.py` | PRNG-in-security-path, IV reuse, weak KDF, custom ciphers | `ue5_prng_handshake_secret_recovery` |
| `mitigations.py` | hardening present/absent + mitigation-weighted exploitability | `hw_stack_overflow_mechanics`, `gameguard_research_22_findings` |
| `obfuscation.py` | packers, control-flow flattening, string ciphers | `gb_obfuscated_code_analysis`, `gameguard_research_22_findings` |
| `chains.py` | multi-component chain templates | `eac_eos_arbitrary_write_chain`, `ue5_*` |

Output: `Finding[]` in state `DETECTED`, each citing its source
Knowledge entry via `knowledge_refs`.

### 5. Triage

**Goal:** transition findings from `DETECTED` to `CONFIRMED` or
`DISMISSED`.

| Agent | Skill |
|---|---|
| `triage-analyst` (Phase 4+) | `triage/` |

Activities: true-positive verification (path is reachable, no
mitigating controls between source and sink), mitigation-weighted
exploitability scoring, reachability validation, dismissal of
heuristic false positives.

Per
[Methodology.md §Findings Validation Process](../../Research/BinaryBounty/Methodology.md):
this is Stage 1 (true-positive confirmation) of the validation
process.

### 6. Exploitation

**Goal:** construct a PoC primitive that triggers the bug. State
transition: `CONFIRMED` → `IMPACT_PENDING`.

| Agent | Skill modules |
|---|---|
| `exploit-builder` (Phase 3) | `exploit/{gadgets,shellcode,primitives,chain}.py` |

Activities: primitive selection (stack-OF / heap-UAF / format-string
/ integer-OF / race / logic), mitigation-bypass strategy, ROP/JOP/
SROP/DOP gadget search, multi-arch shellcode generation, chain
composition via `chain.py`.

Output: PoC artefact (script + payload + reproduction notes) that
triggers the bug *in isolation*. Real-launch-chain testing happens
in Verification.

### 7. Verification

**Goal:** prove impact in the target's actual launch chain. State
transition: `IMPACT_PENDING` → `IMPACT_VERIFIED` ≡ `PROVEN`.

| Agent | Skill modules |
|---|---|
| `poc-validator` (Phase 4) | `verify/{sanitizer,debugger,triage}.py` |

Activities: sanitizer integration (ASan / UBSan / MSan / TSan /
HWASan), debugger-based PoC verification, **actual launch-chain
testing** (per
[Methodology.md Stage 2](../../Research/BinaryBounty/Methodology.md))
— launching the binary through the production launcher, service
manager, or update flow rather than direct invocation.

Output: `IMPACT_VERIFIED` findings ready for reporting; failed
verifications return findings to `CONFIRMED` with verification notes.

### Reporting (output sub-stage)

**Goal:** emit external artefacts, gated to PROVEN findings.

| Agent | Skill modules |
|---|---|
| `report-writer` (Phase 6) | `output/{sarif,markdown,report}.py` |
| `threat-analyst` (Phase 6, rebased) | (synthesis layer) |

Activities: SARIF generation, vendor-specific format rendering
(H1, MSRC, Bugcrowd), disclosure-altitude filter (per
`Memory/Feedback/disclosure_altitude_capability_vs_results`),
PROVEN-only output with explicit theoretical-finding annexes for
research candidates.

## Cross-cutting agents

These agents do not own a stage but are invoked from multiple
stages or out-of-band:

| Agent | Skill | Purpose |
|---|---|---|
| `binary-research-orchestrator` | n/a | Pipeline driver — invokes stage agents in sequence, manages session manifest, gates user-confirmation |
| `binary-differ` (Phase 5, rebased) | `differ/` | 1-day workflow + Patch-Tuesday analysis |
| `binary-patcher` (Phase 5, rebased) | `patch/` | Authorised binary modification (CTF / RE / authorised testing) |

## Two-layer Knowledge integration

Knowledge reaches both the LLM-consumed agent prose and the
deterministic Python skill scripts:

**Layer 1 — agent pre-flight retrieval.** Each stage agent's bash
quick-reference invokes `jm retrieve` tagged for its domain. Loads
top-N relevant Knowledge entries into LLM context. Shapes
*strategy* — what to look for, what reference book applies.

**Layer 2 — heuristics package.** `skills/binary-ninja/scripts/heuristics/`
exports pattern tables hand-curated from Knowledge entries. Each
pattern dict carries `name`, `signature`, `cwe`, `mitre`, `severity`,
`knowledge_ref`. Shapes *deterministic detection*.

| Heuristics module | Knowledge entries that drive it |
|---|---|
| `imports.py` | legacy SUSPICIOUS_IMPORTS / DANGEROUS_FUNCTIONS extended; baseline |
| `syscalls.py` | `em_direct_syscall_ssn_resolution`, `wnapi_syscall_mechanics`, `hw_multi_arch_shellcode`, `hw_cross_arch_syscall_conventions` |
| `injection.py` | `em_advanced_injection_variants`, `bhg_process_injection_fundamentals`, `bhg_windows_type_mapping`, `injection_trigger_composition` |
| `evasion.py` | `em_covert_execution_tls_seh`, `em_peb_antidebug_fields`, `em_veh_hwbp_hook_evasion`, `em_hook_evasion_three_approaches`, `gh_anti_cheat_evasion` |
| `rootkit.py` | `em_rootkit_irp_minifilter_callbacks`, `rb_secure_boot_bypass` |
| `crypto.py` | `ue5_prng_handshake_secret_recovery` (canonical exemplar); future crypto entries |
| `mitigations.py` | `hw_stack_overflow_mechanics` (canary mechanics), `gameguard_research_22_findings` (mitigation-absence-as-finding) |
| `obfuscation.py` | `gb_obfuscated_code_analysis`, `gameguard_research_22_findings` (LCG string cipher) |
| `chains.py` | `eac_eos_arbitrary_write_chain`, `ue5_server_crash_chain_prng_fstring`, `ue5_fstring_allocation_amplification` |
| `arch.py` | `a64_*`, `wnapi_segment_register_teb_bootstrap`, `wnapi_peb_teb_structures` |
| `hooking.py` | `gh_hooking_techniques_d3d_iat_vft` |

## Reference book → stage map

Each major reference book primarily serves one or two pipeline
stages. When the orchestrator pre-flights Knowledge for a given
stage, these are the highest-signal sources:

| Book / family | Knowledge prefix | Primary stage |
|---|---|---|
| Heavy Wizardry | `hw_*` | Identification (mechanics) + Exploitation (multi-arch shellcode) |
| Black Hat Go | `bhg_*` | Identification (Go-specific patterns) + Exploitation (injection in Go) |
| Evading the Machine | `em_*` | Identification (malware indicators) + Verification (anti-debug awareness) |
| Game Hacking | `gh_*` | Identification (hooking, anti-cheat) + Exploitation (game-runtime context) |
| Ghidra Book | `gb_*` | Recon (disassembly, custom loaders) + Identification (obfuscation) |
| Windows Native API Programming | `wnapi_*` | Identification (Windows API surface) + Exploitation (syscall, heap) |
| Rootkits and Bootkits | `rb_*` | Identification (firmware, kernel) + Verification (boot-chain) |
| Effective C | `ec_*` | Identification (UB taxonomy) + Triage (exploitability per UB class) |
| AArch64 references | `a64_*` | Cross-cutting (multi-arch support) |

## Finding state machine

```
            ┌─ DISMISSED (terminal)
            │
DETECTED ──┼─→ CONFIRMED ──┬─→ IMPACT_PENDING ──→ IMPACT_VERIFIED ≡ PROVEN
            │              │                       │   (terminal)
            └──────────────┴───────────────────────┴─→ DISMISSED
```

State transitions are recorded in `Finding.state_history`. External
output is gated to `IMPACT_VERIFIED`. Theoretical findings (good
analysis but no demonstrable impact) are tagged as research
candidates and surface in private artefacts only — never in vendor
submissions, per
[Methodology.md §Findings Validation](../../Research/BinaryBounty/Methodology.md).

## Default posture: find all viable

Unless the operator narrows scope, the orchestrator runs the full
identification stage with all detection modules enabled. Output is
filtered for prioritisation (mitigation-weighted exploitability) but
never for completeness. The operator can opt in to narrower scoping
("just run the differ on these two binaries", "just check this
function for stack overflows") via direct stage-agent invocation.

## Confirmation gates (default)

The orchestrator pauses for explicit user confirmation before:

- any disk write outside `findings/`
- any binary execution beyond verification harnesses
- any external network call (similarity hashing service uploads,
  vendor portal queries, etc.)
- reporting / submitting

Stages 1–4 (acquisition, recon, source-guided, identification) run
without confirmation by default. Stage 5 (triage) runs auto-mode
unless the operator has opted into manual review. Stages 6–7
(exploitation, verification) require confirmation per finding before
PoC construction begins.

This default is calibration-friendly: after a real session the
operator can adjust which stages auto-run vs require confirmation
in the orchestrator's session config.

## Quality gates (per LIFECYCLE.md)

All six gates must pass before any agent or skill module promotes
from `D:\Repos\Security\Argus\` to `~/.claude\`:

1. **Detection** — 100% TP on applicable VulnTest programs
2. **No false positives** — 0 FPs against test corpus + clean control set
3. **PoC validation** — generated PoCs trigger their target vulnerability
4. **Output contract** — Finding v2 schema validated; SARIF 2.1.0 conformant
5. **Pipeline integration** — end-to-end run passes against real and synthetic targets
6. **Documentation** — TESTING.md updated, MANUAL_WORKFLOWS.md complete, every Finding category cites its source Knowledge entry

Independent verification: `jm associate` against a sample of
generated Findings should surface the cited Knowledge entries as
top matches. If the heuristics module says "this is a direct-syscall
stub" but `jm associate` doesn't surface
`em_direct_syscall_ssn_resolution`, the pattern table is mis-cited.

## Manual-workflow companion docs

Every skill module ships a `MANUAL_WORKFLOW.md` companion at
`skills/binary-ninja/manual_workflows/` that maps the programmatic
flow to the equivalent human Binary-Ninja-UI sequence, plus the
relevant reference-book chapter. Per the template at
[`_template.md`](../skills/binary-ninja/manual_workflows/_template.md):

- Programmatic invocation
- Manual workflow (Binja UI step-by-step)
- Reference Knowledge entries + book chapters
- Divergence policy (who's authoritative when programmatic and
  manual disagree, by vulnerability class)

This serves three functions: teaching artefact, audit trail, and
correctness check.
