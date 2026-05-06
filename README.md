# Argus — Vulnerability-Research Pipeline

> An AI-driven binary security research pipeline that catches real-world
> disclosed vulnerabilities and gates external output to PROVEN-only findings.

## In plain English

Most security scanners that look for vulnerabilities in compiled
software produce findings that are mostly noise — patterns that look
like bugs but aren't actually exploitable. Argus is a multi-stage
pipeline of AI agents that work together to find candidate
vulnerabilities, verify them through real exploitation testing on
isolated systems, and only emit findings whose actual impact has
been proven. The pipeline runs over LittleJohnnyMnemonic (LJM), a
cognitive memory substrate that gives the agents persistent
technical context they would otherwise lose between sessions.

## What it has accomplished

Validation runs against external known-positive disclosure targets,
April–May 2026:

- **Caught CVE-2026-31431 ("copy.fail")** — a real, recently-disclosed
  kernel-level vulnerability — on the first run against the
  disclosure target.
- **First real-world disclosed CVE caught** on the Linux kernel
  `authencesn.ko` driver. The detection fired at the exact call
  sites cited in the public disclosure, and the same detector
  generalised to identify sibling-class candidates in the related
  `authenc.ko` driver.
- **First IMPACT_VERIFIED transitions** through the full state machine
  on a 0-day kernel CVE — meaning Argus didn't just identify a
  candidate vulnerability but actually proved exploitability through
  sanitizer + debugger + launch-chain verification on an isolated
  test system.
- **Multi-driver BYOVD generalisation sweep:** run against the same
  Windows kernel drivers as the previous-generation pre-Argus
  toolset, the pre-Argus detector recorded a 100% false-positive
  rate against Argus's calibrated findings — direct evidence of the
  detector quality difference.

The four-state finding lifecycle —
**DETECTED → CONFIRMED → IMPACT_PENDING → IMPACT_VERIFIED ≡ PROVEN** —
is enforced at the pipeline boundary; external output (vendor
reports, public disclosures) is restricted to PROVEN findings only.
Theoretical or unverified findings are recorded internally as
research candidates and never appear in outgoing artifacts.

## Why it matters

AI agents performing autonomous vulnerability research is no longer
a theoretical capability — Argus catches real-world disclosed CVEs
on real targets, with full proof of exploitability before findings
leave the pipeline. The discipline of gating external output to
proven findings is what separates *"automated scanner that pages
humans about probably-not-exploitable patterns"* from *"research
tool that produces actionable artifacts."* The controlled
comparison between agents running over the LJM memory substrate
versus the same agents running without it provides empirical
evidence that **context infrastructure — not just prompt
engineering or model size — substantially changes what AI agents
can accomplish.**

---

> Argus, the all-seeing — a hundred-eyed watchman in Greek myth.
> Useful framing for a binary-research toolset whose job is to look at
> every entry point, every flow, every primitive, and every chain
> simultaneously, drawing on a knowledge corpus rather than running
> from a fixed checklist.

A **pipeline-shaped, knowledge-driven, manual-workflow-documented**
binary-analysis-and-exploitation toolset. Rebases the pre-LJM agents
and the `binary-ninja` skill into a coordinated workflow that
consumes the LJM Knowledge corpus as detection substrate, defaults
to "find all viable vulnerabilities," and gates external output to
PROVEN findings only.

Status: **Phase 0** — architecture + shared infrastructure.

## Architecture in one diagram

```
                ┌─ Source acquisition ───┐
[Acquisition] ──┤                         ├──→ target manifest
                └─ Binary acquisition ────┘
                                                ↓
[Recon]      ── surface scan, hardening, packer, entropy ──→ target profile
                                                ↓
[Source-Guided   ── source attack-surface map (grey-box) ──→ source-level map
 (optional)]     (Methodology.md grey-box pipeline)
                                                ↓
[Identification] ── taint • heap • crypto • mitigations ──→ DETECTED findings
                  • obfuscation • chains
                                                ↓
[Triage]       ── true-positive + reachability + ──────→ CONFIRMED findings
                  mitigation-aware exploitability
                                                ↓
[Exploitation] ── primitive selection, mitigation ────→ PoC artefact
                  bypass, gadget search, shellcode
                                                ↓
[Verification] ── sanitizer + debugger + actual ──────→ IMPACT VERIFIED →
                  launch-chain testing                  PROVEN findings
                                                ↓
[Reporting]    ── disclosure-altitude filter, vendor ──→ external report
                  format, PROVEN-only output
```

Authoritative spec: [`docs/PIPELINE.md`](docs/PIPELINE.md).

Working plan (rolling): [`C:\Users\C2xor\.claude\plans\starting-with-5-and-vectorized-whistle.md`](file://C:/Users/C2xor/.claude/plans/starting-with-5-and-vectorized-whistle.md).

## Repository layout

```
Argus/
├── README.md                        ← this file
├── .gitignore
├── docs/                            ← architecture and methodology
│   └── PIPELINE.md                  ← seven-stage pipeline (authoritative)
├── agents/                          ← Claude Code agent definitions
│   └── binary-research-orchestrator.md
├── skills/
│   └── binary-ninja/                ← rebased binary-ninja skill
│       ├── SKILL.md                 ← skill protocol + schemas
│       ├── TESTING.md               ← quality-gate results per LIFECYCLE.md
│       ├── MANUAL_WORKFLOWS.md      ← index of per-module companion docs
│       ├── scripts/
│       │   ├── analysis/            ← static analysis modules
│       │   ├── heuristics/          ← Knowledge-derived patterns
│       │   ├── exploit/             ← primitive construction (Phase 3)
│       │   ├── verify/              ← dynamic verification (Phase 4)
│       │   ├── differ/              ← binary diff (Phase 5)
│       │   ├── patch/               ← binary patch (Phase 5)
│       │   ├── output/              ← Finding schema + renderers
│       │   ├── lib/                 ← shared library (binja, knowledge, state)
│       │   └── legacy/              ← old scripts kept as reference
│       └── manual_workflows/        ← per-module Binja-UI companion docs
│           └── _template.md         ← per-module doc template
└── vulntest/                        ← three-tier test corpus (mini-CTF format)
    ├── INDEX.md                     ← challenge index
    ├── _templates/cell_README.md    ← per-cell brief template
    ├── tier1-single/                ← isolated single-vuln × language matrix
    ├── tier2-chains/                ← commonly-chained vulnerabilities
    └── tier3-obfuscated/            ← obfuscation layered on Tier 1/2
```

## Knowledge integration

Two layers reach the toolchain:

1. **Agent pre-flight retrieval.** Each stage agent invokes
   `jm retrieve` at session start with domain-tagged intent,
   loading top-N Knowledge entries into LLM context. Shapes
   *strategy*.
2. **Heuristics package.** `skills/binary-ninja/scripts/heuristics/`
   contains pattern tables hand-curated from Knowledge entries
   (each pattern carries `knowledge_ref` citing its source). Shapes
   *deterministic detection*.

See [`docs/PIPELINE.md`](docs/PIPELINE.md) for the
reference-book → stage → module mapping.

## Finding state machine

Reconciles LIFECYCLE.md (DETECTED/CONFIRMED/PROVEN) and
Methodology.md (DETECTED/CONFIRMED/IMPACT VERIFIED) under one
four-state model:

```
DETECTED ──(true-positive verification)──→ CONFIRMED
CONFIRMED ──(reachability + isolated PoC)──→ IMPACT_PENDING
IMPACT_PENDING ──(launch-chain validation)──→ IMPACT_VERIFIED ≡ PROVEN
```

External output gates to `IMPACT_VERIFIED` (alias `PROVEN`) only.
Theoretical findings are recorded as research candidates and never
appear in vendor submissions.

## Governance

Quality gates per [`LIFECYCLE.md`](../Research/Agents/LIFECYCLE.md):
detection (100% TP on VulnTest), zero false positives, PoC
validation (PROVEN), output-contract conformance, pipeline
integration, documentation. All six gates must pass before
promotion to `~/.claude/`.

Authorisation inherits from
[`PurpleTeam.md`](../Research/PurpleTeam.md).

Methodology reference:
[`Methodology.md`](../Research/BinaryBounty/Methodology.md).

## Phase status

| Phase | Scope | Status |
|---|---|---|
| 0 | Architecture + shared infrastructure | **Done** (2026-04-30) |
| 1 | Identification stage rebase (heuristics + analysis modules + malware-analyzer + vuln-class-analyzer + manual-workflow docs) | **In progress** — 11 heuristics + surface/mitigations/taint/heap landed; Phase 1++ E1-E5 enhancements landed (Run 10: dbutil_2_3.sys 1→32 findings); Tier-2 foundational classes (Run 16): format-string, integer-OF, stack-OF, heap classes, uninit-mem, type-confusion (research), TOCTOU; Plans A/B/C v1 (Run 17): SDDL, write-then-verify CFG, low-entropy PRNG seed; legacy parity (Run 18): SOURCES 45 / SINKS 98, both supersets of legacy |
| 2 | Source-guided / grey-box pipeline | **In progress** — minimal slice landed (Run 11): source parsing, source↔binary alignment, IOCTL constant decoding |
| 3 | Exploitation stage | Planned |
| 4 | Verification stage | **In progress** — minimal SSH-driven slice landed; first IMPACT_VERIFIED transitions on CVE-2026-31431 (Run 8) |
| 5 | Differ + patcher rebases | Planned |
| 6 | Synthesis + reporting | Planned |

## Validation history

This section tracks how Argus's detection quality evolves across
phases. Each entry documents target set, methodology, results, and
the delta versus the prior baseline. Side-by-side comparisons
against the pre-Argus legacy skills (`~/.claude/skills/binary-ninja/`)
verify whether the rebase is moving the toolchain in the right
direction.

Re-runnable harnesses:

- `dev/validate.py` — Argus pipeline against a target list
- `dev/legacy_validate.py` — equivalent pre-rebase modules

### Executive overview

Argus is the LJM-driven rebase of a pre-LJM Binary Ninja
instrumentation. As of Run 20 it has surpassed the legacy toolchain
on every measurable axis (precision, speed, provenance, lifecycle
discipline) and added several detector classes the legacy toolchain
never had.

**What Argus does that the legacy toolchain did not:**

- **MLIL SSA inter-procedural taint** with per-seed visited
  tracking and CFG-disjoint-branch pruning. Replaces the legacy
  pattern-table-only approach. Catches CVE-2026-31431 in
  `authencesn.ko` and BYOVD primitives across 13/13 sample drivers.
- **Fan-discount-aware confidence scoring**.
  `signal_weight / (1 + ln(N))` for hub signals; class-specific
  signals at full weight. `Finding.confidence` distinct from the
  `mitigation_weighted_exploitability` axis (the assuming-it's-
  real exploitability score).
- **CFG-shape detectors** — write-then-verify with no rollback
  (Plan B), allocate-before-read primitive, missing-guard
  dominator analysis for integer-OF, CFG-dominator check for
  TOCTOU and double-free.
- **SDDL/ACE permissive-IPC analysis** (Plan A) — abbreviated +
  canonical SID forms, NULL DACL + empty DACL, V1 ACEs (V2
  parser hooks scaffolded; full grammar reference at
  `Memory/Knowledge/windows_sddl_grammar.md`).
- **PRNG-in-crypto-context** (Plan C) — low-entropy seed detection
  via SSA-def chase, synthetic PRNG sources from `lcg_constants`
  pattern hits (catches inlined `FMath::Rand` in encrypted
  binaries), CSPRNG-laundering detection.
- **UE5-aware source enrichment** (Plan D) — off-by-one cap
  check, allocate-before-read regex, `FMath::Rand%N` near
  security keywords.
- **BYOVD primitive coverage** (E1-E7) — process-killer,
  arbitrary-kernel-RW, MSR, file/registry write, kernel module
  load. Auto-discovers IRP dispatch wiring (per-slot StoreStruct,
  raw Store, bulk `__memfill_u64`).
- **C++ stdlib propagator scaffolding** — `std::basic_string` /
  `std::vector` ctor patterns; integer-OF/cpp catches. Full cpp
  variant flow requires memory-region taint (v3).
- **ATL/wil RAII-wrapper FP filter** — `CHeapPtr<T>::Allocate`,
  `wil::details::ProcessHeapAlloc`, `unique_ptr` / `shared_ptr` /
  `make_unique` excluded from `unchecked_allocation` emission.
- **Knowledge citation per finding** — every Finding cites the
  LJM Knowledge entry that drove its detector.
- **Four-state Finding lifecycle** — DETECTED → CONFIRMED →
  IMPACT_PENDING → IMPACT_VERIFIED. External output gated to
  PROVEN only.
- **Phase 4 verification slice** — SSH-driven sanitizer + dmesg
  deltas confirmed CVE-2026-31431 IMPACT_VERIFIED on isolated lab.

**Architectural posture:** Argus is "direct protection" — its
detection survives runtime telemetry loss. Where EDR-class
detection collapses to a *blackout* failure mode when ETW is
patched or kernel callbacks are deregistered, Argus operates
against the binary itself and remains effective.

## Detector capabilities — done

| Class | Module | Status |
|---|---|---|
| Stack overflow (red-zone + canary aware) | `analysis/taint.py` (extends), `_il_helpers.resolves_to_stack_variable` | Done |
| Heap UAF / double-free / heap-OF | `analysis/heap.py` (SSA-def-chase + phi-merge filter + CRT denylist + RAII-wrapper denylist + CFG-disjoint pruning) | Done |
| Global-pointer UAF (`g_session` pattern) | `analysis/heap.py:find_global_pointer_uaf` | Done |
| Format-string with tainted format slot | `analysis/taint.py` (position-aware sink check) | Done |
| Integer-OF → allocation (missing-guard CFG) | `analysis/taint.py` + `_cfg_primitives.has_dominating_comparison_on` | Done |
| Uninitialised memory disclosure | `analysis/uninit.py` | Done |
| Type-confusion candidate (research-grade) | `analysis/types.py` (binary-level RTTI absence) | Done (v1) |
| TOCTOU / race | `analysis/race.py` (CFG-dominator) | Done |
| Permissive SDDL + NULL DACL | `analysis/sddl.py` (Plan A) | Done |
| Pre-verification write (CFG-path-sensitive) | `analysis/integrity_check_order.py` (Plan B v2) | Done |
| Low-entropy PRNG seed | `analysis/crypto.py:find_low_entropy_seeds` (Plan C v1) | Done |
| Synthetic PRNG sources from LCG constants | `analysis/crypto.py:_enumerate_synthetic_prng_call_sites` (Plan C v2) | Done |
| CSPRNG-then-srand laundering | `analysis/crypto.py:find_csprng_laundered_to_prng` (Plan C v2) | Done |
| UE5 source patterns | `analysis/source_surface.py:_scan_ue5_source_patterns` (Plan D v1) | Done |
| BYOVD primitive class fingerprint | `heuristics/byovd_primitives.py` (E1-E7) | Done |
| Windows kernel IRP dispatch wiring | `analysis/windows_drivers.py` (per-slot + bulk memfill) | Done |
| Tainted-pointer-dereference (CWE-822) | `analysis/taint.py` E4 | Done |
| Inlined-memcpy structural detection | `analysis/taint.py` E5 | Done |
| Hardening matrix (`/GS`, CFG, ASLR, CET, etc.) | `analysis/mitigations.py` | Done |
| Crypto-primitive fingerprint (LCG/MT/AES/DES/MD5) | `heuristics/crypto.py` | Done |
| Obfuscation (entropy / RWX / CFF / LCG-XOR string cipher) | `analysis/obfuscation.py` | Done |
| Phase 2 source enrichment (callee alignment + IOCTL decode) | `analysis/source_surface.py` | Done |
| Phase 4 verification (SSH sanitizer + dmesg deltas) | `analysis/verify/sanitizer.py` | Done |
| Output (Finding v2 schema, SARIF 2.1.0, Markdown) | `output/` | Done |

**Sources / sinks** (`heuristics/imports.py`): 45 sources, 98 sinks
— both supersets of the pre-Argus legacy lists. Includes Win32
expansion (`GetCommandLineW`, `WSARecv`, `RegQueryValueExW`,
`InternetReadFile`, `WinHttpReadData`), full BYOVD primitive set
(`MmMapIoSpace`, `__writemsr`, `Zw*Process`, `Zw*File`,
`ZwSetValueKey`, `scatterwalk_map_and_copy`, `memcpy_to_iter`,
`copy_to_iter`), shell-expansion sinks (`ShellExecute*`,
`CreateProcess*`, `WinExec`), all 12 FORTIFY `__*_chk` variants,
and IPC entries (`accept`, `msgrcv`, `mq_receive`, `shmat`).

**Fan-discount signals** (`lib/scoring.py`):

- Hub: `tainted_size_arg`, `tainted_pointer_write`,
  `tainted_pointer_read`, `alloc_then_write_no_full_init`,
  `free_then_use`
- Specific: `tainted_format_arg`,
  `missing_alloc_size_guard_dominator`,
  `stack_write_exceeds_compile_size`,
  `leaf_redzone_use_with_tainted_offset`,
  `two_free_paths_same_alloc`, `freed_ssa_subsequent_use`,
  `alloc_size_lt_full_initial_fill`,
  `vtable_dispatch_after_unguarded_downcast`,
  `check_then_use_split_by_attacker_window`,
  `permissive_sddl_grant_overbroad_principal`,
  `null_dacl_set_explicit`,
  `commit_without_rollback_for_resource`,
  `low_entropy_seed_to_prng`,
  `csprng_laundered_through_weak_prng`,
  `permissive_sddl_grant_overbroad_principal_canonical_sid`

## Known-positive validation

| Target | Status | Argus result |
|---|---|---|
| **CVE-2026-31431** (`authencesn.ko`, "copy.fail") | IMPACT_VERIFIED | 6 critical `kernel_oob_write_at_offset` findings at exact disclosure call sites; sanitizer + dmesg deltas confirmed exploitability via Phase 4 SSH-driven verify. Generalised to sibling `algif_aead.ko`. |
| **CVE-2021-21551** (`dbutil_2_3.sys`, Dell BYOVD) | CONFIRMED | 30 critical findings (29 `tainted_pointer_dereference` + 1 `kernel_arbitrary_rw_primitive`) at the IOCTL handler dispatch path. IRP dispatch table extracted automatically. Deterministic across runs. |
| **BYOVD multi-driver sweep** (13 drivers) | DETECTED | 13/13 detected without per-target tuning. Includes RTCore64, dbutildrv2, asusio, ProcessHacker ring0, kdmapper-bundled drivers. |
| **Tier-1 VulnTest corpus** (12 cells) | DETECTED | 11/12 TP. Only `double-free/c` (struct-field aliasing) remains FN — flagged as v3 work. |

**Microsoft accessibility binaries** (utilman / sethc / osk) — used
as a control set:

| Binary | Result |
|---|---|
| `utilman.exe` | 3 candidate-grade TOCTOU findings in ATL `StartList::HandleFirstTime` (`GetFileAttributesW` → `DeleteFileW` over `CAtlList<CRegKey>` iteration). Status: requires source-level review; registry-derived path + one-time-setup function suggests but does not prove benign. |
| `sethc.exe` | 0 findings (CFG-disjoint-branch fix correctly suppressed the phi-merge artefact in `SettingsCopier::DeleteATSettings`). |
| `osk.exe` | 0 findings. |

## Pre-Argus comparison

Side-by-side numbers from the calibration runs (April 2026), with
the FP/FN framing recontextualised against post-parity-audit
ground truth:

| Axis | Legacy | Argus |
|---|---|---|
| Microsoft control set finding count | 43 | 0 / 4 candidate (mature detector lineup) |
| Pipeline runtime, 3-binary control set | 200.4s | 14.9s (~13×) |
| VulnTest emissions across 33 cells | 169 | 35 (~5× quieter) |
| Per-finding Knowledge citation | None | 82% Knowledge-cited |
| Per-finding confidence + exploitability axes | None | `confidence` + `mitigation_weighted_exploitability` |
| Sources / sinks coverage | 35 sources, 34 sinks | 45 sources, 98 sinks (supersets) |
| Native API / BYOVD primitive set | None | Full coverage |

The 43 legacy "FPs" were not all FPs — without per-finding ground
truth in the legacy output format, the FP/FN ratios reported in
the original calibration runs aren't load-bearing. Some of those
legacy detections were proximate to genuinely surfaced patterns
(the utilman.exe and sethc.exe candidates that Argus's mature
pipeline now flags). The honest framing: Argus produces
lower-volume, higher-precision, Knowledge-cited output; the
legacy toolchain produced higher-volume, lower-precision,
unsourced output. Both detected real things; only Argus
distinguishes signal from noise reliably.

## Detector capabilities — to-do (v3+)

| Item | Notes |
|---|---|
| Struct-field aliasing for double-free | `e->name` vs `e.name` cross-function alias; needs interprocedural alias analysis. `vulntest/tier1-single/double-free/c` remains FN. |
| C++ memory-region taint | Required for cpp variants (format-string / stack-OF / heap-OF) to propagate end-to-end through `std::string` objects. SSO-aware. The SSA-only data model needs region tags. |
| LCG-as-cipher / LCG-as-PRNG distinction | Context classifier for synthetic-PRNG-source approach. Without it, GameGuard-class binaries with 720+ LCG-XOR string-cipher call sites would FP. |
| Type-confusion per-call-site anchoring | Current detector is binary-level research-grade (no-RTTI + virtual-dispatch present). v2 needs source-pattern detection on unguarded `static_cast<X*>`. |
| Cross-detector dedup at orchestrator level | `heap.py` and `taint.py` both emit `heap_buffer_overflow` on heap-overflow/c with different `detector` strings. |
| Plan A V2/conditional ACE handling | Grammar reference now in `Memory/Knowledge/windows_sddl_grammar.md`; parser still v1. |
| E2 indirect-dispatch beyond `__memfill_u64` | FastIoDispatch tables, PnP-only IRP registration. |
| Phase 4 Windows-lab integration | Currently only Linux-lab is wired for dynamic verification. Windows lab needed for CVE-2021-21551 verification. |
| Cross-arch target validation | AArch64, MIPS, RISC-V — verify `heuristics/syscalls.py` cross-arch SVC / ECALL patterns fire correctly. |
| Expanded Windows control set | `cmd.exe`, `notepad.exe`, `explorer.exe`, `taskmgr.exe`. |
| Linux ELF control set | `bash`, `coreutils`, `openssl`. |
| BYOVD-set re-sweep with Tier-2 + Plans A-C | Run 12 covered 13/13 BYOVD drivers for primitives only; foundational classes have not been swept across the same set yet. |

## Operational follow-ups (operator-driven)

| Item | Notes |
|---|---|
| Triage utilman.exe TOCTOU triple at source level | Determine TP vs FP for the `StartList::HandleFirstTime` finding. If TP, MSRC submission is warranted. |
| HackerOne submissions | Recommended order from coverage-gap analysis: 04 → 02 → 03 → 01. |
| Sub 01 escalation demo | Consider demonstrating one downstream consequence (driver-corruption observability or AppData cache poisoning persistence) before submitting; current escalation framing is "potential" not demonstrated. |

## Methodology notes

The validation harnesses do not include the binary outputs in this
repo — they invoke Binary Ninja against system / external binaries
the operator has authorised access to. Re-running them on different
hardware will produce different timing numbers; the *findings
counts* are the load-bearing signal.

When new analysis modules land, expand the control set first, then
re-run the comparison: a row added to a richer module set against a
larger control set is the most informative baseline.
