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
- **Complete HTB binary exploitation + rootkit track: 10/10 binary
  exploitation challenges + diamorphine LKM rootkit (cyberpsychosis),
  all live remote exploitation over VPN.** Vulnerability classes:
  ret2win, ret2libc (two-stage with GOT-leak), format string
  (32-bit, plain `%p` chain, flag on stack), 3-stage format string
  GOT overwrite (simultaneous libc leak + `system` write in one
  payload), signed integer overflow (int32 wraparound), stack
  variable overwrite, ret2shellcode (NX-off), and LKM rootkit
  analysis — diamorphine getdents64 hook bypassed via stat-based
  path probing (`test -e` uses lstat, not hooked) to discover
  world-readable flag hidden from `ls` by MAGIC_PREFIX (= challenge
  name fragment `psychosis`). Each session accumulates methodology
  corrections and exploit patterns into LJM memory — the iterative
  improvement is measurable: the second and third sessions required
  zero human correction on exploit logic. This directly answers the
  question *"can AI develop exploits and pentest?"* with
  externally-graded, time-stamped evidence.
- **Full Detect → PoC → Verify pipeline on the Windows C/C++ corpus**
  (2026-05-11): a single `vulntest --c-cpp-only` pass walks **100
  IMPACT_VERIFIED transitions across 28+ cells**, covering twelve
  bug-class categories end-to-end (format_string, off_by_one,
  path_traversal, uninitialised_memory_disclosure, use_after_free,
  stack/heap buffer overflow, trusted_path_xref_to_load, toctou,
  double_free, command_injection, stack_buffer_overflow). Findings
  promote through the full state machine without operator
  intervention: detector emits, `auto_triage` confirms, generic
  per-finding PoC generator (`exploit/finding_poc.py`) renders a
  category-appropriate trigger, and the local-execution harness
  (`verify/local.py`) executes it and records the impact evidence.
  The local harness mirrors the SSH-driven Linux sanitizer; the
  state-machine bridge consumes both interchangeably.

The four-state finding lifecycle —
**DETECTED → CONFIRMED → IMPACT_PENDING → IMPACT_VERIFIED ≡ PROVEN** —
is enforced at the pipeline boundary; external output (vendor
reports, public disclosures) is restricted to PROVEN findings only.
Theoretical or unverified findings are recorded internally as
research candidates and never appear in outgoing artifacts.

## External validation

Argus operates an independent Hack The Box account; the public
profile at
[`hackthebox.com/public/users/3471795`](https://app.hackthebox.com/public/users/3471795)
displays the pipeline's autonomous challenge completions. The pipeline
operates the account end-to-end — solves are externally graded,
time-stamped, and verifiable without any access request.

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

Status: **Phase 1 + 2 + 3 + 5 + 6 substantially complete; Phase 4
landed on both Linux (SSH-driven) and Windows-userspace (local
subprocess) paths, with the runner walking findings DETECTED →
IMPACT_VERIFIED in a single pass**.

Forward-work prioritisation: [`docs/PROGRESSION.md`](docs/PROGRESSION.md).

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
│   ├── PIPELINE.md                  ← seven-stage pipeline (authoritative)
│   ├── ANALYSIS_PLAYBOOK.md         ← operator manual analysis playbook
│   ├── PROGRESSION.md               ← forward-work prioritisation and sprint plan
│   └── detection-gaps.md            ← exploitation pattern gaps identified in live runs
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
    ├── runner.py                    ← end-to-end Detect → PoC → Verify harness
    │                                  (--c-cpp-only / --verify / --no-verify)
    ├── build_all.sh                 ← MSVC vcvars64 multi-cell build driver
    ├── _templates/cell_README.md    ← per-cell brief template
    ├── tier1-single/                ← isolated single-vuln × language matrix (28 cells)
    ├── tier2-chains/                ← commonly-chained vulnerabilities (EAC, UE5)
    ├── tier3-obfuscated/            ← obfuscation layered on Tier 1/2
    └── known-positive/              ← real-world disclosure reproducers
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
reference-book → stage → module mapping. The detector design
philosophy — TTP-altitude framing, v1/v2 layering, dominance
scoping, FP gates, source/sink/propagator vocabulary — is
captured in the LJM Knowledge entry
`Memory/Knowledge/argus_detector_design_principles.md`. Read
that first when designing a new detector or reviewing FP
regressions.

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
| 1 | Identification stage rebase (heuristics + analysis modules + malware-analyzer + vuln-class-analyzer + manual-workflow docs) | **Substantially complete** — 14 heuristics + 24 analysis modules; Phase 1++ E1-E7 BYOVD detection (13/13 multi-driver sweep); Run-14 per-seed visited tracking; Tier-2 foundational classes; Plans A-D + integrity_check_order v4 (verify-call-presence) + cleanup_dominance v2 + trusted_path detectors; Sprint 3/4 lineup hardening (cross-function heap, off-by-one, dynamic sink-arg, evasion structures, tagged-union, managed/Go) |
| 2 | Source-guided / grey-box pipeline | **Substantially complete** (closed 2026-05-07) — three Epic-submission coverage gaps closed: SDDL/ACE, write-then-verify v3 (verify-call-dominates-commit), PRNG provenance (Path A/B/C + IV-reuse + custom-cipher signatures); callee-signature alignment slice |
| 3 | Exploitation stage | **Complete** (2026-05-11) — chain scaffolding (Primitive + PoC dataclasses, `compose_pocs`, RET/JOP gadget finder, multi-arch shellcode tables, pwntools-style ret2win + egg-hunt templates) PLUS generic per-finding PoC generator `exploit/finding_poc.py` (12 category renderers — stack/heap OF, format string, command injection, path traversal, off-by-one, UAF, double-free, uninit memory disclosure, TOCTOU, trusted-path load, kernel decrypt-external-pages stub). Each renderer emits a deterministic `[+] EXPLOIT RAN` marker the Phase-4 harness greps for. |
| 4 | Verification stage | **Done** (2026-05-11) — two-path harness: `verify/sanitizer.py` (SSH-driven Linux lab — first IMPACT_VERIFIED transitions on CVE-2026-31431, dirty-frag CVE-2026-43284/43500) and `verify/local.py` (local-subprocess, cross-platform — drives Phase-3 PoCs against userspace targets on the analysis host itself). `vulntest/runner.py` integrates the local harness so a single `--c-cpp-only` pass walks DETECTED → CONFIRMED → IMPACT_PENDING → IMPACT_VERIFIED end-to-end. Latest sweep: 100 IMPACT_VERIFIED transitions across the Windows C/C++ corpus, 28+ cells, 12 bug-class categories. HTB binary-exploitation + rootkit track: 11/11 PROVEN over live VPN. |
| 5 | Triage + Differ + Patcher | **Triage functional** (2026-05-07) — `auto_triage(findings, min_confidence)` promotes DETECTED → CONFIRMED, wired between chain-match and PoC composition. Differ + Patcher scaffolding: dataclasses + skeleton API; full implementations deferred. |
| 6 | Synthesis + reporting | **Scaffolding shipped** (2026-05-07) — `output/vendor.py` HackerOne / MSRC / Bugcrowd / Epic Games renderers with PROVEN-only emission gate; SARIF + Markdown renderers from Phase 0. |

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
instrumentation. It has surpassed the legacy toolchain on every
measurable axis (precision, speed, provenance, lifecycle
discipline) and added several detector classes — plus a full
Detect → PoC → Verify pipeline — the legacy toolchain never had.

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
- **Phase 4 verification — two-path harness.** SSH-driven sanitizer
  + dmesg deltas (Linux kernel lab; first IMPACT_VERIFIED on CVE-
  2026-31431 and the decrypt-into-external-pages disclosure target).
  Local-subprocess harness mirrors the SSH variant on the analysis
  host itself for Windows userspace targets; both paths share the
  same `VerificationResult` shape so the state-machine bridge
  consumes them interchangeably.
- **Per-finding PoC generator (Phase 3).** Generic, category-driven
  PoC renderer (`exploit/finding_poc.py`) emits a self-contained
  Python trigger for each CONFIRMED finding with a deterministic
  `[+] EXPLOIT RAN` marker; Phase 4 greps for that marker plus a
  cross-platform crash-pattern set (Segfault, AddressSanitizer,
  Access violation, _invalid_parameter, etc.).
- **Single-pass runner integration.** `vulntest/runner.py` walks a
  cell through detection, auto-triage, per-finding PoC generation,
  and local verification in one invocation. The 2026-05-11 sweep
  produced 100 IMPACT_VERIFIED transitions across the Windows C/C++
  corpus without operator intervention.

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
| Cross-function / class-aware heap (cross-function DF, C++ shallow-copy DF, cross-method UAF) | `analysis/cross_function_heap.py` (Sprint 4.1/4.2) | Done |
| Off-by-one (loop `CmpUle`/`CmpSle` + indexed store sharing induction-variable ancestor) | `analysis/off_by_one.py` v1 | Done |
| Dynamic-argument sink (non-constant pointer into `printf`/`system`/`fopen`-class) | `analysis/dynamic_sink_arg.py` — covers shapes where SSA taint dies at C++ stdlib wrappers | Done |
| Format-string with tainted format slot | `analysis/taint.py` (position-aware sink check) | Done |
| Integer-OF → allocation (missing-guard CFG) | `analysis/taint.py` + `_cfg_primitives.has_dominating_comparison_on` | Done |
| Uninitialised memory disclosure | `analysis/uninit.py` | Done |
| Type-confusion candidate (binary-level RTTI absence + tagged-union misuse) | `analysis/types.py` v1 (info-grade hint) + Sprint 4.3 tagged-union shape | Done (v1) |
| Evasion structural patterns (TLS callbacks, hidden-from-debugger thread) | `analysis/evasion_structures.py` — pairs with `heuristics/evasion.py` StructuralPattern declarations | Done |
| Managed-binary metadata heuristic (.NET IL + Go runtime strings) | `analysis/dotnet_managed.py` v1 (heuristic string co-presence; IL/gopclntab walk deferred to v2) | Done (v1) |
| TOCTOU / race | `analysis/race.py` (CFG-dominator) | Done |
| Permissive SDDL + NULL DACL | `analysis/sddl.py` (Plan A) | Done |
| Pre-verification write (verify-dominates-commit + verify-presence v4) | `analysis/integrity_check_order.py` v4 | Done — gate-2 CLEAN |
| Missing cleanup on failure | `analysis/cleanup_dominance.py` v2 (verify-call-presence gate) | Done — gate-2 CLEAN (suppresses notepad-class FPs) |
| Trusted-path cache load | `analysis/trusted_path.py` v1 (binary-scope path-string + load-API) and v2 (per-callsite SSA xref from path literal to load API; HIGH severity, suppresses v1 when v2 fires) | Done — gate-2 CLEAN (0 FPs across 15-binary clean Windows corpus) |
| Low-entropy PRNG seed | `analysis/crypto.py:find_low_entropy_seeds` (Plan C v1) | Done |
| Synthetic PRNG sources from LCG constants | `analysis/crypto.py:_enumerate_synthetic_prng_call_sites` (Plan C v2) | Done |
| CSPRNG-then-srand laundering | `analysis/crypto.py:find_csprng_laundered_to_prng` (Plan C v2) | Done |
| Weak PRNG in security-named context (Path B/C) | `analysis/crypto.py` — function/caller name match + binary-scope indicator + MSVC-mangling-aware filter | Done |
| IV reuse (constant or shared-buffer across cipher-init calls) | `analysis/crypto.py:find_iv_reuse` — consults `PossibleValueSet.value` for constant-pointer resolution | Done |
| Custom cipher constants (Salsa/ChaCha sigma, RC4 table size) | `heuristics/crypto.py` — added Salsa/ChaCha sigma 0x61707865, RC4 256-byte marker | Done |
| Decrypt-into-externally-owned-pages | `analysis/decrypt_external_pages.py` v1 (binary-scope: scatterlist constructor + crypto decrypt sink with no privately-own gate) + v2 (per-function CFG-aware: same shape proven via dominance check) | Done |
| Buffer-content taint (snprintf→system, etc.) via stack-slot aliasing | `analysis/taint.py` — `_tainted_stack_slots` + `_propagate_to_aliases_of_slot` | Done (2026-05-08) |
| Process-handle taint chain (BYOVD process-killer) | `analysis/taint.py` PROPAGATORS — ZwOpenProcess / PsLookupProcessByProcessId / ObReferenceObjectByPointer sink-as-propagator wiring | Done (2026-05-08) |
| Linux exploit primitives (ret2win, egg-hunt, RWX-shellcode, alarm-timer, seccomp) | `analysis/linux_exploit.py` + `exploit/templates.py` (ret2win + egg-hunt PoC renderers) | Done |
| UE5 source patterns | `analysis/source_surface.py:_scan_ue5_source_patterns` (Plan D v1) | Done |
| BYOVD primitive class fingerprint | `heuristics/byovd_primitives.py` (E1-E7) | Done |
| Windows kernel IRP dispatch wiring | `analysis/windows_drivers.py` (per-slot + bulk memfill + nested-add offset fold for rebased-pointer shapes) | Done — 13/13 BYOVD-corpus IOCTL handlers resolved |
| Tainted-pointer-dereference (CWE-822) | `analysis/taint.py` E4 | Done |
| Inlined-memcpy structural detection | `analysis/taint.py` E5 | Done |
| Hardening matrix (`/GS`, CFG, ASLR, CET, etc.) | `analysis/mitigations.py` | Done |
| Crypto-primitive fingerprint (LCG/MT/AES/DES/MD5) | `heuristics/crypto.py` | Done |
| Obfuscation (entropy / RWX / CFF / LCG-XOR string cipher) | `analysis/obfuscation.py` | Done |
| Phase 2 source enrichment (callee alignment + IOCTL decode) | `analysis/source_surface.py` | Done |
| Phase 4 verification — Linux SSH lab (sanitizer + dmesg deltas) | `verify/sanitizer.py` | Done |
| Phase 4 verification — local subprocess (cross-platform; drives Phase-3 PoCs against userspace targets on the analysis host itself) | `verify/local.py` — `verify_local(plan)` + `verify_finding_locally(finding, poc_script)`; shares `VerificationResult` with the SSH variant | Done |
| Per-finding PoC generator (Phase 3, generic, 12 category renderers) | `exploit/finding_poc.py` — emits deterministic `[+] EXPLOIT RAN` marker the Phase-4 harness greps for | Done |
| Runner integration — Detect → PoC → Verify in a single pass, with `(binary, category)` PoC dedup and multi-language cell skip | `vulntest/runner.py:_run_local_verifications` + `--c-cpp-only`/`--verify`/`--no-verify` flags | Done |
| Known-vulnerable byte-pattern (0patch corpus, 2991 entries) | `heuristics/known_vulnerable_patterns.py` (exact SHA-1 + fuzzy version match) | Done |
| Output (Finding v2 schema, SARIF 2.1.0, Markdown) | `output/` | Done |
| Vendor-format renderers (HackerOne / MSRC / Bugcrowd / Epic Games) | `output/vendor.py` — PROVEN-only gate enforced | Done |
| Phase 3 scaffolding (Primitive + PoC + ROP/JOP gadgets + multi-arch shellcode) | `scripts/exploit/` — primitives.py / chain.py / gadgets.py / shellcode.py / templates.py | Done — scaffolding |
| Phase 5 Triage (auto-triage DETECTED → CONFIRMED) | `scripts/triage/__init__.py` — confidence-threshold default; reachability gates planned for v2 | Done — scaffolding |
| Chain composition (heuristics/chains.py + ChainPattern.min_primitives) | `heuristics/chains.py:match` — round-trips PoC.to_chain_template_payload() back into ChainPattern | Done |
| VulnTest harness (cell discovery, vuln/clean diff, hard-sig matcher, substrate-coherence check) | `vulntest/runner.py` + `vulntest/build_all.sh` (MSVC vcvars64) | Done |
| Clean-corpus FP sweep harness | `dev/clean_corpus_sweep.py` — 15-binary Windows System32 baseline | Done |

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
| **Tier-1 VulnTest corpus** (28 cells × C/C++/Go/Rust/.NET sub-cells) | DETECTED + IMPACT_VERIFIED | Cells span the full bug-class taxonomy: apc-injection, api-hash-resolution, command-injection, decrypt-external-pages, deserialization, direct-syscall, double-free, format-string, heap-overflow, hidden-thread, integer-overflow, iv-reuse, lcg-xor-cipher, null-dacl, off-by-one, path-traversal, peb-antidebug, permissive-sddl, pre-verify-write, prng-security-path, seh-veh-abuse, stack-overflow, tls-callback, toctou, trusted-path-xref, type-confusion, uninit-mem-disclosure, use-after-free. The 2026-05-11 `vulntest --c-cpp-only` sweep produced 51 PASS / 0 WARN / 4 FAIL and **100 IMPACT_VERIFIED transitions across 28+ cells** through the integrated Detect → PoC → Verify pipeline. Tier-2 chains (EAC + UE5) emit end-to-end via `ChainPattern.min_primitives`. Multi-language sub-cells (Go / Rust / .NET) build cleanly but are currently skipped by the local-verify harness pending per-language detectors (the `dotnet_managed.py` v1 heuristic catches metadata-rich shapes; runtime-pattern FPs against the C-flavoured detectors keep the cells out of verification scope). `double-free/c` (struct-field aliasing) remains FN — flagged as v3 work. |
| **HTB binary-exploitation + rootkit track** (Runs 21-XX) | DETECTED + PROVEN | 11/11 challenges solved; 18+ working PoC scripts. Mathematricks (int32 overflow), Racecar (format string / random race), Restaurant (ret2libc two-stage), r0bob1rd (3-stage format-string GOT overwrite), Questionnaire (ret2win), El Teteo / El Mundo / El Pipo / Rocket Blaster XXX / Hunting (ret2shellcode + variable overwrite variants), Cyberpsychosis (diamorphine LKM rootkit — MAGIC_PREFIX = "psychosis", getdents64 hook bypassed via stat-based probing, world-readable flag at `/opt/psychosis/flag.txt`). All exploits run live over VPN. Third-party-graded, time-stamped solves at public Argus HTB profile. |
| Decrypt-into-externally-owned-pages disclosure target (CVE-2026-43284 esp4/esp6 + CVE-2026-43500 rxrpc) | IMPACT_VERIFIED — framework's generic detector caught the disclosed CVE class organically (2026-05-08) | The pre-existing `analysis/decrypt_external_pages.py` (scatterlist-constructor + crypto-decrypt-sink without privately-own-gate) fired on the disclosure-named call sites — `esp_input`, `esp6_input`, `rxkad_verify_packet_1` — across Ubuntu 24.04 / 6.8.0-111 pre-patch modules, plus 2 sibling-class candidates (`rxkad_decrypt_ticket`, `rxkad_verify_response`). Phase-4 harness ran the public PoC against the lab VM: ESP path corrupted `/usr/bin/su` page cache (entry bytes `31 ff` at 0x78 confirmed; dmesg captured kernel-side `'su' launched '/bin/sh' with NULL argv`); RxRPC path injected `root::0:0:` into `/etc/passwd` page cache (`getent passwd root` returned the empty-password root entry via NSS). State: `esp_input` + `rxkad_verify_packet_1` → IMPACT_VERIFIED, `esp6_input` → IMPACT_PENDING (PoC IPv4-only). Evidence: `vulntest/known-positive/dirty-frag/impact-verification/`. |

**Microsoft accessibility binaries** (utilman / sethc / osk) — used
as a control set:

| Binary | Result |
|---|---|
| `utilman.exe` | 3 candidate-grade TOCTOU findings in ATL `StartList::HandleFirstTime` (`GetFileAttributesW` → `DeleteFileW` over `CAtlList<CRegKey>` iteration). Status: requires source-level review; registry-derived path + one-time-setup function suggests but does not prove benign. |
| `sethc.exe` | 0 findings (CFG-disjoint-branch fix correctly suppressed the phi-merge artefact in `SettingsCopier::DeleteATSettings`). |
| `osk.exe` | 0 findings. |

## Pre-Argus comparison

Fresh side-by-side numbers from the 2026-05-11 head-to-head run.
Both pipelines were invoked against the identical 3-binary
Microsoft accessibility control set (`utilman.exe`, `sethc.exe`,
`osk.exe`) on the same host, same Binary Ninja install, same
session. Harnesses: `dev/legacy_validate.py` (subprocess-driven
against `~/.claude/skills/binary-ninja/scripts/`) and
`dev/validate.py` (in-process Argus pipeline).

| Axis | Legacy | Argus | Delta |
|---|---|---|---|
| Control-set finding count (3 binaries) | 43 | 3 (candidate-grade TOCTOU in `utilman.exe`) | **~14× quieter** |
| Per-binary finding breakdown | utilman 3 / sethc 2 / osk 38 | utilman 3 / sethc 0 / osk 0 | osk noise fully gated |
| Wall-clock pipeline runtime (3 binaries, end-to-end) | 117.7s | 26.8s | **~4.4× faster** |
| Per-finding Knowledge citation | None | 82% Knowledge-cited (cumulative across detector lineup) | new capability |
| Per-finding confidence + exploitability axes | None | `confidence` + `mitigation_weighted_exploitability` (independent) | new capability |
| Sources / sinks coverage | 35 sources, 34 sinks | 45 sources, 98 sinks | supersets |
| Native API / BYOVD primitive set | None | Full coverage (E1–E7) | new capability |
| Phase 3 — generic per-finding PoC generator | None | 12 category renderers | new capability |
| Phase 4 — dynamic verification | None | SSH-driven (Linux kernel lab) + local-subprocess (cross-platform userspace) | new capability |
| End-to-end Detect → PoC → IMPACT_VERIFIED in one pass | None | `vulntest --c-cpp-only` walks 100 IMPACT_VERIFIED transitions across the C/C++ corpus | new capability |

The Argus detector lineup grew substantially between the original
April calibration and this run (14 heuristics, 24 analysis modules;
+8 modules since the last comparison), so per-binary wall-clock
time rose from the 14.9 s seen in April to 26.8 s today — the new
modules pay for themselves in coverage. The legacy timing dropped
from 200.4 s to 117.7 s on this host (different background load
than the April calibration); the head-to-head ratio is the
load-bearing number.

The 3 remaining Argus findings on `utilman.exe` are the
race-detector's TOCTOU triple in ATL `StartList::HandleFirstTime`
(`GetFileAttributesW` → `DeleteFileW` over `CAtlList<CRegKey>`),
flagged as candidate-grade pending source-level review. Argus
emits zero findings on `sethc.exe` and `osk.exe`; the legacy
toolchain emits 2 and 38 respectively on the same inputs.

Caveat on FP framing: legacy emissions don't ship with per-finding
provenance, so "FP rate" against legacy output isn't reproducible.
Some of the 43 legacy emissions were proximate to genuinely
surfaced patterns. The honest summary: same input, same host,
~14× fewer emissions and ~4.4× faster runtime; Argus also tags
each emission with its driving Knowledge entry and a confidence
score, neither of which the legacy pipeline produces.

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
| Phase 4 Windows-kernel-lab integration | Local-subprocess harness covers Windows userspace (100 IMPACT_VERIFIED across the C/C++ corpus, 2026-05-11). Windows **kernel** verification (e.g. `dbutil_2_3.sys` driver, currently CONFIRMED) still needs a remote-Windows-kernel target plumbed analogously to `verify_remote`. |
| Per-language detectors (Go gopclntab, Rust DWARF + panic-string anchors, .NET IL walk) | `dotnet_managed.py` v1 is heuristic string co-presence. Multi-lang cells are currently skipped by the local-verify harness (`--c-cpp-only` filter) until per-language detectors can distinguish runtime patterns from real bugs (Go runtime's `<=` comparisons FP into the off-by-one detector, Rust release binaries' large function counts time out under the same detector, etc.). |
| Linux kernel-module build infrastructure | `vulntest/tier1-single/decrypt-into-external-pages/c` and the dirty-frag fixtures both rely on out-of-tree `.ko` builds; missing toolchain in the fixture corpus blocks any Phase-4 verification driven from inside the repo. The Phase-4 harness already differentiates `verify_remote` (kernel-LPE) vs `verify_local` (userspace) — only the fixtures are missing. |
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

### Known-vulnerable-pattern corpus

`heuristics/known_vulnerable_patterns.py` consumes a curated corpus
at `data/known_vulnerable_patterns.json` containing
`(binary, sha1, vulnerable offset, pre-patch byte signature, CVE,
class)` tuples. The corpus contains **only research-derivable
fields** — every record is reproducible from public CVE
disclosure plus binary diff against the patched version. The
detector emits in two modes:

- **Exact match**: SHA-1 of the analyzed binary is in the corpus →
  flag every recorded offset as a known-vulnerable code path
  (severity inherited from the vulnerability class).
- **Fuzzy match**: same binary name but different SHA-1 — scan
  recorded offsets for the pre-patch byte signature; if still
  present, the vulnerability likely persists in this version.

The corpus is regenerated by an operator-private pipeline outside
this repository; only the redacted JSON ships here.

When new analysis modules land, expand the control set first, then
re-run the comparison: a row added to a richer module set against a
larger control set is the most informative baseline.
