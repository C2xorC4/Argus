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

Status: **Phase 1 + 2 substantially complete; Phase 3 + 5 + 6 scaffolding shipped; Phase 4 minimal slice landed**.

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
│   ├── detection-gaps.md            ← exploitation pattern gaps identified in live runs
│   └── DIRTY_FRAG_DETECTION_PLAN.md ← CVE-2026-43284/43500 detector design
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
| 1 | Identification stage rebase (heuristics + analysis modules + malware-analyzer + vuln-class-analyzer + manual-workflow docs) | **Substantially complete** — 11 heuristics + 12+ analysis modules; Phase 1++ E1-E7 BYOVD detection (13/13 multi-driver sweep); Run-14 per-seed visited tracking; Tier-2 foundational classes; Plans A-D + integrity_check_order v4 (verify-call-presence) + cleanup_dominance v2 + trusted_path detectors |
| 2 | Source-guided / grey-box pipeline | **Substantially complete** (closed 2026-05-07) — three Epic-submission coverage gaps closed: SDDL/ACE, write-then-verify v3 (verify-call-dominates-commit), PRNG provenance (Path A/B/C + IV-reuse + custom-cipher signatures); callee-signature alignment slice |
| 3 | Exploitation stage | **Scaffolding shipped** (2026-05-07) — `exploit/` package: Primitive + PoC dataclasses, `compose_pocs(findings)` with state transitions + Evidence accumulation, x86/x86_64 RET + JOP gadget finder, multi-arch shellcode tables (x86 / x86_64 / aarch64 Linux execve_sh + x86 / x86_64 Windows winexec_calc), pwntools-style PoC renderer with ret2win + egg-hunt templates |
| 4 | Verification stage | **In progress** — minimal SSH-driven slice landed; first IMPACT_VERIFIED transitions on CVE-2026-31431 (Run 8); HTB complete binary-exploitation + rootkit track — 11/11 challenges PROVEN; 18+ working PoC scripts; live remote exploitation over HTB VPN |
| 5 | Triage + Differ + Patcher | **Triage functional** (2026-05-07) — `auto_triage(findings, min_confidence)` promotes DETECTED → CONFIRMED, wired between chain-match and PoC composition. Differ + Patcher scaffolding: dataclasses + skeleton API; full implementations deferred |
| 6 | Synthesis + reporting | **Scaffolding shipped** (2026-05-07) — `output/vendor.py` HackerOne / MSRC / Bugcrowd / Epic Games renderers with PROVEN-only emission gate; SARIF + Markdown renderers from Phase 0 |

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
| Pre-verification write (verify-dominates-commit + verify-presence v4) | `analysis/integrity_check_order.py` v4 | Done — gate-2 CLEAN |
| Missing cleanup on failure | `analysis/cleanup_dominance.py` v2 (verify-call-presence gate) | Done — gate-2 CLEAN (suppresses notepad-class FPs) |
| Trusted-path cache load | `analysis/trusted_path.py` v1 (binary-scope path-string + load-API) and v2 (per-callsite SSA xref from path literal to load API; HIGH severity, suppresses v1 when v2 fires) | Done — gate-2 CLEAN (0 FPs across 15-binary clean Windows corpus) |
| Low-entropy PRNG seed | `analysis/crypto.py:find_low_entropy_seeds` (Plan C v1) | Done |
| Synthetic PRNG sources from LCG constants | `analysis/crypto.py:_enumerate_synthetic_prng_call_sites` (Plan C v2) | Done |
| CSPRNG-then-srand laundering | `analysis/crypto.py:find_csprng_laundered_to_prng` (Plan C v2) | Done |
| Weak PRNG in security-named context (Path B/C) | `analysis/crypto.py` — function/caller name match + binary-scope indicator + MSVC-mangling-aware filter | Done |
| IV reuse (constant or shared-buffer across cipher-init calls) | `analysis/crypto.py:find_iv_reuse` — consults `PossibleValueSet.value` for constant-pointer resolution | Done |
| Custom cipher constants (Salsa/ChaCha sigma, RC4 table size) | `heuristics/crypto.py` — added Salsa/ChaCha sigma 0x61707865, RC4 256-byte marker | Done |
| Decrypt-into-externally-owned-pages (Dirty Frag class) | `analysis/decrypt_external_pages.py` v1 (binary-scope import co-presence) | Done — v1 (CVE-2026-43284 / CVE-2026-43500 target) |
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
| Phase 4 verification (SSH sanitizer + dmesg deltas) | `analysis/verify/sanitizer.py` | Done |
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
| **Tier-1 VulnTest corpus** (12 cells + 1 IV-reuse + 1 decrypt-external-pages) | DETECTED | 11/12 TP on the original 12; new cells (iv-reuse, decrypt-external-pages) extend coverage. Tier-2 chains (EAC + UE5) emit end-to-end with `ChainPattern.min_primitives`. Only `double-free/c` (struct-field aliasing) remains FN — flagged as v3 work. |
| **HTB binary-exploitation + rootkit track** (Runs 21-XX) | DETECTED + PROVEN | 11/11 challenges solved; 18+ working PoC scripts. Mathematricks (int32 overflow), Racecar (format string / random race), Restaurant (ret2libc two-stage), r0bob1rd (3-stage format-string GOT overwrite), Questionnaire (ret2win), El Teteo / El Mundo / El Pipo / Rocket Blaster XXX / Hunting (ret2shellcode + variable overwrite variants), Cyberpsychosis (diamorphine LKM rootkit — MAGIC_PREFIX = "psychosis", getdents64 hook bypassed via stat-based probing, world-readable flag at `/opt/psychosis/flag.txt`). All exploits run live over VPN. Third-party-graded, time-stamped solves at public Argus HTB profile. |
| **Dirty Frag** (CVE-2026-43284 esp4/esp6 + CVE-2026-43500 rxrpc) | IMPACT_VERIFIED — Phase-4 PoC exercised both LPE primitives (2026-05-08) | `analysis/decrypt_external_pages.py` v2 fires on the exact disclosure call sites — `esp_input`, `esp6_input`, `rxkad_verify_packet_1` — across Ubuntu 24.04 / 6.8.0-111 pre-patch modules, plus 2 sibling-class candidates (`rxkad_decrypt_ticket`, `rxkad_verify_response`). Phase-4 harness ran the public PoC at `github.com/V4bel/dirtyfrag` against the lab VM: ESP path corrupted `/usr/bin/su` page cache (entry bytes `31 ff` at 0x78 confirmed; dmesg captured kernel-side `'su' launched '/bin/sh' with NULL argv`); RxRPC path injected `root::0:0:` into `/etc/passwd` page cache (`getent passwd root` returned the empty-password root entry via NSS — PoC stderr explicitly logged `PRIMITIVE proven`). State: `esp_input` + `rxkad_verify_packet_1` → IMPACT_VERIFIED, `esp6_input` → IMPACT_PENDING (PoC IPv4-only). Evidence: `vulntest/known-positive/dirty-frag/impact-verification/`; plan: `docs/DIRTY_FRAG_DETECTION_PLAN.md`. |

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
