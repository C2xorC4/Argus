# Argus — Vulnerability-Research Pipeline

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
| 1 | Identification stage rebase (heuristics + analysis modules + malware-analyzer + vuln-class-analyzer + manual-workflow docs) | **In progress** — 11 heuristics + surface/mitigations/taint/heap landed; Phase 1++ E1-E5 enhancements landed (Run 10: dbutil_2_3.sys 1→32 findings) |
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
direction — fewer false positives on clean controls, no loss of
real signal, and increasing speed as the pipeline matures.

Re-runnable harnesses:

- `dev/validate.py` — Argus pipeline against a target list
- `dev/legacy_validate.py` — equivalent pre-rebase modules

### Run 1 — Phase 1 baseline calibration (2026-04-30)

**Target set:** Microsoft accessibility binaries (control samples;
known-clean Windows system binaries that exercise the toolchain on
fully-mitigated targets).

| Binary | Path | Size | Functions |
|---|---|---|---|
| utilman.exe | `C:\Windows\System32\utilman.exe` | 315 KB | 1,315 |
| sethc.exe   | `C:\Windows\System32\sethc.exe`   | 168 KB | 495 |
| osk.exe     | `C:\Windows\System32\osk.exe`     | 618 KB | 1,025 |

**Methodology.** Both pipelines invoke Binary Ninja headless with
full analysis on the same binary; both emit findings that are
counted comparably. Argus runs surface + taint + heap. Legacy
runs `security_audit.py` + `deep_analysis.py` + `heap_analysis.py`.

**Results.**

| Binary | Argus findings | Argus time | Legacy findings | Legacy time |
|---|---|---|---|---|
| utilman.exe | **0** | 7.4s | 3 | 65.1s |
| sethc.exe   | **0** | 3.0s | 2 | 71.3s |
| osk.exe     | **0** | 4.5s | 38 | 64.0s |
| **TOTAL**   | **0** | **14.9s** | **43** | **200.4s** |

**Findings characterisation (legacy).**

- **35/38 osk.exe findings: "Call to free()"** — every `free()`
  callsite flagged at medium severity. Pure noise; `free()` is
  the canonical heap-deallocation function and presence in any
  non-trivial binary is expected.
- 3 utilman.exe and 1 sethc.exe `security_audit` findings: similar
  shape — flagging `free` / `realloc` / `rand` / banned imports
  standalone, without taint context.
- 1 sethc.exe + 3 osk.exe `heap_analysis` findings: heap-pattern
  flags Argus's calibrated detector now correctly suppresses (no
  matching SSA def-use across actual free + use).
- All three `deep_analysis` runs produced 0 findings — even legacy
  taint correctly does not fire on these targets.

**What Argus changed (calibration deltas, this run).**

1. **Per-pattern severity replaces blanket-medium.** `free()` is a
   sink for `analysis/heap.py` UAF / double-free detection, not a
   standalone Finding. Legacy emitted one Finding per call site;
   Argus emits zero.
2. **Combo gating.** `NTDLL_UNHOOK` requires the full re-mapping
   import combo (`CreateFileMappingA + MapViewOfFile + UnmapViewOfFile +
   VirtualProtect + GetSystemDirectory*`); D3D hook requires
   `VirtualProtect` paired with D3D-unique interface names;
   `ntdll.dll` string is suppressed unless the unhook combo also
   fires.
3. **Word-boundary matching for short tokens.** `EAC` no longer
   matches `EACH`; `Present` no longer matches `represented`.
4. **PE / ELF format detection.** FORTIFY checks only fire on ELF
   (it's a glibc concept; PE binaries don't have FORTIFY semantics).
5. **Mitigation extraction wired and accurate.** All three Microsoft
   targets correctly profiled: `CFG=True ASLR=True DEP=True
   SAFESEH=True PE32+ HighEntropyVA=True`. Mitigation-weighted
   exploitability score feeds into every Finding.

**Conclusion.**

On three known-clean Microsoft control samples, Argus reports 0
findings (43 fewer than legacy) in 14.9s (≈13× faster). FP
suppression is genuine — mitigation extraction confirms the
targets carry full Win10/11 hardening; taint analysis
independently produces 0 findings on each (no actual source→sink
flows). Calibration moved the toolchain in the right direction
without losing real signal.

### Run 2 — Phase 1 with crypto + obfuscation modules (2026-04-30)

**Same target set, same calibration, broader detector surface.**
After landing `analysis/crypto.py` and `analysis/obfuscation.py`
(weak-PRNG-to-security-sink flow detection, MD5/DES/LCG constant
recognition, CSPRNG-vs-non-CSPRNG balance check; section-entropy
calculation, RWX-section detection, CFF-dispatcher candidate
recognition), re-run against the same control set. Expected:
0 findings remains; the two new modules add ≤ 0.4s overhead.

| Binary | Argus findings | Argus time | Δ vs Run 1 (time) |
|---|---|---|---|
| utilman.exe | **0** | 11.2s | +3.8s |
| sethc.exe   | **0** | 5.0s  | +2.0s |
| osk.exe     | **0** | 7.7s  | +3.2s |
| **TOTAL**   | **0** | **23.9s** | +9.0s |

Per-module timings on osk.exe (largest target):

| Stage | Time |
|---|---|
| Binja load + analysis | 6.1s |
| surface | 0.88s |
| taint | <0.01s |
| heap | 0.34s |
| crypto | 0.09s |
| obfuscation | 0.26s |

The added time is mostly Binja's analysis re-run; the new analysis
modules contribute < 0.4s each on the largest binary. **Crypto +
obfuscation produced 0 findings on all three** — correct: these
Microsoft binaries do not perform `rand()`-seeded crypto and are
not packed / RWX-flagged / CFF-flattened. New modules' work is
visible in their per-module timing slot, not in spurious findings.

**Conclusion.** Detector surface broadens 2× without regressing
the 0-FP-on-clean-control gate. Pipeline still ≈8× faster than
legacy total (23.9s vs 200.4s) despite running 5 modules instead
of 3.

### Run 3 — Phase 1.11 quality-gate run against the VulnTest corpus (2026-04-30)

**The first detection-capability measurement.** Runs 1 and 2
showed 0-FP-on-clean-controls (the absence-of-noise gate). Run 3
flips it: feed the pipeline known-vulnerable code and measure how
much it actually detects.

**Targets:** Tier-1 single-vulnerability cells in `vulntest/tier1-single/`.
Restricted to C and C++ columns (37 cells with `expected.json`;
managed-language cells need toolchains not on this Windows host).
Cells compile via `dev/run_corpus.py` which bypasses per-cell
Makefiles and applies inferred build flags directly.

**Methodology.** Each cell:

1. Compile `source/vuln.c` (or `vuln.cpp`) with MinGW gcc/g++ +
   the cell-Makefile-equivalent flag set
   (`-O0 -g -fno-stack-protector -fno-pie -no-pie ...`).
2. Run Argus full pipeline (surface + mitigations + taint + heap
   + crypto + obfuscation + attack_surface + chains).
3. Compare emitted Findings' `category` to `expected.json:findings[*].category`.
4. Classify per category: TP (emitted = expected), FN (expected
   but not emitted), FP (emitted but not expected).
5. Run legacy pipeline on the same binary for comparison.

**Headline numbers.**

| Metric | Argus | Legacy |
|---|---|---|
| Cells in scope | 37 | 37 |
| Build succeeded | 33 | 33 |
| Total emissions | 35 | 169 |
| Cells with 0 FP | 22/33 (67%) | — (not measured against expected.json) |
| Cells with strict-TP detection | 1/33 (3%) | — |
| Cells with relaxed-TP detection (related category) | 6/33 (18%) | — |
| Cells perfect (FN=0 + FP=0) | 1/33 | — |

**Build failures (4):** `null-dacl/c`, `permissive-sddl/c`,
`pre-verify-write/c`, `seh-veh-abuse/c` — all Windows-API-heavy
cells that need `advapi32` / `ntdll` import linkage MinGW-w64
doesn't pull by default. Iteration: add explicit `-ladvapi32` etc.
to the corpus harness flag set, or extend the harness to read the
cell Makefile's `LDFLAGS`.

**Per-category aggregate (Argus, all 33 cells).**

| Category | TP | FN | FP | Precision | Recall |
|---|---|---|---|---|---|
| api_hash_resolution | 1 | 0 | 0 | 1.00 | 1.00 |
| apc_injection_local *(related: apc_injection)* | — | — | 1 | rel-TP | rel-TP |
| ssn_resolution_helpers + ntdll_function_string *(related: direct_syscall_stub)* | — | — | 2 | rel-TP | rel-TP |
| lcg_constants + lcg_xor_cipher *(related: lcg_xor_string_cipher)* | — | — | 2 | rel-TP | rel-TP |
| csprng_absent + non_csprng_use *(related: weak_prng_in_security_path)* | — | — | 2 | rel-TP | rel-TP |
| stack_buffer_overflow | 0 | 2 | 0 | — | 0.00 |
| heap_buffer_overflow | 0 | 2 | 0 | — | 0.00 |
| use_after_free | 0 | 2 | 0 | — | 0.00 |
| double_free | 0 | 2 | 0 | — | 0.00 |
| format_string | 0 | 2 | 0 | — | 0.00 |
| command_injection | 0 | 2 | 0 | — | 0.00 |
| path_traversal | 0 | 2 | 0 | — | 0.00 |
| toctou | 0 | 2 | 0 | — | 0.00 |
| type_confusion | 0 | 2 | 0 | — | 0.00 |
| integer_overflow_to_allocation | 0 | 2 | 0 | — | 0.00 |
| off_by_one | 0 | 2 | 0 | — | 0.00 |
| uninitialised_memory_disclosure | 0 | 2 | 0 | — | 0.00 |
| direct_syscall_stub | 0 | 1 | 0 | — | 0.00 |
| (others) | 0 | 1-2 | 0 | — | 0.00 |

**Honest read.** Phase 1 baseline detectors are *conservative* —
they fire on the canonical pattern shape, miss real-world variants.
The biggest gap is **taint propagation through memory** — argv is
seeded from `main()`'s parameter (post-fix, this run), but the
`argv[N]` indirection through char**, then through inter-procedural
calls into helpers, isn't fully tracked yet. That single gap
explains every `command_injection`, `path_traversal`, `format_string`,
and `stack_buffer_overflow` miss.

The second-biggest gap is **category-name precision vs umbrella**.
Five cells have detection working under a related-but-different
category name (`apc_injection_local` vs `apc_injection`,
`lcg_constants` vs `lcg_xor_string_cipher`, `csprng_absent` vs
`weak_prng_in_security_path`). The detection is correct; the label
disagrees. Either expected.json should use the precise subtype, or
the heuristic should additionally emit the umbrella.

The third gap is **SSA-on-globals** — `g_session` UAF / double-free
cells use a global pointer; current heap detector tracks SSA
versions, which doesn't apply directly to globals. Phase 1+ adds
load/store tracking on globals.

**Comparison vs legacy.**

- Argus: **35 emissions across 33 cells**, of which 1 strict-TP +
  6 relaxed-TP + ~14 calibration FPs (mostly category-naming) +
  ~14 unrelated FPs.
- Legacy: **169 emissions across 33 cells**, dominated by `Call
  to free()` and similar standalone-import flags. Effectively
  no precision-recall measurement is possible without per-finding
  ground truth in the legacy output format.
- Argus / legacy emission ratio: **1 : 4.8** — Argus is ~5×
  quieter overall.

**Phase 1.11 gate status (per LIFECYCLE.md §4):**

| Gate | Required | Actual | Status |
|---|---|---|---|
| Detection (100% TP) | 100% | 18% relaxed / 3% strict on C/C++ | **NOT MET** |
| FPs (0 on test corpus) | 0 | 67% of cells have 0 FP; aggregate ~14 calibration-class FPs | **NOT MET** |
| FPs (0 on clean controls) | 0 | 0 (Run 1 + Run 2 still hold) | **MET** |
| PoC validation | trigger fires | deferred to Phase 3 | **N/A this phase** |
| Output schema (Finding v2 + SARIF 2.1.0) | conformant | conformant | **MET** |
| Pipeline integration | end-to-end on real + synthetic | corpus harness runs end-to-end | **MET** |
| Documentation | TESTING + MANUAL_WORKFLOWS + Knowledge cites | 8 manual-workflow docs, 82% Knowledge-cited patterns | **MET** |

**No promotion to `~/.claude/`** — Detection / FP gates not met.
Phase 1+ iteration sprint targets the three gaps above before
re-running Run 4.

**Iteration items prioritised by gap severity:**

1. **Argv-through-memory + char\*\* indirection.** Fix taint
   propagation to track loads from indexed pointers (`argv[N]`,
   `char**` dereference). Highest leverage — unblocks ~14 cells.
2. **Category umbrella emission.** Heuristic emits both precise
   (`apc_injection_local`) and umbrella (`apc_injection`) categories.
   Low-effort fix; converts 5+ relaxed-TPs to strict-TPs.
3. **SSA-on-globals taint.** Add memory-load tracking for globals
   referenced by free/UAF detection. Unblocks 4-5 heap cells.
4. **Compiler-variant stub byte recognition.** Extend
   `heuristics/syscalls.py:HELLS_GATE_STUB` to handle MinGW /
   MSVC inline-asm output variants.
5. **VulnTest corpus build harness Win32 linkage.** Add
   `-ladvapi32 -lkernel32` defaults so Win-API-heavy cells build
   under MinGW.

### Run 4 — Phase 1+ iteration sprint, post-fix corpus run (2026-05-01)

**Iteration items applied** (prioritised from Run 3 gap list):

1. **Argv-as-source seeding** via `main()` parameter walk — every
   `main(int argc, char**argv)` / `wmain` / `WinMain` form is now a
   synthetic source.
2. **Depth-counting fix** — intra-function SSA chain length no
   longer consumes the inter-procedural depth budget; compiler-
   generated register shuffles don't burn it.
3. **Position-aware sink check** — taint reaching a sink at a
   non-dangerous arg slot no longer fires; the propagator path
   continues.
4. **Propagator table** in `analysis/taint.py:PROPAGATORS` — when
   tainted data is at a `memcpy` / `sprintf` / `snprintf` / `strcpy`
   source-arg slot, the destination buffer's SSA var inherits the
   taint and propagation continues.
5. **Umbrella category emission** in `heuristics/injection.py` —
   precise variants (`apc_injection_local`, `process_hollowing`)
   also emit their umbrella (`apc_injection`, `process_injection`).
6. **`stack_buffer_overflow` as default `buffer_overflow` sink-class
   category** — taint emits the category cells expect.
7. **Conditional `-municode` in corpus harness** — applied only to
   cells whose source actually defines `wmain` / `wWinMain`,
   unblocking the wmain-using Win-API cells without breaking
   plain-`main` cells.
8. **Win32 linkage flags** (`-ladvapi32 -lkernel32 -luser32 -lbcrypt`)
   in corpus harness.

**Results.**

| Metric | Run 3 | Run 4 | Δ |
|---|---|---|---|
| Cells in scope | 37 | 37 | — |
| Build succeeded | 33 | **36** | **+3** |
| Detection complete (FN=0) | 1/33 | **4/36** | **+3** |
| 0-FP cells | 22/33 (67%) | **24/36 (67%)** | hold |
| Perfect (FN=0 + FP=0) | 1/33 | **2/36** | **+1** |
| Argus emissions | 35 | 40 | +5 |
| Legacy emissions | 169 | 184 | +15 |

Build-failure list dropped from 4 to 1: `seh-veh-abuse/c` only
(MSVC `__try`/`__except` extensions; MinGW gcc doesn't support
the inline-asm form the cell uses).

**Strict-TP detections per category (R = 1.00 unless noted):**

| Category | Cells covered | Recall |
|---|---|---|
| `api_hash_resolution` | 1/1 | 1.00 |
| `apc_injection` (umbrella) | 1/1 | 1.00 |
| `format_string` | 1/2 | 0.50 (cpp uses iostreams; C-style printf only catches the C variant) |
| `stack_buffer_overflow` | 1/2 | 0.50 (cpp uses `std::cin >> name`; C++ stream-source recognition not yet wired) |

**Conclusion.** The iteration sprint moved the toolchain from 1
strict-TP to 4 strict-TPs, plus 3 unblocked builds. The remaining
gaps are systematic — same pattern explains most missing
detections:

- **C++ source pattern recognition** — `std::cin >>`, `std::printf`,
  `std::system` aren't import names; need source-language-aware
  taint sources / sinks. Affects format_string/cpp,
  stack_buffer_overflow/cpp, command_injection/cpp,
  path_traversal/cpp.
- **Buffer-content tainting** — `snprintf(buf, ...); system(buf);`
  pattern needs stack-variable taint tracking, not just
  SSA-variable taint. Affects all `command_injection` and
  `path_traversal` cells.
- **SSA-on-globals** — UAF/double-free cells use module-level
  globals; SSA versioning doesn't apply directly. Affects all
  `use_after_free` and `double_free` cells.
- **Type-confusion and off-by-one detection** — neither has a
  Phase-1 detector module (would require structural pattern
  recognition over IL).
- **Uninit-mem-disclosure** — needs partial-fill-then-output
  pattern recognition (struct-shape-aware analysis).

These five gaps explain the remaining 32 cells with FN ≥ 1.

**Phase 1++ iteration plan** — Run 5 targets:

1. C++ source-language taint extension (lifts ~6 cells)
2. Buffer-content tainting via stack-variable tracking (lifts ~4 cells)
3. SSA-on-globals taint extension (lifts ~4 cells)
4. Type-confusion detector (`static_cast` from polymorphic base)
5. Off-by-one detector (`<=` against buffer-size constant)

Each is a Phase 1++ iteration; none requires architectural redesign.

**Comparative summary across all runs:**

| | Argus emissions | Argus strict-TP cells | Legacy emissions |
|---|---|---|---|
| Run 1 (3 control samples) | 0 | n/a | 43 |
| Run 2 (same, +crypto+obf) | 0 | n/a | 43 |
| Run 3 (corpus, 33 cells) | 35 | 1/33 (3%) | 169 |
| Run 4 (corpus, 36 cells, post-iteration) | 40 | 4/36 (11%) | 184 |

Argus / legacy emission ratio across the corpus: **1 : 4.6** —
quieter than legacy by ~5×, with 11% true detection vs an
unmeasurable legacy detection rate (legacy doesn't carry per-finding
ground-truth comparison). Phase 1++ iteration targets 60-80% strict
TP before the next promotion gate attempt.

### Run 5 — Live 0-day landed: CVE-2026-31431 ("copy.fail") as known-positive (2026-05-01)

A real-world disclosure landed during the iteration sprint:
**copy.fail / CVE-2026-31431** — a 4-byte attacker-controlled OOB
write in the Linux kernel `algif_aead` / `authencesn` crypto path
that has been silently exploitable for ~9 years. Container-escape
grade; affects Ubuntu 24.04 / Amazon Linux 2023 / RHEL 10.1 / SUSE
16 plus most Linux distributions. PoC is 732 bytes of stdlib
Python.

Imported as a `known-positive/` corpus cell so Argus's detection
quality is measurable against live disclosed real-world bugs, not
just synthetic VulnTest cells.

**Cell:** [`vulntest/known-positive/CVE-2026-31431/`](vulntest/known-positive/CVE-2026-31431/)

| Artefact | Source |
|---|---|
| `source/algif_aead.c` | torvalds/linux v6.12 (vulnerable) |
| `source/authencesn.c` | torvalds/linux v6.12 (vulnerable) |
| `poc/_repo/` | clone of theori-io/copy-fail-CVE-2026-31431 |
| `expected.json` | what should fire on detection |
| `remediation/README.md` | upstream fix + temporary mitigations |

**The bug shape (one line):**

```c
// authencesn.c line 295 — crypto_authenc_esn_decrypt
scatterwalk_map_and_copy(tmp + 1, dst, assoclen + cryptlen, 4, 1);
//                                     ^^^^^^^^^^^^^^^^^^^      ^
//                                     attacker-controlled      write
//                                     offset (from req->*)     direction
```

When `dst` is the in-place AEAD scatterlist (chained via
`sg_chain()` in `algif_aead.c` to attach splice'd page-cache
pages), the 4-byte write at `assoclen + cryptlen` lands in
read-only page-cache memory, silently corrupting cached file
contents.

**Phase 1 binary detection:** **gated** — needs a vulnerable
`algif_aead.ko` extracted from one of the affected distros. Forward-
ready: `scatterwalk_map_and_copy` is now in `heuristics/imports.SINKS`
under sink-class `kernel_oob_write`, which maps to category
`kernel_oob_write_at_offset` (severity CRITICAL, CWE-787, MITRE
T1068+T1611). When the binary lands, taint analysis should fire on
the offset arg if it can trace from `req->assoclen + req->cryptlen`.

**Phase 2 source detection:** the natural fit. The source-attack-
surface mapper would identify `crypto_authenc_esn_decrypt` as an
AEAD entry point, taint from `req->*`, hit `scatterwalk_map_and_copy`
at line 295. Phase 2 isn't built yet — this cell becomes one of its
first test cases.

**Iteration items added:**

1. `scatterwalk_map_and_copy`, `memcpy_to_iter`, `copy_to_iter`
   added to taint sink registry as `kernel_oob_write` class.
2. New `SINK_CLASS_META` entry: `kernel_oob_write` →
   `kernel_oob_write_at_offset` finding category, severity
   CRITICAL, CWE-787, MITRE T1068+T1611.
3. New `vulntest/known-positive/` tier — for live-disclosed CVEs
   with public source + PoC. Cells added as further disclosures
   land.

**What this run *doesn't* do:**

- Doesn't pull the kernel module binary (would require Linux + the
  affected distro's kernel image extraction; deferred to next
  session on legion/strx).
- Doesn't iterate Phase 1 detector recall further — the iteration
  sprint's open items (C++ stream sources, buffer-content taint,
  SSA-on-globals, type-confusion, off-by-one) are still on the
  Phase 1++ list.

**Run 5 metric impact:** No corpus re-run — adding the cell adds
data, not detection capability. The known-positive cell shifts the
gauge: detection efficacy is now measurable not just against
synthetic Tier-1 cells but against live-disclosed real-world
disclosures with full ground-truth artefacts.

### Run 6 — first run against the live `algif_aead.ko` / `authencesn.ko` (2026-05-01)

Channel-up run. After Proxmox VM stand-up + SSH wiring, pulled
the actual vulnerable kernel modules from a fresh Ubuntu install
(kernel `6.8.0-111-generic`, built `2026-04-11` — 11 days BEFORE
the disclosure; pre-fix and confirmed in the vulnerable window).

**Pipeline-side gaps surfaced:**

1. **`imports_in()` missed ExternalSymbol type** — kernel modules
   reference kernel core via the `ExternalSymbol` mechanism, not
   userspace `ImportedFunctionSymbol`. Argus saw 0 imports on the
   .ko initially. Fixed: extended `heuristics/_base.py:imports_in()`
   to cover `ExternalSymbol`, `ImportAddressSymbol`, and
   `ImportedDataSymbol` in addition to the userspace shape.
2. **FORTIFY heuristic firing on kernel modules** — same FP shape
   as Run 1's PE-vs-ELF issue; FORTIFY is a glibc-only concept,
   doesn't apply to kernel modules. Fixed:
   `heuristics/mitigations.py:_is_userspace_elf()` rejects kernel
   modules via `entry_point==0` plus section-marker discriminators
   (`.modinfo`, `__versions`, `.gnu.linkonce.this_module`).

**Detection gap surfaced:** taint analysis didn't fire even after
the import-table fix. `analysis/taint.py:_seed_argv_taint()` works
for userspace `main()` but kernel modules don't have `main()`.
Their entry points are functions registered into kernel subsystems
(crypto template ops in this case). Tracked as Run 7's primary
iteration item.

**Run 6 result:** 0 findings, 0 FPs. Pipeline cleanly handles
kernel modules end-to-end but doesn't yet detect the bug — the
detection-source plumbing is the next iteration.

### Run 7 — kernel-mode taint seeding lands; live CVE caught (2026-05-01)

The first-ever real-world disclosed CVE caught by Argus on a
stripped kernel module without source / debug info.

**Iteration shipped:**

1. **`analysis/taint.py:_seed_kernel_module_taint()`** — analog of
   `_seed_argv_taint()` for kernel modules. Detects kernel `.ko`
   via section markers; for each non-stub function, seeds taint
   from the SSA variables corresponding to argument-register
   prefixes (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` per Linux
   x86_64 SysV; `rcx`/`rdx`/`r8`/`r9` for Win64).
2. **Argument-register-via-SSA-naming heuristic** — Binja's
   stripped-`.ko` analysis doesn't recover C-level parameter
   types (`func.parameter_vars` is empty), so seeding from typed
   parameters fails. Instead, scrape `func.mlil.ssa_form.ssa_vars`
   for SSA variables whose underlying register name matches the
   ABI's arg-register set; take the lowest-version of each (the
   function-entry value).
3. **`peb_antidebug_check` combo-gate.** The `imports_in()`
   extension surfaced new imports that triggered FPs on Win32
   control samples (every Win32 binary imports `IsDebuggerPresent`
   /`OutputDebugString*`). Combo-gated to require co-presence of
   PEB-field strings (`BeingDebugged`, `NtGlobalFlag`, ...).

**Results:**

| Module | Funcs | Findings | Severity | Interpretation |
|---|---|---|---|---|
| `authencesn.ko` (CVE site) | 34 | **6** | critical | **TPs** at the disclosure-cited call sites: `crypto_authenc_esn_decrypt`, `_genicv`, `_decrypt_tail`, `_genicv_tail` — taint flows from kernel arg registers through field-offset loads to `scatterwalk_map_and_copy` |
| `algif_aead.ko` (chained-sg setup) | 32 | 0 | — | **Correct** — bug isn't here; this module sets up the in-place chained scatterlist that *makes* the OOB possible, but the write itself happens in authencesn |
| `authenc.ko` (non-ESN sibling) | 36 | 4 | critical | **Sibling-class candidates** — same `scatterwalk_map_and_copy` pattern with attacker-derived offset; not the disclosed CVE per se but worth manual triage. Detector correctly generalises the bug class |
| utilman / sethc / osk (control) | varies | 0 each | — | **Regression-free** — Win32 control set still 0-FP after kernel-mode taint seeding lands |

**Detection methodology that worked:**

```
function entry: arg registers (rdi, rsi, ...) tainted by ABI
       │
       ▼ propagation through register-renaming SSA chain
intermediate: rax_N#M = [rdi_X + offset]   # field load
       │
       ▼ propagation through field loads
sink call: scatterwalk_map_and_copy(buf, sg, OFFSET, len, write=1)
                                          ^^^^^^
                                          tainted at arg index 2 (offset)
       │
       ▼ position-aware sink check: arg 2 is the dangerous slot
       ▼
EMIT: kernel_oob_write_at_offset @ <call site>
```

This worked despite:
- No source code available to Argus (sources fetched separately;
  the binary was analysed in isolation)
- `func.parameter_vars` being empty (stripped .ko, no DWARF)
- No type information for `struct aead_request` fields
- The bug being a multi-component issue (chained-sg setup is in a
  different .ko than the OOB write)

The detection emerges purely from:
- Recognising kernel-module-shaped binaries
- ABI-aware register taint seeding
- SSA def-use propagation through field-offset loads
- Position-aware sink check at `scatterwalk_map_and_copy(_, _, OFFSET, _, write_flag)`

**Phase 1.11 gate update:**

| Gate | Run 4 status | Run 7 status |
|---|---|---|
| Detection on real-world disclosure | not measured | **MET** (CVE-2026-31431 caught) |
| FPs on clean controls | MET | **MET** (held) |
| Cross-distro / generalisation | not measured | **MET in part** — detector generalises to authenc sibling; cross-distro pending |
| 100% TP on VulnTest C/C++ | NOT MET (11%) | NOT MET (Phase 1++ items still open) |

This is the first run where Argus catches a live-disclosed CVE on
a stripped binary. The Phase 1++ list (C++ stream sources, buffer-
content taint, SSA-on-globals, type-confusion, off-by-one) is
still open for the synthetic VulnTest corpus, but the kernel-mode
extension demonstrates the detection-engine architecture
generalises beyond userspace.

**Iteration items added to the Phase 1++ queue:**

1. **Tighten kernel arg-register seeding** — currently seeds all
   six SysV arg registers per function. For functions that take
   only one argument (the typical kernel API case), this over-taints.
   Refine to "only seed registers actually read in the function
   prologue" once Binja's calling-convention analysis lands more
   reliably.
2. **Validate against more kernel CVEs** — pull other recent
   kernel-crypto / kernel-net CVEs (CVE-2025-*, CVE-2024-*) and
   measure detection rate.
3. **Apply C source types for higher-precision detection** — when
   the cell carries source files (as `known-positive/CVE-2026-31431/`
   does), use them to apply struct types to Binja's binary view.
   Field accesses then become named (`req->assoclen` instead of
   `[rdi+0x18]`).

### Run 8 — Phase 4 minimal slice; first IMPACT_VERIFIED transitions (2026-05-01)

**What landed.** Phase-4 dynamic verification:

- `skills/binary-ninja/scripts/verify/sanitizer.py` — SSH-driven
  primitive (file-hash deltas + dmesg pattern matching + plan-
  declared setup/teardown commands).
- `skills/binary-ninja/scripts/verify/triage.py` — verification-plan
  orchestrator + state-machine driver.
- `skills/binary-ninja/scripts/lib/config.py` — typed
  `LabTargetConfig` accessor for the `[lab_target]` TOML section.
- `vulntest/known-positive/CVE-2026-31431/verification.json` — the
  reference plan: setup un-mitigates the modprobe.d block and
  loads the vulnerable modules; trigger runs the lab-side probe;
  teardown unloads modules and re-applies the block.
- `vulntest/known-positive/CVE-2026-31431/probe/{probe_authencesn.py,setup.sh,run_probe.sh,README.md}` —
  sandboxed adaptation of the public PoC. Targets
  `/tmp/argus_probe.txt` instead of `/usr/bin/su`; writes a
  16-byte `ARGV`-marker payload via the bug primitive.
- `dev/deploy_probe.sh` — rsync wrapper that syncs a cell's probe
  directory to `[lab_target].default_workdir/<cell-derived>/`.

**Pipeline.**

```
Phase 1 detection → findings.json (DETECTED, 6 entries)
                                 ↓
verify.triage applies plan      ↓
   ├── setup_commands run on lab (un-mitigate, modprobe, prep probe file)
   ├── pre-snapshot sha256 + dmesg drain
   ├── trigger: ssh <alias> 'bash ~/argus/2026-31431/run_probe.sh'
   ├── post-snapshot sha256 + dmesg read
   └── teardown_commands run on lab (rmmod, restore mitigation)
                                 ↓
verdict roll-up → state machine walked (DETECTED → CONFIRMED → IMPACT_VERIFIED)
                                 ↓
findings.json (IMPACT_VERIFIED, 6 entries) + run log
```

**Result.** All 6 Run-7-equivalent Findings on `authencesn.ko`
transitioned cleanly:

| Finding | Function | State path |
|---|---|---|
| `bba17208…` | `crypto_authenc_esn_decrypt` | DETECTED → CONFIRMED → IMPACT_VERIFIED |
| `6b193ad6…` | `crypto_authenc_esn_decrypt_tail` | DETECTED → CONFIRMED → IMPACT_VERIFIED |
| `131795ce…` | `crypto_authenc_esn_genicv` | DETECTED → CONFIRMED → IMPACT_VERIFIED |
| `40007ca3…` | `crypto_authenc_esn_genicv_tail.isra.0` | DETECTED → CONFIRMED → IMPACT_VERIFIED |
| `dcaa4918…` | `crypto_authenc_esn_decrypt_tail` | DETECTED → CONFIRMED → IMPACT_VERIFIED |
| `ac4a2149…` | `crypto_authenc_esn_genicv_tail.isra.0` | DETECTED → CONFIRMED → IMPACT_VERIFIED |

**Evidence chain.** Each Finding now carries:

- `verify_run` Evidence with the full `VerificationResult` (setup
  rcs, trigger stdout, post snapshot, teardown rcs)
- `file_delta` Evidence: `/tmp/argus_probe.txt: content (before=6896d9ea3f73, after=f415046c8e2e)`

The page-cache content of `/tmp/argus_probe.txt` after the trigger
shows `41524756 41524756 41524756 41524756` (`ARGVARGVARGVARGV`)
at offset 0 — the marker payload, written via the OOB primitive.
That delta is the bug demonstrated end-to-end.

**Lab state preserved.** Teardown ran cleanly: `algif_aead` and
`authencesn` unloaded, `/etc/modprobe.d/disable-algif_aead.conf`
restored. The lab is back in its documented mitigated state after
every cycle.

**Why a probe instead of the upstream PoC.** The public
`copy_fail_exp.py` and `kopy_fail_exp_lite.py` install a setuid
backdoor in `/usr/bin/su`. Argus only needs to demonstrate the
bug primitive *fired*; corrupting a real binary is invasive and
hard to reset cleanly between cycles. The probe variant uses an
identical kernel mechanism on a sandboxed `/tmp/` target with a
deterministic marker payload — same primitive, none of the
collateral.

**Phase 4 forward-state.** Documented inline in
`skills/binary-ninja/scripts/verify/README.md`. Items captured but
deferred:

- KASAN / KFENCE / UBSAN-instrumented kernel for sanitizer-pattern
  dmesg matches
- ASan / UBSan / MSan / TSan integration for userspace targets
- GDB / WinDbg / LLDB launch-chain harness for full-launch-chain
  PROVEN validation
- Crash deduplication and runtime-mitigation-aware exploitability
  refresh
- Per-finding plans (one trigger per finding) for finding-specific
  userspace exploitation
- Reachability gate before trigger

**Pivot.** With known-positive validation closed, the next phase
work resumes Phase 2 (source-guided slice). The struct-type
application against authencesn.c source — applied to Binja's view
of authencesn.ko — should give us named-field traces in evidence
(`req->assoclen` instead of `[rdi+0x18]`), measurably improving
the report-writer artefacts that Phase 6 will consume.

### Run 9 — Dogfood against `dbutil_2_3.sys` (CVE-2021-21551 BYOVD); detection-gap survey (2026-05-01)

**Target.** Dell BIOS Utility Driver `dbutil_2_3.sys` — Windows
kernel driver, PE32+, x86_64, 14,840 bytes, 25 functions, fully
stripped. Universally documented BYOVD: exposes IOCTL handlers
that take attacker-supplied pointers and produce arbitrary
kernel R/W primitives. Used in production red-team toolkits
(kdmapper, KDU). Disclosure mechanics established 2021.

**Argus output.** 1 finding total — `kernel_driver_irp_dispatch`
at INFO/LOW (just "this is a kernel driver"). **Zero** taint
findings. The vulnerability class is not detected at all.

**What Argus correctly identified:**

- File loaded as Windows kernel driver
  (`platform=windows-kernel-x86_64`, recognises INIT/PAGE
  sections)
- Mitigation profile populated: CFG/ASLR/DEP all `False`,
  SAFESEH `True` — driver-shape mitigation set
- Imports table extracted via the kernel-aware
  `ExternalSymbol` path that Phase 1 added for Linux .ko
  (16 imports: `MmMapIoSpace`, `MmGetPhysicalAddress`,
  `MmAllocateContiguousMemorySpecifyCache`, `IoCreateDevice`,
  `IoCreateSymbolicLink`, `IofCompleteRequest`, …)
- Surface heuristic `kernel_driver_irp_dispatch` fired on
  `IoCreateDevice + IoCreateSymbolicLink` pair

**What Argus missed (manual inspection, ground truth from
disclosure):**

The IRP dispatch table is wired at DriverEntry+0x110e7:

```
DriverObject->MajorFunction[0xe]  = sub_11170    // IRP_MJ_DEVICE_CONTROL — the IOCTL dispatcher
DriverObject->MajorFunction[0]    = sub_11170    // IRP_MJ_CREATE
DriverObject->MajorFunction[2]    = sub_11170    // IRP_MJ_CLOSE
DriverObject->MajorFunction[0x10] = sub_11170    // IRP_MJ_SHUTDOWN
```

`sub_11170` is the IOCTL dispatcher. It pulls the IRP from
`arg2`, reads `Parameters.DeviceIoControl.IoControlCode` from
the IO_STACK_LOCATION, and switches on the IOCTL code:

| IOCTL | Handler | Primitive |
|---|---|---|
| `0x9b0c1ec0` | `sub_151d4` | `MmAllocateContiguousMemorySpecifyCache` + `MmGetPhysicalAddress` — physical memory allocation, address leak |
| `0x9b0c1ec4` | `sub_15294(rdi, 1)` | **memcpy(arbitrary_kernel_ptr, user_data, len)** — arbitrary kernel WRITE |
| `0x9b0c1ec8` | `sub_15294(rdi, 0)` | **memcpy(user_buf, arbitrary_kernel_ptr, len)** — arbitrary kernel READ |
| `0x9b0c1f40` / `0x9b0c1f44` | `sub_15100(_, 0/1)` | `MmMapIoSpace(physaddr, size, MmNonCached)` + memcpy in either direction — physical memory R/W |
| `0x9b0c1f80..0x9b0c1f8c` | `sub_15008` | MSR R/W (`__readmsr` / `__writemsr` via custom stubs) |
| `0x9b0c1ecc` | (inline) | `MmFreeContiguousMemorySpecifyCache` — free arbitrary contiguous-memory allocation |
| `0x9b0c1f00` / `0x9b0c1f04` / `0x9b0c1f08` | (inline + DPC) | DPC scheduling / memcpy primitives |
| `0x9b0c1fc0` / `0x9b0c1fc4` | (inline) | physical-memory metadata write / cmpxchg |

Five distinct kernel-context arbitrary-resource primitives. Zero
of them surface as Argus findings.

**Why Argus missed it — five concrete gaps:**

#### Gap 1 — No Windows kernel sinks in `heuristics/imports.py`

`SINK_TABLE` carries `scatterwalk_map_and_copy` /
`copy_to_iter` / `memcpy_to_iter` (Linux kernel) but none of the
Windows kernel write-where-what primitives:

```python
# Missing; should be added:
("MmMapIoSpace",                            0, "kernel_arbitrary_rw"),
("MmGetPhysicalAddress",                    0, "kernel_phys_disclosure"),
("MmAllocateContiguousMemorySpecifyCache",  0, "kernel_alloc_size"),
("ZwMapViewOfSection",                      4, "kernel_arbitrary_rw"),
("__writemsr",                              0, "kernel_msr_write"),
```

Plus matching `SINK_CLASS_META` entries.

#### Gap 2 — No IRP dispatch table extraction → no IOCTL handler discovery

There's no heuristic that walks DriverEntry, finds writes of the
form `arg1->MajorFunction[N] = <addr>`, and registers `<addr>`
as an IOCTL dispatcher. Without this, the dispatch entry-point
is just `sub_11170` — Argus has no reason to seed taint there.

Implementation shape: a structural match for stores to
`MajorFunction[]` slots (offset `0x70 + N*8` from
DRIVER_OBJECT). Emit a Finding *and* register the handler in a
session-level dispatch map for downstream detectors.

#### Gap 3 — No Win64 ABI IOCTL-handler taint seeding

`_seed_kernel_module_taint` seeds from rdi/rsi/rdx/… (Linux SysV
ABI) and only fires when `_is_kernel_module()` matches Linux
.ko shape. Windows kernel drivers need the analogue:

- Win64 ABI: `rcx=DeviceObject`, `rdx=PIRP`
- Seed taint from `rdx` (the IRP) and the field-load chain into:
  - `IRP.AssociatedIrp.SystemBuffer` (METHOD_BUFFERED input/output)
  - `IRP.UserBuffer` (METHOD_NEITHER output)
  - `IO_STACK_LOCATION.Parameters.DeviceIoControl.Type3InputBuffer` (METHOD_NEITHER input)
  - `IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode` / `InputBufferLength` / `OutputBufferLength`

Without this, the taint analyzer has no source to propagate from.

#### Gap 4 — Tainted-pointer-as-pointer is not its own sink class

The dbutil arbitrary-write primitive doesn't pass tainted data
to a *named* sink — it reads 8 bytes from the user buffer and
*dereferences them as a kernel pointer*:

```
r9_1 = *arg1;                  // arg1 = user-controlled SystemBuffer
rax_1 = *r9_1;                 // r9_1 is the user-supplied pointer
rcx_2 = (zx.q(rax_3.d) + rax_2);   // composed kernel address
sub_11790(rcx_2, src, len);    // memcpy WHERE = attacker pointer
```

This is the canonical "write-anywhere primitive" shape: load
through tainted pointer, use load result as pointer. Currently
not recognised. Argus needs a sink class
`tainted_pointer_dereference` that fires on **any** dereference
where the pointer expression is tainted — independent of whether
the dereference is then handed to a named sink.

#### Gap 5 — Inlined / unrolled memcpy not in PROPAGATORS

`sub_11790` is memcpy, but it's MSVC-inlined and unrolled
(byte/word/qword/cacheline branches; never imported as a named
symbol). Current `PROPAGATORS` is name-keyed, so taint flow
through `sub_11790(dst, src, n)` is dropped.

Two compatible fixes:

- **Structural match.** A 3-arg function whose body is a
  copy-loop pattern (`*dst = *src; dst++; src++; len--` or its
  vectorised equivalent) is memcpy. Add `_seed_propagators_from_shape`
  alongside the name-keyed table.
- **Binja signature lib.** Apply the matching `mscomp.sig` /
  WDK signature pack at load time so Binja renames `sub_11790`
  to `memcpy` and the existing name-keyed propagator picks it up.

Either path; signature-lib is cheaper if the WDK pack is
reachable, structural is robust to stripped binaries that don't
match a signature.

**Enhancement queue (Phase 1++ before next iteration).**

Priority ordered. (1)+(2)+(3) together are the minimum to detect
this class of BYOVD; (4) catches the sub_15294 arbitrary-R/W
primitive specifically; (5) is a foundation the others rely on
for stripped kernel drivers without WDK signatures.

1. **Windows kernel sinks in `heuristics/imports.py`** —
   straightforward, additive, won't regress anything else
2. **IRP dispatch-table extractor** — new structural heuristic;
   exposes a session-level "registered handlers" map that seeds (3)
3. **Win64 ABI IOCTL-handler taint seeding** in `analysis/taint.py` —
   analogue of `_seed_kernel_module_taint` for Windows drivers
4. **`tainted_pointer_dereference` sink class** — generalises
   beyond BYOVD; catches any "use tainted load as pointer" pattern
5. **Inlined-memcpy structural detection** in `PROPAGATORS` —
   robust to stripped binaries

**Cell candidate.** When the work above lands, promote
`dbutil_2_3.sys` to a known-positive cell at
`vulntest/known-positive/CVE-2021-21551/` with `expected.json`
covering the five sink call sites. Phase 4 verification will
need a Windows lab target (out of scope for this dogfood —
current `lab_target` is Linux-only); for now the cell exists
as Phase-1-only known-positive.

**Daydream contributions.** A seeded daydream
(`Buffer/Daydream/2026-05-01_daydream-byovd-ioctl-dispatch-gap.md`)
arrived at the same five gaps independently from the
LJM Knowledge corpus side — particularly identifying that the
existing corpus has BYOVD-as-concept and IRP-transport-layer
coverage but no IOCTL-dispatch-internals or
physical-memory-mapping-primitive entries. That's a parallel
LJM Knowledge gap worth ingesting as a future Knowledge entry
once the Argus heuristics land.

### Run 10 — Phase 1++ E1-E5 enhancements; dbutil_2_3.sys revisited (2026-05-01)

**What landed.** Five enhancements queued from Run 9, all in
`skills/binary-ninja/scripts/`:

- **E1 — Windows kernel sinks** in `heuristics/imports.py`: added
  `MmMapIoSpace`, `MmGetPhysicalAddress`,
  `MmAllocateContiguousMemorySpecifyCache`, `MmMapIoSpaceEx`,
  `MmAllocateContiguousMemory`, `ZwMapViewOfSection`,
  `NtMapViewOfSection`, `__writemsr`, `__readmsr` to `SINKS`.
  Six new `SINK_CLASS_META` entries (`kernel_arbitrary_rw`,
  `kernel_phys_disclosure`, `kernel_alloc_size`,
  `kernel_msr_write`, `kernel_msr_read`,
  `tainted_pointer_dereference`).
- **E2 — IRP dispatch-table extractor** at
  `analysis/windows_drivers.py`: walks DriverEntry's tail-callee
  chain, finds `DriverObject->MajorFunction[N] = handler`
  writes via `MediumLevelILStoreStruct` shape, returns a
  structured `DispatchTable` and exposes
  `discover_ioctl_handlers(bv) -> list[int]`.
- **E3 — Win64 ABI IOCTL-handler taint seeding** in
  `analysis/taint.py`: `_seed_windows_ioctl_taint` consumes E2's
  output, seeds taint on the IRP-bearing argument(s) of every
  registered IOCTL handler. Prefers Binja-recovered typed
  parameters (the `windows-kernel-x86_64` platform module
  recovers `H(PDEVICE_OBJECT, PIRP)` from the
  `MajorFunction[]` slot type), falls back to `rdx`/`r8`/`r9`
  register-prefix seeding for stripped drivers. Also seeds
  the dispatcher's direct callees' parameters — needed because
  the dispatcher commonly stores user-controlled state into a
  `DeviceExtension`-typed buffer that pure SSA def-use can't
  follow across the memory-store boundary.
- **E4 — `tainted_pointer_dereference` sink class**: new
  emission rule that fires when a tainted SSA var (which itself
  came via at least one memory load) is used as the address of
  another load or store. Captures the BYOVD canonical
  arbitrary-R/W pattern (`*p = *q` where `q` was reloaded from
  user-controlled memory). Two confidence filters suppress
  noise: skip emission inside inlined-memcpy bodies, and skip
  emission for the Linux kernel-arg shotgun seeding.
- **E5 — Inlined-memcpy structural detection**:
  `_detect_inlined_memcpy_functions` runs at `analyze()` entry,
  identifies in-binary functions structurally shaped as memcpy
  (3 typed params, returns first param, 3+ stores and 3+ loads,
  body size in [8, 800] MLIL nodes), and registers them in
  `PROPAGATORS` as `[(1, 0)]` (src arg → dst arg). The
  inlined-memcpy address set also gates E4 emission and E3
  callee-seeding so memcpy internals don't pollute the finding
  output. Generic call-return transit added: when an unnamed
  callee receives a tainted argument, its return value
  conservatively inherits taint, letting flows past trivial
  wrappers without per-callee modelling.

**Re-run.** `dev/validate.py` against `dbutil_2_3.sys`:

|        | Run 9 | Run 10 |
|---|---|---|
| Total findings | 1 | **33** |
| Surface (kept) | 1 LOW | 1 LOW |
| `kernel_irp_handler_registered` | 0 | 1 HIGH (E2) |
| `kernel_arbitrary_rw_primitive` | 0 | 2 CRITICAL (E1+E3) |
| `tainted_pointer_dereference` | 0 | 29 CRITICAL (E4) |
| Wall time | 10s | 2.1s |

**Where the 29 deref findings land.**

| Function | n | What it represents |
|---|---|---|
| `sub_15294` | 6 | The CVE arbitrary R/W primitive — IOCTLs `0x9b0c1ec4` (write) / `0x9b0c1ec8` (read) |
| `sub_15008` | 6 | MSR R/W handler — IOCTLs `0x9b0c1f80..0x9b0c1f8c` |
| `sub_15100` | 2 | `MmMapIoSpace` handler — IOCTLs `0x9b0c1f40` / `0x9b0c1f44` |
| `sub_11170` | 15 | The dispatcher — IRP field reads + DeviceExtension stores; structurally tainted derefs but most are benign IRP plumbing |

**No regressions.** Per-target taint findings post-E5:

| Target | Findings | Note |
|---|---|---|
| `authencesn.ko` (copy.fail) | **6 critical** | Run 7 baseline preserved |
| `algif_aead.ko` | 0 | Correctly stays clean (sg-chain setup, no write) |
| `utilman.exe` | 0 | Canonical Win control sample |
| `sethc.exe` | 0 | Same |
| `osk.exe` | 0 | Same |

**Cell promotion.** `dbutil_2_3.sys` promoted to known-positive
at `vulntest/known-positive/CVE-2021-21551/`:

- `README.md` — disclosure summary, IOCTL-by-IOCTL primitive
  table, references
- `expected.json` — per-handler finding manifest
- `binary/README.md` — operator-supplied binary path
- `source/README.md` + `poc/README.md` —
  **deliberately empty**, reserved for Phase 2 dogfood per the
  operator's experimental discipline (initial Phase 1+4 build
  done without consulting the public PoC repo)
- `remediation/README.md` — Microsoft blocklist, HVCI guidance,
  architectural lessons
- `verification.json` — Phase 4 plan with a fail-fast setup
  command that documents the lab gap (current
  `argus-lab` is Linux-only; `dbutil_2_3.sys` needs a Windows
  lab for live verification)

**Phase 4 status: scaffold-only.** The verification plan loads
correctly, `triage.py --dry-run` selects all 32 persisted Run 10
findings, and a live run cleanly fails at the setup step with
the documented "lab unsupported" exit code. No findings
transition past DETECTED — the right behaviour given we don't
have the lab to verify against. Captured as a Phase 4 forward-
state item.

**Findings persisted** to `findings/cve-2021-21551.json` for
downstream comparison work (Phase 2 vs Phase 1+4 baseline,
old-skills delta).

**Daydreams (parallel).** A seeded daydream confirmed
LJM-corpus alignment with the implementation:

- `a64_procedures_ms_abi` covers Win64 ABI cleanly (E3 grounded)
- `em_rootkit_irp_minifilter_callbacks` covers the IRP concept
  but lacks concrete `IO_STACK_LOCATION` offsets — implementation
  was driven from disassembly, not corpus
- `tainted_pointer_dereference` (E4) and inlined-memcpy
  recognition (E5) are greenfield additions; no Knowledge
  prior art consulted

A random-walk daydream surfaced a CLS / consolidation-pipeline
gap (replay-during-consolidation missing in LJM) — flagged for
later, not pursued.

### Run 11 — Phase 2 source enrichment slice; legacy delta vs dbutil (2026-05-01)

**Operator-set experimental discipline.** The mathisvickie/CVE-2021-21551
reference repo (Ghidra-decompiled `dbutil_2_3.c` + user-mode exploit
`CVE-2021-21551.c`) was deliberately **not** consulted during Phase
1+4 build-out. Pulled in only after Run 10 was locked, exclusively
to drive Phase 2 + serve as ground truth for the comparison work.

**What landed.** `skills/binary-ninja/scripts/analysis/source_surface.py`:
the Phase 2 minimal slice. Three responsibilities:

1. **Source parsing.** Permissive C-shaped function-and-IOCTL-constant
   extractor. No compiler, no preprocessor, no AST — operates on
   decompiler output directly. Captures top-level function definitions
   (return-type + name + body), kernel-API callee signatures (the set
   of `Mm*`/`Io*`/`Ke*`/etc. names called), and IOCTL constants in
   both `IoControlCode == 0xXXXX` and `DeviceIoControl(handle, 0xXXXX, …)`
   shapes.

2. **Source ↔ binary alignment.** Strict callee-set match: a source
   function aligns to a binary function when their `_looks_like_kernel_api`
   callee sets are identical and at least one such callee exists. The
   binary-side resolver walks MLIL call instructions and resolves
   each callee against the import symbol table — `func.callees` alone
   misses extern-symbol calls (which is the entire kernel-API surface
   in a Windows driver).

3. **IOCTL constant decoding.** Every captured IOCTL is decoded per
   `CTL_CODE`: DeviceType (high 16 bits), Access (bits 14-15), Function
   (bits 2-13), Method (bits 0-1; `METHOD_BUFFERED` / `_NEITHER` /
   etc.). Emitted as a `kernel_ioctl_handler_classified` Finding per
   code.

**Run 11 vs Run 10 (binary-only) on `dbutil_2_3.sys`:**

| | Run 10 | Run 11 |
|---|---|---|
| Total findings | 32 | **51** |
| `kernel_irp_handler_registered` | 1 (HIGH) | 1 (HIGH; named `ioctl`) |
| `kernel_arbitrary_rw_primitive` | 1 (CRIT) | 1 (CRIT; in `ArbitraryPhysMemReadWrite`) |
| `tainted_pointer_dereference` | 29 (CRIT) | 29 (CRIT; same hits, source-named functions in evidence) |
| `kernel_ioctl_handler_classified` | 0 | **14** (one per source IOCTL) |
| `source_function_alignment` | 0 | **4** (`entry`, `ioctl`, `ArbitraryPhysMemReadWrite`, `wrapper_MmAllocateContiguousMemorySpecifyCache`) |
| `phase2_source_summary` | 0 | 1 |
| Wall time | 2.1s | 2.1s |

**Coverage vs ground truth.**

The reverse-engineered `dbutil_2_3.c` documents 15 distinct IOCTL
codes and 5 driver-side functions. Argus caught:

- **14 of 15 IOCTL codes** (the missing one was a `IoControlCode != 0xXXXX`
  comparison, which my regex initially didn't match — fixed)
- **4 of 5 driver-side functions** — `entry` / `ioctl` /
  `ArbitraryPhysMemReadWrite` / `wrapper_MmAllocateContiguousMemorySpecifyCache`
  all aligned cleanly
- The missed function `ArbitraryKrnlMemReadWrite` (= `sub_15294`, the
  canonical CVE arbitrary-R/W primitive) has zero kernel-API callees —
  it uses the inlined `CopyMemoryBlock` (memcpy). Acceptable for the
  slice; future enhancement: structural alignment via call-graph
  topology (the function called from already-aligned `ioctl` at the
  position the source's `ioctl` calls `ArbitraryKrnlMemReadWrite`
  would match unambiguously).

**Coverage vs the public exploit's primitives.**

The public exploit chains:
`GetKernelBase` → `ReadKernelMemory(PsInitialSystemProcess)` →
`ReadKernelMemory(SystemEPROCESS+0x348)` for system token →
loop `ActiveProcessLinks` → `WriteKernelMemory(self+EPROCESS_Token, SystemToken)` →
`system("cmd")`.

The two IOCTL primitives the exploit relies on are `0x9b0c1ec4`
(READ) and `0x9b0c1ec8` (WRITE). Both dispatch to the same handler
(`ArbitraryKrnlMemReadWrite` / `sub_15294`), where Argus emitted **6
critical `tainted_pointer_dereference` findings** in both Run 10 and
Run 11 — covering the read and write paths of the bug primitive
that's the exploit's load-bearing dependency.

**Legacy-skill delta — quantified.**

Run `dev/legacy_validate.py vulntest/known-positive/CVE-2021-21551/binary/dbutil_2_3.sys`:

| Skill | Findings | Notes |
|---|---|---|
| Pre-Argus `security_audit.py` | 0 | Clean miss |
| Pre-Argus `deep_analysis.py` | 0 | Clean miss |
| Pre-Argus `heap_analysis.py` | 0 | Clean miss |
| **Legacy total** | **0** |  |
| Argus Run 9 (Phase 1 baseline) | 1 (LOW) | Surface heuristic only — kernel-driver shape recognition |
| Argus Run 10 (Phase 1++ E1-E5) | 32 (30 CRIT) | All vulnerable handlers + IRP dispatch wiring |
| Argus Run 11 (Phase 1+2 enriched) | 51 (30 CRIT + named) | + 14 IOCTL classifications + source-named functions |

**Ground-truth correction.** While reading the source, found a Run 9/10
README error: I'd written `0x9b0c1ec4=write, 0x9b0c1ec8=read`. The
source's `oneRead_zeroWrite` parameter (and the user-mode exploit's
`ReadKernelMemory`/`WriteKernelMemory` IOCTL choices) confirms the
opposite — `0x9b0c1ec4` is READ, `0x9b0c1ec8` is WRITE. Cell README
fixed. This is the kind of error source-aware analysis catches that
binary-only inspection doesn't — the binary's `oneRead_zeroWrite`
parameter name was lost in stripping.

**Phase 2 future-state, captured.**

- **Cross-function structural alignment** — match `ArbitraryKrnlMemReadWrite`
  by call-graph topology (called from already-matched `ioctl`)
- **DWARF / PDB consumption** when debug symbols are present
- **Source-level taint analysis** as an independent detection pass
  (currently we only enrich binary taint output)
- **libclang / tree-sitter** for cleaner source parsing when the source
  is upstream-quality (the regex slice is permissive enough for
  decompiled output but loses precision on heavily-templated C++)
- **Cross-cell pattern library** — when one cell teaches the system
  about a sink class, future cells inherit that knowledge

**Files added / changed for Phase 2:**
- `skills/binary-ninja/scripts/analysis/source_surface.py` (new)
- `skills/binary-ninja/scripts/analysis/__init__.py` (export)
- `dev/validate.py` (Phase 2 hooked into pipeline, runs after surface
  before taint so renames are visible to evidence)
- `vulntest/known-positive/CVE-2021-21551/source/_repo/` (cloned
  reference — gitignored, fetched by operator)
- `findings/cve-2021-21551.run11.json` (51 persisted findings)

### Run 12 — BYOVD multi-driver generalisation sweep (2026-05-01)

**Test set.** 13 Windows kernel drivers from the BlackSnufkin BYOVD
repo (`D:\Repos\Security\Known Vulnerable\BYOVD\BYOVD`) plus the
existing `dbutil_2_3.sys` baseline. The repo's per-driver Rust killer
sources document the vulnerable IOCTL codes + buffer formats — used
as Phase 2 grey-box ground truth.

**Operator intent: prove generalisation, not point performance.** The
E1-E5 enhancements were tuned around dbutil's arbitrary-R/W primitive
class. The BYOVD repo is dominantly the *process-killer* primitive
class (12 of 13 drivers terminate processes via tainted PID +
`ZwOpenProcess` + `ZwTerminateProcess`), structurally distinct from
dbutil's pointer-arithmetic class. Detection has to fire on both
without per-driver tuning.

**Two enhancements landed first (E6 + E7):**

- **E6 — Windows process-handle / process-control sinks.** Added to
  `heuristics/imports.py:SINKS`: `Zw/NtOpenProcess` (CLIENT_ID at arg 3),
  `Zw/NtTerminateProcess`, `Zw/NtCreateFile` + `Zw/NtWriteFile`,
  `Zw/NtSetValueKey`, `PsLookupProcessByProcessId`. Six new
  `SINK_CLASS_META` entries (`kernel_arbitrary_process_handle`,
  `kernel_arbitrary_process_terminate`, `kernel_arbitrary_file_open`,
  `kernel_arbitrary_file_write`, `kernel_arbitrary_registry_write`).
  Provenance-based: position-aware sink check fires only when the
  PID / handle / path traces back to the user IRP — `ZwTerminateProcess`
  alone is a legitimate kernel API.
- **E7 — primitive-class fingerprint heuristic** at
  `heuristics/byovd_primitives.py`. Co-presence import filter: a
  driver fires "process_killer" class when it imports both a
  process-handle-acquiring API AND `Zw/NtTerminateProcess`. Six
  classes encoded (process_killer, arbitrary_kernel_rw,
  arbitrary_msr, arbitrary_file_write, arbitrary_registry_write,
  kernel_module_load). Direct adaptation of the BYOVD repo's
  "Step 0 — Function Import Screening" methodology, generalised
  across primitive classes. Severity MEDIUM/HIGH per-class —
  triage signal, not a vulnerability assertion.

**Sweep result (Phase 1 — black box):**

| Driver | Findings | Primitive class fingerprint |
|---|---|---|
| `dbutil_2_3.sys` (CVE-2021-21551) | 33 | arbitrary_kernel_rw |
| `BdApiUtil64.sys` (CVE-2024-51324) | 79 | process_killer + arbitrary_registry_write |
| `CcProtect.sys` | 17 | process_killer + arbitrary_file_write + arbitrary_registry_write |
| `GameDriverX64.sys` (CVE-2025-61155) | 45 | process_killer + arbitrary_file_write |
| `GoFly64.sys` | 12 | process_killer + arbitrary_file_write |
| `K7RKScan_2310.sys` (CVE-2025-52915) | 52 | process_killer |
| `ksapi64.sys` | 314 | process_killer + arbitrary_registry_write |
| `NSecKrnl.sys` | 12 | process_killer |
| `PoisonX.sys` | 8 | process_killer |
| `STProcessMonitor_v2618.sys` (CVE-2025-70795) | 39 | process_killer + arbitrary_file_write |
| `SysMon.sys` (TfSysMon) | 47 | process_killer + arbitrary_registry_write |
| `Viragt64.sys` | 5 | process_killer + arbitrary_file_write + arbitrary_registry_write |
| `wsftprm.sys` (CVE-2023-52271) | 53 | process_killer + arbitrary_registry_write |

**E2 (IRP dispatch extraction)** fired on 11 of 13 drivers. The two
misses (CcProtect, Viragt64) didn't expose a `MajorFunction[]` write
the extractor recognises — likely indirect dispatch or compiler-emitted
table writes outside DriverEntry's tail-callee chain. Captured as a
known-shape gap; future enhancement: also walk INIT-section
initializers and exported-function-table writes.

**E7 (primitive-class fingerprint)** fired on **all 13** drivers
with the correct primitive class. No tuning per driver.

**E4 (tainted-pointer-dereference) + E6 (process-handle sinks)**
combined: **6 of 13 drivers** had `kernel_arbitrary_process_handle`
findings (taint flowed from IRP into `ZwOpenProcess` CLIENT_ID arg 3).
The other 7 process-killers terminated processes via different paths
(some via `PsLookupProcessByProcessId` + `ObReferenceObjectByPointer`;
some via in-kernel-state-machine dispatch the simple seed didn't
follow). All 13 still got E7 fingerprints; the E4 hits are the *taint
provenance proof*, complementary to the E7 import-co-presence signal.

**Legacy-skill sweep (same set):**

| | Findings |
|---|---|
| `security_audit.py` total | 29 across 13 drivers (only 2 drivers got hits) |
| `deep_analysis.py` total | 0 |
| `heap_analysis.py` total | 0 |
| **Legacy aggregate** | **29** across 13 drivers, 11 of which got 0 findings |

**Argus aggregate**: **756 findings** across 13 drivers, **0 of which got 0 findings**.

Per-driver delta:

| Driver | Legacy | Argus | Δ |
|---|---|---|---|
| `dbutil_2_3` | 0 | 33 | +33 |
| `BdApiUtil64` | 0 | 79 | +79 |
| `CcProtect` | 14 | 17 | +3 |
| `GameDriverX64` | 0 | 45 | +45 |
| `GoFly64` | 0 | 12 | +12 |
| `K7RKScan` | 0 | 52 | +52 |
| `ksapi64` | 0 | 314 | +314 |
| `NSecKrnl` | 0 | 12 | +12 |
| `PoisonX` | 0 | 8 | +8 |
| `STProcessMonitor` | 0 | 39 | +39 |
| `SysMon (TfSysMon)` | 0 | 47 | +47 |
| `Viragt64` | 15 | 5 | -10 ← regression candidate; legacy hits are likely string-pattern FPs |
| `wsftprm` | 0 | 53 | +53 |

The Viragt64 case is worth investigating. Legacy's 15 are likely
import-string matches (this driver imports many Zw/Nt APIs); Argus's
5 are post-combo-gating + Phase-1++-suppression. Whether legacy's 10
extra are FPs or real signal we lost is open — flagged as future-
state.

**Phase 2 grey-box.** Killer-side Rust source documents the canonical
exploit IOCTL per driver. Captured as ground truth at
`findings/byovd_killer_source_groundtruth.json` for 11 of 12 PoCs
(K7Terminator's source doesn't follow the `DriverConfig` trait, and
the Ksapi64 entry uses decimal IOCTL constant which the slice's
hex-only regex didn't match — both are minor source-parser
enhancements queued).

The grey-box use-case differs from CVE-2021-21551's: there, the
reversed *driver* source was available. For these BYOVD drivers we
have the *killer-side* source, which documents IOCTL codes / device
paths / buffer offsets but doesn't contain driver functions to align
against. Phase 2's value here is **ground-truth confirmation** rather
than binary-view enrichment. All 13 drivers' E7 process_killer
fingerprint matches the killer source's intent.

**Enhancement opportunities surfaced (future-state):**

1. **E2 robustness — beyond DriverEntry tail-callees.** CcProtect +
   Viragt64 don't expose `MajorFunction[]` writes the current
   extractor catches. Need to also walk INIT-section initializers,
   exported function tables, and other indirect-dispatch sites.
2. **IOCTL switch enumeration from binary.** Currently we only
   classify IOCTL codes when source provides them. Adding a binary-
   side analyser that walks the IOCTL dispatcher's switch statement
   to enumerate cases would close the source-required gap.
3. **Decimal IOCTL constant parsing in source_surface.** Trivial
   regex extension.
4. **K7-style standalone-PoC source parsing.** Different shape;
   minor enhancement.
5. **Process-handle taint chain modelling.** When `ZwOpenProcess`
   succeeds with a tainted CLIENT_ID, the OUT handle is itself
   tainted; tainted handle → `ZwTerminateProcess` should fire as
   `kernel_arbitrary_process_terminate`. Currently caught
   structurally via `kernel_arbitrary_process_handle` but the
   second-order chain is a tighter primitive signature.
6. **TTP-altitude-vs-indicator-altitude documentation.** Per the
   daydream's note: E1-E5/E6/E7 are pitched at TTP altitude (kernel
   sinks, taint flow, primitive classes) NOT indicator altitude
   (specific IOCTL codes, named driver signatures). That's the
   right call per `detection_pressure_escalation_terminus` but
   should be made explicit in architecture notes.

**Persistence.** Run 12 sweep results at
`findings/byovd_sweep_phase1.json`. Killer-source ground truth at
`findings/byovd_killer_source_groundtruth.json`.

### Run 13 — Viragt64 regression analysis + E2 memfill-dispatch enhancement (2026-05-01)

Investigation of the Run 12 outlier: Viragt64 went legacy 15 → Argus 5,
operator asked whether this was a regression or correct FP suppression.

**Verdict: both, in different parts.** Two distinct findings:

#### Part 1 — Legacy's 15 are 100% false positives

Pulled the actual finding bodies from `security_audit.py`. All 15
findings on Viragt64 are *the same* finding repeated: "Call to sprintf()"
flagged at 15 different call sites, all HIGH severity in the
`format_string` category.

Inspected each call site. Every one passes a constant `.rdata` format
string:

```
0x16d67  sprintf(_, "%d/%d/%d - %d:%d:%d", ...)               -- date formatting
0x1ad73  sprintf(_, "%s -> DriverStartIo = %I64x", ...)         -- debug log of detected hook
0x1af90  sprintf(_, "%s -> MajorFunction[%s] = %I64x", ...)     -- debug log
... (12 more, all const format strings, all debug logging)
```

Viragt64 is an antifraud rootkit-detection driver from Tg Soft — the
sprintf calls construct **debug log messages** about hook locations
the driver detected. The format strings are hardcoded literals from
.rdata; no user input reaches arg 1 (the format slot) of any of these
sprintf calls. **No format-string vulnerability is possible** —
CWE-134 requires attacker-controlled format. Legacy fires on every
sprintf call site without checking taint flow, classic name-presence
detector.

Argus correctly emits **1 LOW `banned_function` finding** ("this
binary uses sprintf — informational signal") rather than 15 HIGH
findings inflating per-driver risk score. The 14-finding gap is
correct FP suppression, not regression. Verdict
methodology: per-finding triage criterion from
[[Buffer/2026-05-01_argus-validation-chronicle-run-n-pattern]] —
each missing finding categorised as (a) import-only / no-flow FP,
(b) detection class Argus lacks, or (c) genuine missed taint path.
All 14 fall into category (a).

#### Part 2 — E2 had a real coverage gap, fixed (and CcProtect benefits)

Investigating Viragt64 revealed that `windows_drivers.extract_dispatch_table`
returned **zero IOCTL handlers** despite the killer-side source
documenting `\\.\viragtlt` + IOCTL `0x82730030`. Same gap on
CcProtect.

Cause: Viragt64 + CcProtect register dispatch differently from
dbutil/TfSysMon. They use a **bulk memory-fill intrinsic** to
populate all 28 `MajorFunction[]` slots with the same handler in
one MLIL operation:

```
arg1->DriverUnload = sub_14154
__memfill_u64(&arg1->MajorFunction, sub_14130, 0x1c)
arg1->DriverExtension->AddDevice = nullptr
arg1->FastIoDispatch = nullptr
```

Binja represents this as `MediumLevelILIntrinsic` with operands
`(target_addr, handler_const, count_const)`. My E2 extractor only
looked at per-slot stores (`arg1->MajorFunction[N] = handler`), so
the bulk-fill idiom was invisible.

This is a **driver-shape generalisation gap**, not a Viragt64-
specific tuning issue. The `__memfill_u64` / `rep stosq`
compiler idiom is the canonical pattern when ALL IRP_MJ slots
route to one handler — common in process-killer drivers where
the dispatch handler is the only one that does anything. CcProtect
exhibits the same shape from a different vendor (CnCrypt) — the
same enhancement unblocks both.

**Fix.** Extended `_scan_function_for_dispatch_writes` to recognise
three idioms:

1. Per-slot `MediumLevelILStoreStruct` (typed shape — dbutil)
2. Per-slot raw `MediumLevelILStore` (untyped fallback)
3. **`__memfill_u64` / `__rep_stosq` / `__stosq` intrinsic** — bulk
   fill of `MajorFunction[]`. Confidence rules: handler must be a
   `.text` constant, count must be in `[1, 28]`. When the offset
   traces cleanly to `+0x70` (DRIVER_OBJECT.MajorFunction start)
   we use it; when offset tracing fails (compilers emit
   `<rebased_pointer> - <const>` shapes — Viragt64 uses
   `rdi_1 - 0xe0` where `rdi_1 = arg1 + 0x150`), we fall back to
   "if count == 28, this is a full dispatch table fill". The
   28-slot constant is the discriminator; no other kernel struct
   has 28 PVOID entries that compilers fill via rep-stosq.

**Re-sweep result (Run 13 vs Run 12):**

| Driver | Run 12 | Run 13 | Δ | IRP handlers (Run 13) |
|---|---|---|---|---|
| dbutil_2_3 | 33 | 33 | +0 | 1 |
| BdApiUtil64 | 79 | 79 | +0 | 3 |
| **CcProtect** | **17** | **57** | **+40** | 1 ← was 0 in Run 12 |
| GameDriverX64 | 45 | 45 | +0 | 4 |
| GoFly64 | 12 | 12 | +0 | 7 |
| K7RKScan | 52 | 52 | +0 | 2 |
| ksapi64 | 314 | 314 | +0 | 1 |
| NSecKrnl | 12 | 12 | +0 | 2 |
| PoisonX | 8 | 8 | +0 | 1 |
| STProcessMonitor | 39 | 39 | +0 | 2 |
| TfSysMon | 47 | 48 | +1 | 1 |
| **Viragt64** | **5** | **47** | **+42** | 1 ← was 0 in Run 12 |
| Wsftprm | 53 | 53 | +0 | 4 |

**Two driver shapes unblocked, zero regressions** across the other
11 drivers + the dbutil baseline + the authencesn.ko Linux baseline
(separately verified). The added enhancement is in the
`MediumLevelILIntrinsic` branch only — completely orthogonal to
the per-slot-store paths that handle the dispatch shapes that
already worked.

**Latent issue surfaced** during this work: the taint analyzer is
**non-deterministic** at the margin. Re-running authencesn.ko
produces 6 critical findings most of the time, occasionally 4 or 5.
The two unstable findings (`0x400790` / `0x4007c4` in
`crypto_authenc_esn_decrypt_tail`) are sometimes missed.

Cause: the `(function, ssa_var)` visited-set is global across all
seeds; seed-iteration order (driven by Python set/dict hash
randomisation + `bv.functions` iteration order) changes which paths
get explored first, and seeds visited later get pre-empted by
earlier ones at shared SSA vars.

This nondeterminism is not introduced by Run 13's E2 changes —
Run 7 and Run 10 likely had it too, just masked by smaller code
volume. Captured as a Phase-1++ enhancement: deterministic seed
ordering + per-seed visited tracking with merge at end.

**Files changed:**
- `skills/binary-ninja/scripts/analysis/windows_drivers.py`
  (`_scan_function_for_dispatch_writes` + new
  `_extract_dispatch_from_memfill`)
- LJM buffer entry filed for the lessons (verdict methodology, the
  three-idiom dispatch detection, the determinism gap)

### Pending follow-up tests

Each item is a future row in this table. Re-runnable via the dev
harnesses above.

- [ ] **Expanded Windows control set** — `cmd.exe`, `notepad.exe`,
  `calc.exe`, `mspaint.exe`, larger system utilities (`explorer.exe`,
  `taskmgr.exe`).
- [ ] **Linux ELF control set** — common GNU userland on legion / strx
  (`bash`, `coreutils`, `openssl`).
- [ ] **VulnTest corpus runs** (Phase 1.11 quality gate) — every
  Tier-1 cell built and executed against the pipeline; required
  100% TP / 0 FP on C+C++ baseline before any module promotes.
- [ ] **Real-world vulnerable target** — one of the operator's
  research samples (private; not committed) to validate detection
  on a genuinely vulnerable binary.
- [ ] **Crypto / obfuscation / chains modules** — re-run all
  comparisons after these analysis modules land; expect new
  signals on weak-PRNG, packed, and chained samples.
- [ ] **Phase 1 → `~/.claude/` promotion gate run** — full
  LIFECYCLE.md six-gate verification before promoting any module.
- [ ] **Controlled malware sample** (operator's lab) — verify
  detection on direct-syscall stub, TLS callback first-stage,
  hidden-from-debugger thread, API-hash resolution.
- [ ] **Cross-arch target** — AArch64 binary, MIPS / RISC-V if
  available; verify `heuristics/syscalls.py` cross-arch SVC / ECALL
  patterns fire correctly.

### Methodology notes

The validation harnesses do not include the binary outputs in this
repo — they invoke Binary Ninja against system / external binaries
the operator has authorised access to. Re-running them on different
hardware will produce different timing numbers; the *findings
counts* are the load-bearing signal.

When new analysis modules land, expand the control set first, then
re-run the comparison: a row added to a richer module set against a
larger control set is the most informative baseline.
