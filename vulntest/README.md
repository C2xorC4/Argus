# Argus VulnTest Corpus

Multi-tier quality-gate substrate for the Argus
toolchain.

## Purpose

The corpus serves two audiences simultaneously:

1. **The toolchain** — supplies the test programs that drive the
   LIFECYCLE.md quality gates (100% TP detection, 0 FPs, PoC
   validation, schema conformance).
2. **The operator** — provides a practice ground for manual
   exploitation refinement. Every cell ships a challenge brief; an
   operator can solve it by hand, then run the toolchain against
   the same target and compare.

Divergences feed back into:
- `skills/binary-ninja/heuristics/` (when the toolchain misses
  something the operator caught)
- `skills/binary-ninja/manual_workflows/` (when the operator's
  approach captures methodology the docs should encode)

## Tiers

| Tier | Directory | Purpose | Phase |
|---|---|---|---|
| 1 | [`tier1-single/`](tier1-single/) | Isolated single-vuln variants per language. Cross-product of vulnerability class × compiled language. | Phase 0 (C/C++ baseline) → Phase 1 (full matrix) |
| 2 | [`tier2-chains/`](tier2-chains/) | Commonly-chained vulnerabilities. Chain composition + per-primitive isolation. | Phase 1 (EAC + UE5 skeletons) → Phase 1+ (full catalogue) |
| 3 | [`tier3-obfuscated/`](tier3-obfuscated/) | Tier-1/Tier-2 programs re-emitted with obfuscation layers. Tests detection / construction / manual reproduction under obfuscation. | Phase 0 (one demo) → Phase 1+ (full coverage) |

## Layout

```
vulntest/
├── INDEX.md                       ← challenge index by class/language/tier/difficulty
├── _templates/
│   └── cell_README.md             ← per-cell brief template
├── tier1-single/
│   ├── README.md
│   └── <class>/<language>/        ← per-cell directory
│       ├── source/
│       ├── Makefile               ← build targets per arch where relevant
│       ├── expected.json          ← finding manifest
│       ├── poc/                   ← trigger script
│       ├── README.md              ← challenge brief (see template)
│       └── remediation/           ← idiomatic fix(es)
├── tier2-chains/
│   ├── README.md
│   └── <chain-name>/<language>/
│       ├── source/                ← all primitives composed
│       ├── components/            ← per-primitive isolation (cross-link to Tier 1)
│       ├── Makefile
│       ├── expected.json          ← findings per primitive + chain
│       ├── poc/                   ← full-chain + per-primitive sub-PoCs
│       ├── README.md
│       └── remediation/           ← one fix per link
└── tier3-obfuscated/
    ├── README.md
    └── <obfuscation>-<source-cell>/
        └── (derived from Tier 1 / Tier 2 source via build-script
             transforms; the underlying program is identical, only
             obfuscation differs)
```

## Languages (Tier 1)

| Language | Phase 0 commitment |
|---|---|
| C | Full Tier-1 coverage for every Phase 1 detection category |
| C++ | Full Tier-1 coverage (vtable / RTTI / exception variants prioritised) |
| C# (.NET) | Variants for stack-OF, heap-UAF, type-confusion, deserialisation |
| Rust | Same four classes, `unsafe`-block-bounded |
| Go | Same four classes; CGO-boundary variants where applicable |
| Swift | Phase 1+ |
| Objective-C | Phase 1+ |
| Java / Kotlin (JVM) | Phase 1+ |
| Pascal / Delphi | Phase 1+ |
| D, Zig, Nim | Optional second-tier (only when assembly differs qualitatively from C/Rust) |
| Fortran, Ada | Deferred — opt in by operator priority |

## Vulnerability classes (Tier 1)

See [`INDEX.md`](INDEX.md) for the canonical class list with
Knowledge anchors. Phase 1 detection categories take priority for
Phase 0 build-out:

- Stack buffer overflow
- Heap buffer overflow
- Use-after-free
- Double-free
- Format-string
- Integer overflow leading to allocation
- Off-by-one bounds check (`>` vs `>=`)
- Type confusion
- TOCTOU / race
- Uninitialised memory disclosure
- PRNG-in-security-path
- Permissive ACL / SDDL on named IPC
- NULL-DACL / world-writable IPC
- Pre-verification write with no cleanup
- Direct-syscall stub
- TLS-callback first-stage
- SEH/VEH handler abuse
- Hidden-from-debugger thread
- PEB anti-debug field check
- API hash resolution (NTDLL bypass)
- LCG / XOR string-cipher obfuscation
- Minifilter-callback unload pattern
- APC / atom-bombing injection variant

## Cell brief template

Every cell ships a `README.md` derived from
[`_templates/cell_README.md`](_templates/cell_README.md). The
template covers: build, detection (programmatic + manual UI),
exploitation walkthrough, chain potential, remediation,
operator-validation checklist.

## Cross-link contract

The per-cell READMEs are **the source of truth** for finding-
specific documentation in two later phases:

- **Phase 1.10 — manual-workflow companion docs.** `MANUAL_WORKFLOWS.md`
  pulls the detection / manual-UI sections of relevant Tier-1 cells
  into per-detector-module companion docs.
- **Phase 6 — report-writer.** Vendor reports use the per-cell
  exploitation / chain / remediation sections as their template.
  The Tier-1 README's exploitation walkthrough becomes the
  H1 / MSRC / Bugcrowd writeup skeleton; the remediation section
  becomes "Recommended Fix."

This means Tier-1 / Tier-2 README authoring is upstream of
documentation in the rest of the toolchain — not duplicate work.

## Phase 0 status

- [x] Directory structure created
- [x] Per-cell README template created
- [x] `INDEX.md` populated
- [x] C / C++ Tier-1 cells (Phase 0 deliverable)
- [x] C# / Rust / Go variants for the four headline classes
- [x] Tier-2 EAC + UE5 chain skeletons
- [x] Tier-3 symbol-stripping demo

Phase 1 builds the remaining Tier-2 chains, expands Tier-3
obfuscation layers, and runs the LIFECYCLE.md quality gates against
the corpus to measure detector TP/FP rates.
