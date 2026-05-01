# Tier 3 — Obfuscated variants

Take Tier 1 / Tier 2 programs and re-emit them with **obfuscation
layers** on top. Tests whether the toolchain's detection still
fires, primitive construction still succeeds, and manual
reproduction stays tractable when the vulnerability location is
buried in noise.

## Obfuscation layers

| Layer | What it adds |
|---|---|
| Symbol stripping | strip debug info; force detection to work on imports + cross-refs only |
| Name decoration | random-name fuzzing; force structural matching |
| Control-flow flattening | dispatcher-loop transformation per `[[Memory/Knowledge/gb_obfuscated_code_analysis]]` |
| Opaque predicates | always-true / always-false branches that look conditional |
| Dummy-code injection | unrelated arithmetic / loops between source and sink |
| String encryption | LCG-XOR per `[[Memory/Knowledge/gameguard_research_22_findings]]`; runtime-decoded |
| Inlining noise | aggressive inlining + dead-code injection to break function-boundary heuristics |
| Compiler-driven obfuscation | Straylight (the operator's LLVM pass framework — `[[Memory/Project/straylight]]`) |

## Layout per cell

```
<obfuscation>-<source-cell>/
├── from: <relative path to Tier-1 / Tier-2 source cell>
├── transform.sh        ← script that produces this variant from source
├── build/
├── expected.json       ← inherits from source cell + obfuscation-specific entries
└── README.md           ← describes the obfuscation, expected behaviour, divergences from source
```

Tier 3 cells are derived from Tier 1 / Tier 2 source via build-
script transformations rather than hand-rewritten — keeps the
underlying program identical, only obfuscation differs.

## Expected behaviour

- **Detection:** programmatic detector still finds the bug. If
  detection drops below 100% TP under a given obfuscation layer,
  the heuristics module is augmented OR the obfuscation is flagged
  as a known limitation in `TESTING.md`.
- **Manual workflow:** Binja UI reproduction still feasible. The
  per-source-cell manual-workflow doc gains an "obfuscated-target
  appendix" describing the additional UI steps.
- **Exploit construction (Phase 3):** `scripts/exploit/` still
  emits a working PoC. Gaps inform Phase 3 mitigation-bypass
  design.

## Phase 0 status

Empty. Phase 0 builds **one demonstration variant** — symbol
stripping applied to one Tier-1 C cell — to prove the layout and
build-script approach. Phase 1 builds out the rest as detector
modules mature and reveal which obfuscation patterns most need
test coverage.
