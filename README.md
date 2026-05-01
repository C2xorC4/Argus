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
| 0 | Architecture + shared infrastructure | **In progress** (this commit lays the skeleton) |
| 1 | Identification stage rebase (heuristics + analysis modules + malware-analyzer + vuln-class-analyzer + manual-workflow docs) | Planned |
| 2 | Source-guided / grey-box pipeline | Planned |
| 3 | Exploitation stage | Planned |
| 4 | Verification stage | Planned |
| 5 | Differ + patcher rebases | Planned |
| 6 | Synthesis + reporting | Planned |
