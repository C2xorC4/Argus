---
name: argus-binary-ninja
description: Binary Ninja headless analysis pipeline — surface scan, taint, heap, crypto, mitigation, obfuscation, chain detection. Knowledge-driven (LJM heuristics modules); outputs the Argus Finding v2 schema. Phase 0 ships package skeleton + Finding schema + lib + output renderers.
---

# Argus Binary-Ninja Skill

## Status

- **Phase 0** — package skeleton, Finding v2 schema, shared library
  (`lib/binja.py`, `lib/knowledge.py`, `lib/state.py`), SARIF +
  markdown renderers, manual-workflow companion scaffolding.
- **Phase 1** (planned) — populates `analysis/` modules and
  `heuristics/` pattern tables; wires the malware-analyzer and
  vuln-class-analyzer agents to consume the skill.
- **Phases 3–5** — exploit/, verify/, differ/, patch/ packages.

## Layout

```
skills/binary-ninja/
├── SKILL.md                 ← this file
├── TESTING.md               ← LIFECYCLE.md gate results
├── MANUAL_WORKFLOWS.md      ← index of per-module Binja-UI companion docs
├── docs/
│   └── binja-cookbook-reference.md  ← Binja Python API build-time reference
├── scripts/
│   ├── analysis/            ← static analysis modules (Phase 1)
│   ├── heuristics/          ← Knowledge-derived pattern tables (Phase 1)
│   ├── exploit/             ← primitive construction (Phase 3)
│   ├── verify/              ← dynamic verification (Phase 4)
│   ├── differ/              ← binary diff (Phase 5)
│   ├── patch/               ← binary patch (Phase 5)
│   ├── output/
│   │   ├── finding.py       ← unified Finding v2 schema
│   │   ├── sarif.py         ← SARIF 2.1.0 renderer
│   │   └── markdown.py      ← markdown renderer
│   ├── lib/
│   │   ├── binja.py         ← Binary Ninja headless wrapper
│   │   ├── knowledge.py     ← jm CLI integration (Knowledge retrieval)
│   │   ├── state.py         ← FindingState machine
│   │   └── jm-helper.sh     ← bash equivalent for agent quick-reference
│   └── legacy/              ← reference copies of pre-Argus scripts
└── manual_workflows/
    ├── _template.md         ← per-module companion-doc template
    └── analysis-*.md        ← populated in Phase 1
```

## Invocation

The skill is consumed by **agents**, not directly by the operator.
Each agent (`vuln-class-analyzer`, `malware-analyzer`,
`binary-research-orchestrator`, etc.) imports the appropriate
skill modules and emits Findings.

For ad-hoc operator use, the package can be run from the skill root:

```bash
cd skills/binary-ninja
python -m scripts.analysis.surface --binary path/to/target
```

(Modules under `analysis/` are stubbed in Phase 0; this works once
Phase 1 lands.)

## Output schema

All modules emit `scripts.output.Finding` objects. See
[`scripts/output/finding.py`](scripts/output/finding.py) for the
canonical schema. Every Finding carries:

- **Identity:** stable hash `id`, `category`, `severity`.
- **Localisation:** `address`, `function`, `binary`, `arch`, `platform`.
- **Provenance:** `detector` (module name), `knowledge_refs` (LJM
  citations), `cwe`, `mitre_attack`.
- **State:** `state` ∈ `{detected, confirmed, impact_pending,
  impact_verified, dismissed}`, `state_history` (audit trail).
- **Mitigation context:** `target_mitigations` profile,
  `mitigation_weighted_exploitability` ∈ [0.0, 1.0].
- **Evidence:** `evidence[]`, free-form `description` and `details`.
- **Reporting:** `disclosure_altitude` ∈ `{capability, observation,
  result, instance}`, `vendor_program`, `bounty_category`.

External output (SARIF, vendor report) is gated to **PROVEN**
(== `IMPACT_VERIFIED`) findings whose `disclosure_altitude` permits
publication. See `Finding.is_externally_reportable`.

## Renderers

```python
from scripts.output import sarif, markdown

# SARIF 2.1.0 (CI/CD ingestion)
sarif_doc = sarif.render(findings)         # dict
sarif_str = sarif.render_json(findings)    # JSON string

# Markdown (human-readable triage / internal review)
md = markdown.render(findings, title="Recon — sample.exe")
```

## Knowledge integration

```python
from scripts.lib import retrieve, associate, verify_finding_citations

# Pre-flight: pull domain-relevant Knowledge entries
entries = retrieve(
    intent="binary vulnerability identification",
    tags=["taint", "heap", "injection"],
    limit=10,
)
for e in entries:
    print(e.title, "->", e.knowledge_ref)

# Substrate-coherence check: confirm a Finding's cited Knowledge
# entries actually match its category + description
ok, top = verify_finding_citations(
    category=f.category,
    description=f.description,
    cited_refs=f.knowledge_refs,
)
```

Bash equivalent at [`scripts/lib/jm-helper.sh`](scripts/lib/jm-helper.sh)
for agent quick-reference blocks:

```bash
source scripts/lib/jm-helper.sh
argus_kb_retrieve "binary vulnerability identification" "taint,heap,injection" /tmp/kb.json
```

## State machine

```python
from scripts.lib import FindingState, transition, IllegalTransition

# DETECTED -> CONFIRMED (via triage)
new_state, record = transition(
    f.state, FindingState.CONFIRMED,
    actor="triage-analyst",
    notes="reachable via test harness",
)
f.state = new_state
f.state_history.append(record)

# Illegal transitions raise; useful as a guard rail
try:
    transition(f.state, FindingState.DETECTED, actor="x")
except IllegalTransition as e:
    ...
```

## Quality gates

Per [`LIFECYCLE.md`](../../../Research/Agents/LIFECYCLE.md), the skill
must pass six gates before promotion to `~/.claude/`. See
[`TESTING.md`](TESTING.md) for current gate status.

## Manual workflows

Every analysis module ships a companion document at
[`manual_workflows/<module-name>.md`](manual_workflows/) that maps
the programmatic flow to an equivalent human Binary-Ninja-UI
sequence. See [`MANUAL_WORKFLOWS.md`](MANUAL_WORKFLOWS.md) for the
index.

## Binary Ninja API reference

Build-time reference for Binja Python API patterns lives at
[`docs/binja-cookbook-reference.md`](docs/binja-cookbook-reference.md).
It mirrors the upstream cookbook
(<https://docs.binary.ninja/dev/cookbook.html>), keyed to Argus's
modules — when an analysis or heuristics module needs to recall a
particular API (SSA def-use, cross-refs, byte search, etc.), check
the local reference first.

Re-fetch + diff the upstream at minor-version bumps of Binary Ninja
to catch API drift.

## Runtime configuration

Per-host paths (Binja install, jm.exe, toolchains, output dirs,
budgets) live in [`../../config/`](../../config/). Defaults in
`argus.toml`; per-host overrides in `argus.local.toml` (gitignored;
copy from `argus.local.toml.example`). Environment variables
override both. See `config/README.md` for the resolution chain.

The `BinjaSession` constructor and `knowledge.retrieve` /
`associate` consult the config automatically — no need to pass
paths explicitly in normal use.

## Dependencies

- Binary Ninja (commercial license; headless API). Default Python
  module path: `/opt/binaryninja/python`. Override via
  `binja_python_path` argument to `BinjaSession()`.
- Python 3.11+ (uses `from __future__ import annotations`,
  PEP 604 union syntax).
- `jm.exe` from LJM — for Knowledge integration. Override path via
  `ARGUS_JM_PATH` env var.
- Phase 4+ adds: AFL++, libFuzzer, GDB / WinDbg / LLDB, sanitizers
  (compiler-bundled), TLSH / ssdeep (similarity hashing).
