# Verify — Phase 4 dynamic verification

Argus's Phase-4 stage transitions Findings from **DETECTED**
(static evidence only) to **CONFIRMED** (PoC ran cleanly) and
**IMPACT_VERIFIED** (the bug primitive demonstrably fired).

## Implemented (minimal slice)

| Module | What it does |
|---|---|
| `sanitizer.py` | SSH-driven primitive (Linux): runs plan-declared setup commands, captures probe-file pre-snapshots, drains dmesg, runs the trigger, captures post-snapshots and dmesg deltas, runs teardown commands, rolls up a CONFIRMED / IMPACT_VERIFIED verdict. |
| `local.py` | Local-subprocess variant of sanitizer.py: same plan schema and VerificationResult shape, runs the trigger command on the same host. |
| `remote_chain.py` | SSH-driven primitive (Windows): PowerShell file probing (Get-FileHash), Event Log capture (Get-WinEvent) in place of dmesg, Defender status snapshot (Get-MpComputerStatus), SCP upload for PoC scripts. Plan mode: `windows_remote`. Convenience wrapper `verify_chain_poc_on_windows()` for direct PoC path → HMDXIN execution. |
| `triage.py` | Plan-driven orchestrator: matches a `verification.json` to Findings via `applies_to`, runs `sanitizer.verify_remote`, walks each Finding through the state machine (DETECTED → CONFIRMED → IMPACT_VERIFIED), persists evidence + run log. |

### Verification-plan schema (Phase-4 minimal)

```jsonc
{
  "name": "<short identifier>",
  "knowledge_refs": ["[[Memory/Knowledge/...]]"],
  "ssh_alias": null,                 // null = use lab_target.ssh_alias from config
  "confirm_destructive": false,      // plan-level destructive-pattern gate default

  "applies_to": {                    // pick the Findings this plan validates
    "binary_basenames": ["<name>.ko"],
    "categories": ["<category>"],
    "function_prefixes": ["<prefix_>"],
    "function_names": ["<exact>"],
    "ids": ["<finding-id>"],
    "match_all": true
  },

  "setup_commands": [                 // run before pre-snapshot, abort on first non-zero rc
    "..."
  ],
  "trigger": {
    "command": "...",
    "timeout_s": 60,
    "confirm_destructive": null       // null inherits plan-level
  },
  "probes": ["/abs/path"],            // hashed before+after; deltas = IMPACT_VERIFIED-grade evidence
  "dmesg_patterns": null,             // null = DEFAULT_DMESG_PATTERNS
  "teardown_commands": [              // ALWAYS run, even on setup failure or trigger skip
    "..."
  ],
  "setup_timeout_s": 60,
  "teardown_timeout_s": 60,
  "notes": ["..."]
}
```

### Verdict roll-up

| Evidence | Result |
|---|---|
| Setup failed | trigger skipped; no transition |
| Trigger skipped (operator denied destructive prompt) | no transition |
| Trigger ran, no file delta, no dmesg match | CONFIRMED |
| Trigger ran, *any* probe-file content delta | IMPACT_VERIFIED |
| Trigger ran, *any* sanitizer-pattern dmesg match | IMPACT_VERIFIED |

### State-machine path

The Argus state machine forbids skipping CONFIRMED on the way to
IMPACT_VERIFIED. `verify/triage.py` walks the legal forward path
automatically — DETECTED → CONFIRMED → IMPACT_VERIFIED becomes two
transitions in `state_history` for one run, both bearing the same
`evidence_ref`.

### Configuring the lab target

`config/argus.local.toml`:

```toml
[lab_target]
ssh_alias       = "argus-lab"          # must match a Host entry in ~/.ssh/config
description     = "Proxmox Ubuntu 24.04 + 6.8.0-111-generic"
default_workdir = "~/argus"
require_confirm_destructive = true     # plan can override per-run
```

Env var `ARGUS_LAB_SSH_ALIAS` and `ARGUS_LAB_NOCONFIRM=1` are the
per-invocation overrides.

### Running a cycle

```bash
# Optional — re-deploy probe artefacts to the lab
bash dev/deploy_probe.sh CVE-2026-31431

# Phase 1 produces (or has produced) a Findings file
PYTHONPATH=skills/binary-ninja python -m scripts.verify.triage \
    --plan vulntest/known-positive/CVE-2026-31431/verification.json \
    --findings findings/cve-2026-31431.json
```

Exit codes: `0` = IMPACT_VERIFIED achieved; `1` = CONFIRMED only;
`2` = no evidence / setup failure.

## Deferred — Phase 4 forward-state

Captured as recognised so they aren't lost.

### Sanitizer-instrumented kernels (KASAN / KFENCE / UBSAN)

The minimal slice runs against a stock Ubuntu kernel; no
sanitizer-pattern dmesg matches are expected for `copy.fail`
(KASAN would have reported an OOB write at the call site). For
sanitiser-positive findings, build a KASAN kernel for the lab and
parameterise `dmesg_patterns` per plan. Probably becomes a separate
`config.local.toml` profile (`lab_target.kasan` vs `lab_target.stock`).

### ASan / UBSan / MSan / TSan for userspace targets

Userspace verification needs a parallel `verify/asan.py` that knows
about sanitizer build flags, runtime envs (`ASAN_OPTIONS`,
`UBSAN_OPTIONS`), and crash-output formats. Not needed for kernel
work; first-class for the open-source userspace targets queued
for Phase 2.

### Debugger launch-chain harness

Methodology.md Stage 2 (PROVEN under launch chain) wants a
`verify/debugger.py` that drives GDB / WinDbg / LLDB through the
target's actual launch chain — not just a standalone PoC. Higher-
fidelity than the minimal slice; needed for IMPACT_PENDING findings
where the isolated PoC works but reachability through the full
launch chain is in question.

### Crash deduplication and exploitability rating refresh

When verification produces multiple matching dmesg captures (or
multiple distinct crash sites), `verify/triage.py` should dedupe
and refresh the per-Finding `mitigation_weighted_exploitability`
score from the *runtime* mitigations observed (NX, ASLR slide
captured, canary intact/clobbered) rather than the static profile
alone.

### Per-finding plans

The current shape is one-plan-many-Findings — right for kernel bugs
where every detected call site shares one PoC trigger. Userspace
exploitation often wants one trigger per finding (different inputs
per call site). Adding `applies_to` becomes a list of plan blocks
inside one verification.json file, with a `for_each_finding`
trigger templating language.

### Reachability analysis

Currently we trust the plan's `applies_to` to be authoritative.
Eventually `verify/triage.py` should run a *reachability check*
(call-graph + tainted-input feasibility) before running the
trigger, downgrading findings whose paths are unreachable from any
external source.

## See also

- `dev/lab_run.sh` — bash wrapper for ad-hoc remote commands;
  shares the destructive-pattern gate
- `dev/deploy_probe.sh` — sync per-cell probe artefacts to the lab
- `vulntest/known-positive/CVE-2026-31431/verification.json` —
  reference plan
