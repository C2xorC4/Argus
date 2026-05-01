"""Phase 4 — verification orchestrator + state-machine driver.

Inputs:
  - A Findings JSON file (a list of Finding v2 dicts) — the output of
    Phase 1 / 2 / 3 detection runs.
  - A verification plan JSON file — names the trigger PoC, probe
    files, dmesg patterns, and the rule that ties one verification
    run to one or more Finding ids.

Output:
  - The Findings JSON, updated in place (or written to --out): each
    matching Finding's `state` advanced through the state machine,
    with a StateTransition appended to `state_history` and the
    sanitizer evidence appended to `evidence`.
  - A run-log written next to the verification plan, capturing the
    full VerificationResult for auditing.

Verification-plan schema (minimal Phase-4 slice):

```json
{
  "name": "CVE-2026-31431 — copy.fail page-cache OOB write",
  "knowledge_refs": ["[[Memory/Knowledge/copy_fail_cve_2026_31431]]"],
  "ssh_alias": null,                 // null = use config default
  "applies_to": {                    // pick the Findings this plan validates
    "binary_basenames": ["authencesn.ko"],
    "categories": ["kernel_oob_write"],
    "function_prefixes": ["crypto_authenc_esn_"],
    "match_all": true                // AND vs OR across the criteria
  },
  "trigger": {
    "command": "cd ~/argus/copyfail && python3 ./run_probe.py",
    "timeout_s": 60,
    "confirm_destructive": false
  },
  "probes": [
    "/tmp/argus_probe.txt"
  ],
  "dmesg_patterns": null             // null = DEFAULT_DMESG_PATTERNS
}
```

Future enhancements (deferred — capture in `verify/README.md`):

- Per-finding verification plans (one trigger per Finding) versus
  the current one-plan-many-Findings shape that's right for kernel
  bugs where every detected call site shares one PoC
- ASan / UBSan integration: the plan's `trigger.preamble` would
  spin up the sanitizer-instrumented variant
- Crash deduplication across multiple plans
- Reachability analysis (intra- vs inter-process trigger paths)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..lib.state import (
    FindingState, IllegalTransition, can_transition, transition,
)
from ..output.finding import Finding
from .sanitizer import (
    VerificationResult, recommend_state, verify_remote,
)


# ─────────────────────────────────────────────────────────────────
# Plan loading + Finding selection
# ─────────────────────────────────────────────────────────────────


def load_plan(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_findings(path: Path) -> list[Finding]:
    """Read a Findings JSON file. Accepts either a top-level list or
    `{"findings": [...]}` object form for forward-compat."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected list of Finding dicts at top level")
    return [Finding.from_dict(d) for d in data]


def save_findings(path: Path, findings: list[Finding]) -> None:
    payload = [f.to_dict() for f in findings]
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _basename(path_or_blob: str) -> str:
    """Last component, ignoring forward/back slashes. Defensive against
    Windows-style paths in cross-platform Findings."""
    if not path_or_blob:
        return ""
    return os.path.basename(path_or_blob.replace("\\", "/"))


def select_findings(findings: list[Finding], applies_to: dict) -> list[Finding]:
    """Return the subset of `findings` matching the `applies_to` clause.

    Criteria (any may be omitted; an omitted criterion accepts all):

    - `binary_basenames`: match if `basename(finding.binary)` is in the list
    - `categories`: match if `finding.category` is in the list
    - `function_prefixes`: match if `finding.function` starts with any prefix
    - `function_names`: match if `finding.function` is in the list (exact)
    - `ids`: match if `finding.id` is in the list
    - `match_all`: True (default) means AND across the above; False means OR
    """
    if not applies_to:
        return list(findings)

    bns = set(applies_to.get("binary_basenames", []) or [])
    cats = set(applies_to.get("categories", []) or [])
    pfxs = tuple(applies_to.get("function_prefixes", []) or [])
    fns = set(applies_to.get("function_names", []) or [])
    ids = set(applies_to.get("ids", []) or [])
    match_all = bool(applies_to.get("match_all", True))

    def predicate(f: Finding) -> bool:
        checks: list[bool] = []
        if bns:
            checks.append(_basename(f.binary) in bns)
        if cats:
            checks.append(f.category in cats)
        if pfxs:
            checks.append(any(f.function.startswith(p) for p in pfxs))
        if fns:
            checks.append(f.function in fns)
        if ids:
            checks.append(f.id in ids)
        if not checks:
            return True
        return all(checks) if match_all else any(checks)

    return [f for f in findings if predicate(f)]


# ─────────────────────────────────────────────────────────────────
# Core orchestration
# ─────────────────────────────────────────────────────────────────


def apply_verification(
    findings: list[Finding],
    plan: dict,
    *,
    actor: str = "verify.triage",
) -> tuple[list[Finding], VerificationResult, list[Finding]]:
    """Run the plan's trigger once, then transition matching Findings.

    Returns `(all_findings, verification_result, transitioned_subset)`.

    The function is in-place on the Finding objects (each transitioned
    Finding has its `state`, `state_history`, and `evidence` mutated).
    The same objects are returned in `all_findings` for caller
    convenience; pass a deep-copy list in if you want immutability.
    """
    selected = select_findings(findings, plan.get("applies_to", {}))
    if not selected:
        raise ValueError(
            f"plan {plan.get('name', '<unnamed>')!r} matched zero findings; "
            "refusing to run (likely a misconfigured applies_to clause)"
        )

    trig = plan.get("trigger", {})
    cmd = trig.get("command", "")
    if not cmd:
        raise ValueError(f"plan {plan.get('name', '<unnamed>')!r}: trigger.command required")
    timeout_s = int(trig.get("timeout_s", 120))
    # Plan-level confirm_destructive sets the default for ALL aux
    # commands (setup/trigger/teardown). trigger.confirm_destructive
    # may still override per-trigger for backwards compatibility.
    plan_confirm = plan.get("confirm_destructive")
    trigger_confirm = trig.get("confirm_destructive")
    confirm = trigger_confirm if trigger_confirm is not None else plan_confirm
    ssh_alias = plan.get("ssh_alias")
    probes = plan.get("probes") or []
    patterns = plan.get("dmesg_patterns")
    setup_cmds = plan.get("setup_commands") or []
    teardown_cmds = plan.get("teardown_commands") or []
    setup_to = int(plan.get("setup_timeout_s", 60))
    teardown_to = int(plan.get("teardown_timeout_s", 60))

    vr = verify_remote(
        trigger_command=cmd,
        probe_paths=list(probes),
        dmesg_patterns=list(patterns) if patterns else None,
        timeout_s=timeout_s,
        ssh_alias=ssh_alias,
        confirm_destructive=confirm,
        setup_commands=list(setup_cmds),
        teardown_commands=list(teardown_cmds),
        setup_timeout_s=setup_to,
        teardown_timeout_s=teardown_to,
    )

    transitioned: list[Finding] = []
    for f in selected:
        recommended = recommend_state(f.state, vr)
        if recommended is None:
            continue
        # Materialise Evidence on every transitioning Finding.
        for ev in vr.as_evidence():
            f.evidence.append(ev)

        # Drive the state machine. The recommend_state() helper may jump
        # DETECTED → IMPACT_VERIFIED in one logical step; the underlying
        # state machine forbids that, so we walk it through CONFIRMED.
        path = _path_through_state_machine(f.state, recommended)
        ok = True
        for nxt in path:
            try:
                f.state, _record = transition(
                    f.state, nxt,
                    actor=actor,
                    evidence_ref=f"verify_run@{vr.started_at}",
                    notes=_transition_notes(plan, vr, nxt),
                    history=f.state_history,
                )
            except IllegalTransition as e:
                ok = False
                f.evidence.append(_note_evidence(
                    f"illegal transition while applying plan {plan.get('name')!r}: {e}"
                ))
                break
        if ok:
            transitioned.append(f)

    return findings, vr, transitioned


def _path_through_state_machine(current: FindingState,
                                target: FindingState) -> list[FindingState]:
    """Walk the legal-transition graph from `current` to `target`.

    Hand-coded for the four-state forward path; cheaper than a general
    BFS and makes the legal trajectory explicit.
    """
    if current is target:
        return []
    forward_order = [
        FindingState.DETECTED,
        FindingState.CONFIRMED,
        FindingState.IMPACT_PENDING,
        FindingState.IMPACT_VERIFIED,
    ]
    if target is FindingState.DISMISSED:
        return [FindingState.DISMISSED]
    if current in forward_order and target in forward_order:
        i = forward_order.index(current)
        j = forward_order.index(target)
        if j <= i:
            return []
        # Skip IMPACT_PENDING for the common DETECTED→IMPACT_VERIFIED case;
        # state machine permits CONFIRMED→IMPACT_VERIFIED directly when
        # the isolated PoC equals the launch-chain test (which is true
        # for kernel-LPE-style bugs where the PoC IS the launch chain).
        path: list[FindingState] = []
        s = current
        while s is not target:
            if s is FindingState.DETECTED:
                path.append(FindingState.CONFIRMED)
                s = FindingState.CONFIRMED
                continue
            if s is FindingState.CONFIRMED:
                if can_transition(FindingState.CONFIRMED, target):
                    path.append(target)
                    return path
                path.append(FindingState.IMPACT_PENDING)
                s = FindingState.IMPACT_PENDING
                continue
            if s is FindingState.IMPACT_PENDING:
                path.append(FindingState.IMPACT_VERIFIED)
                return path
        return path
    return []


def _transition_notes(plan: dict, vr: VerificationResult, target: FindingState) -> str:
    name = plan.get("name", "<unnamed plan>")
    bits = [f"plan={name!r}"]
    if vr.impact_verified_evidence:
        if vr.dmesg_matches:
            bits.append(f"dmesg_matches={len(vr.dmesg_matches)}")
        if vr.any_file_changed:
            n = sum(1 for d in vr.file_deltas if d.changed and d.delta_kind != "error")
            bits.append(f"file_changes={n}")
    if vr.confirmed_evidence and not vr.impact_verified_evidence:
        bits.append(f"trigger_rc={vr.trigger_returncode}")
    return "; ".join(bits)


def _note_evidence(text: str):
    from ..output.finding import Evidence
    return Evidence(kind="verify_note", source="verify.triage", payload=text)


# ─────────────────────────────────────────────────────────────────
# Run-log writer
# ─────────────────────────────────────────────────────────────────


def _default_log_path(plan_path: Path) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return plan_path.with_name(f"{plan_path.stem}.run.{ts}.json")


def write_run_log(plan_path: Path, plan: dict, vr: VerificationResult,
                  transitioned: list[Finding], log_path: Optional[Path] = None) -> Path:
    log_path = log_path or _default_log_path(plan_path)
    payload = {
        "plan_path": str(plan_path),
        "plan_name": plan.get("name"),
        "verification": vr.to_dict(),
        "transitioned_findings": [
            {"id": f.id, "category": f.category, "function": f.function,
             "binary": f.binary, "address": hex(f.address) if isinstance(f.address, int) else f.address,
             "new_state": f.state.value}
            for f in transitioned
        ],
    }
    log_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return log_path


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="verify.triage",
        description="Apply a Phase-4 verification plan to a Findings file.",
    )
    ap.add_argument("--plan", required=True, type=Path,
                    help="path to the verification-plan JSON")
    ap.add_argument("--findings", required=True, type=Path,
                    help="path to the Findings JSON to verify against")
    ap.add_argument("--out", type=Path, default=None,
                    help="write updated Findings here; default: in place")
    ap.add_argument("--log", type=Path, default=None,
                    help="write run log here; default: alongside the plan")
    ap.add_argument("--dry-run", action="store_true",
                    help="select matching Findings and print, but do not run")
    args = ap.parse_args(argv)

    plan = load_plan(args.plan)
    findings = load_findings(args.findings)

    if args.dry_run:
        selected = select_findings(findings, plan.get("applies_to", {}))
        print(f"plan: {plan.get('name')}")
        print(f"would verify {len(selected)} of {len(findings)} findings:")
        for f in selected:
            print(f"  [{f.state.value:>15s}] {f.id} {f.category} @ {f.function} "
                  f"({_basename(f.binary)}+{hex(f.address) if isinstance(f.address, int) else f.address})")
        return 0

    findings, vr, transitioned = apply_verification(findings, plan)

    out_path = args.out or args.findings
    save_findings(out_path, findings)
    log_path = write_run_log(args.plan, plan, vr, transitioned, args.log)

    sys.stderr.write(
        f"[verify.triage] plan={plan.get('name')!r}\n"
        f"  trigger rc={vr.trigger_returncode} duration={vr.duration_s:.2f}s\n"
        f"  dmesg matches={len(vr.dmesg_matches)}  file changes="
        f"{sum(1 for d in vr.file_deltas if d.changed and d.delta_kind != 'error')}\n"
        f"  evidence: confirmed={vr.confirmed_evidence} impact={vr.impact_verified_evidence}\n"
        f"  transitioned {len(transitioned)} finding(s)\n"
        f"  findings -> {out_path}\n"
        f"  run log  -> {log_path}\n"
    )
    if vr.impact_verified_evidence:
        return 0
    if vr.confirmed_evidence:
        return 1
    return 2


if __name__ == "__main__":                          # pragma: no cover
    raise SystemExit(main())
