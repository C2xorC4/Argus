"""Phase 4 — local-execution verification primitive.

Parallel to `sanitizer.py` (SSH-driven Linux harness). Where that
module reaches into a remote target via SSH, this one drives a
local subprocess on the same Windows / Linux host that's running
Argus itself. Same plan-JSON schema, same `VerificationResult`
output — different execution mode.

Use case: tier-1 / tier-2 fixtures whose vuln binary is on the
local host. The Phase-3 finding-PoC generator
(`exploit/finding_poc.py`) emits a Python driver per finding; this
harness runs that driver, captures evidence, and emits a verdict
ready for the state-machine bridge in `triage.py` /
`phase4_triage`.

Plan-JSON additions over the SSH variant:

  mode: "local"                  // discriminator vs "ssh"
  trigger.cwd: <abs path>        // optional working dir
  trigger.env: {KEY: VAL}        // optional extra env
  crash_patterns: [regex, …]     // matched against trigger stdout+stderr;
                                  // any hit elevates to IMPACT_VERIFIED
                                  // (cross-platform — same role as
                                  // dmesg_patterns in the SSH variant)

The verdict logic mirrors the SSH harness:
  - CONFIRMED   — trigger ran (rc captured, didn't time out beyond
                  a hard limit, no setup-step failure)
  - IMPACT_VERIFIED  — at least one of: probe-file changed, the
                       trigger crashed (non-zero rc on Windows
                       *or* negative on POSIX), a crash_patterns
                       regex matched the captured output, OR the
                       PoC's `[+] EXPLOIT RAN` marker appeared on
                       stdout.

Knowledge anchor:
  `[[Memory/Knowledge/argus_detector_design_principles]]` (§ Phase
  vocabulary — VERIFIED requires demonstrable trigger evidence, not
  just clean execution).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Re-use the data types from sanitizer.py — same shape, just
# populated by local exec rather than SSH.
from .sanitizer import (
    CommandResult,
    Evidence,
    FileDelta,
    FileSnapshot,
    VerificationResult,
)


# Cross-platform crash signatures matched against the trigger's
# combined stdout+stderr. The Phase-3 finding_poc generator emits
# `[+] EXPLOIT RAN` deterministically — every category-specific
# template uses that exact marker so we can detect it here.
DEFAULT_CRASH_PATTERNS: tuple[str, ...] = (
    r"\[\+\] EXPLOIT RAN",          # Phase-3 PoC success marker
    r"Segmentation fault",
    r"Stack overflow",
    r"Stack canary failed",
    r"AddressSanitizer:",
    r"==.*==ERROR:",                # ASan / UBSan banner
    r"Aborted \(core dumped\)",
    r"Access violation",            # Windows AV
    r"This application has requested the Runtime to terminate",
    r"buffer overrun",
    r"_invalid_parameter",          # MSVC CRT
    r"\bdouble free\b",
    r"\bglibc detected\b",
)


def _sha256_file(path: Path) -> FileSnapshot:
    if not path.exists():
        return FileSnapshot(path=str(path), present=False)
    try:
        h = hashlib.sha256()
        size = 0
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
                size += len(chunk)
        return FileSnapshot(
            path=str(path), sha256=h.hexdigest(),
            size_bytes=size, present=True,
        )
    except Exception as e:
        return FileSnapshot(
            path=str(path), present=False, error=f"{type(e).__name__}: {e}",
        )


def _diff_snapshots(before: FileSnapshot, after: FileSnapshot) -> FileDelta:
    if before.error or after.error:
        return FileDelta(path=before.path or after.path,
                         before=before, after=after,
                         changed=False, delta_kind="error")
    if not before.present and not after.present:
        return FileDelta(path=before.path, before=before, after=after,
                         changed=False, delta_kind="unchanged")
    if not before.present and after.present:
        return FileDelta(path=after.path, before=before, after=after,
                         changed=True, delta_kind="appeared")
    if before.present and not after.present:
        return FileDelta(path=before.path, before=before, after=after,
                         changed=True, delta_kind="vanished")
    if before.sha256 == after.sha256 and before.size_bytes == after.size_bytes:
        return FileDelta(path=before.path, before=before, after=after,
                         changed=False, delta_kind="unchanged")
    delta_kind = "content" if before.sha256 != after.sha256 else "size"
    return FileDelta(path=before.path, before=before, after=after,
                     changed=True, delta_kind=delta_kind)


def _run_command(command: str, *,
                 cwd: Optional[str] = None,
                 env: Optional[dict] = None,
                 timeout_s: int = 30,
                 shell: bool = True) -> CommandResult:
    started = time.time()
    extra_env = None
    if env:
        extra_env = os.environ.copy()
        for k, v in env.items():
            extra_env[k] = str(v)
    try:
        cp = subprocess.run(
            command,
            shell=shell,
            cwd=cwd,
            env=extra_env,
            capture_output=True,
            timeout=timeout_s,
        )
        return CommandResult(
            command=command,
            returncode=int(cp.returncode),
            stdout=(cp.stdout or b"").decode("utf-8", errors="replace"),
            stderr=(cp.stderr or b"").decode("utf-8", errors="replace"),
            duration_s=round(time.time() - started, 3),
        )
    except subprocess.TimeoutExpired as e:
        return CommandResult(
            command=command,
            returncode=-1,
            stdout=(e.stdout or b"").decode("utf-8", errors="replace") if e.stdout else "",
            stderr=(e.stderr or b"").decode("utf-8", errors="replace") if e.stderr else "",
            duration_s=round(time.time() - started, 3),
            timed_out=True,
        )
    except Exception as e:
        return CommandResult(
            command=command,
            returncode=-1,
            stdout="",
            stderr=f"{type(e).__name__}: {e}",
            duration_s=round(time.time() - started, 3),
        )


def verify_local(plan: dict, *,
                 crash_patterns: Optional[tuple] = None) -> VerificationResult:
    """Run a verification plan against a local target.

    Plan schema (Phase-4 local variant):

        {
          "name": "<run name>",
          "mode": "local",
          "setup_commands": ["mkdir ...", ...],   // optional
          "trigger": {
            "command": "python dev/_test_stack_of_poc.py",
            "timeout_s": 30,
            "cwd": null,                         // optional
            "env": {}                            // optional
          },
          "probes": ["C:/path/to/file/maybe/written/by/trigger"],
          "teardown_commands": [...],            // optional
          "crash_patterns": [regex, ...]         // optional, augments
                                                 // DEFAULT_CRASH_PATTERNS
        }

    Returns a `VerificationResult` with the same shape as the
    SSH-driven variant so the existing state-machine bridge can
    consume both interchangeably.
    """
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.time()

    if (plan.get("mode") or "local").lower() != "local":
        raise ValueError(
            f"verify_local invoked on a plan with mode={plan.get('mode')!r}; "
            "use verify_remote for SSH-driven plans."
        )

    setup_results: list[CommandResult] = []
    setup_failed = False
    for cmd in plan.get("setup_commands", []) or []:
        r = _run_command(cmd)
        setup_results.append(r)
        if r.returncode != 0:
            setup_failed = True
            break

    probes = list(plan.get("probes", []) or [])
    before_snapshots = {p: _sha256_file(Path(p)) for p in probes}

    trigger_cfg = plan.get("trigger") or {}
    trigger_command = trigger_cfg.get("command", "")
    trigger_timeout = int(trigger_cfg.get("timeout_s", 30) or 30)
    trigger_cwd = trigger_cfg.get("cwd")
    trigger_env = trigger_cfg.get("env") or {}

    if setup_failed or not trigger_command:
        trigger_result = CommandResult(
            command=trigger_command,
            returncode=-1, stdout="", stderr="",
            duration_s=0.0,
            skipped_reason=("setup failed" if setup_failed
                            else "no trigger command provided"),
        )
    else:
        trigger_result = _run_command(
            trigger_command,
            cwd=trigger_cwd,
            env=trigger_env,
            timeout_s=trigger_timeout,
        )

    after_snapshots = {p: _sha256_file(Path(p)) for p in probes}
    file_deltas = [
        _diff_snapshots(before_snapshots[p], after_snapshots[p])
        for p in probes
    ]
    any_file_changed = any(fd.changed for fd in file_deltas)

    teardown_results: list[CommandResult] = []
    for cmd in plan.get("teardown_commands", []) or []:
        teardown_results.append(_run_command(cmd))

    # Pattern matching against trigger's captured output.
    all_patterns = list(crash_patterns or DEFAULT_CRASH_PATTERNS)
    for extra in (plan.get("crash_patterns") or []):
        all_patterns.append(extra)
    combined = (trigger_result.stdout or "") + "\n" + (trigger_result.stderr or "")
    pattern_matches: list[dict] = []
    for pat in all_patterns:
        try:
            for m in re.finditer(pat, combined):
                pattern_matches.append({
                    "pattern": pat,
                    "match": m.group(0)[:160],
                })
        except re.error:
            continue

    # Verdict.
    confirmed = (
        not setup_failed
        and not trigger_result.timed_out
        and trigger_result.returncode != -1
    )
    impact_verified = (
        confirmed and (
            any_file_changed
            or trigger_result.returncode != 0
            or bool(pattern_matches)
        )
    )

    finished = datetime.now(timezone.utc).isoformat()
    return VerificationResult(
        started_at=started,
        finished_at=finished,
        duration_s=round(time.time() - t0, 3),
        ssh_alias="<local>",
        trigger_command=trigger_command,
        probe_paths=probes,
        setup_results=setup_results,
        teardown_results=teardown_results,
        setup_failed=setup_failed,
        trigger_returncode=int(trigger_result.returncode),
        trigger_stdout=trigger_result.stdout or "",
        trigger_stderr=trigger_result.stderr or "",
        trigger_timed_out=trigger_result.timed_out,
        trigger_skipped_reason=trigger_result.skipped_reason,
        file_deltas=file_deltas,
        any_file_changed=any_file_changed,
        dmesg_new_lines=[],                              # N/A for local
        dmesg_matches=pattern_matches,                   # repurposed
        dmesg_capture_method="local-subprocess-stdout+stderr",
        confirmed_evidence=confirmed,
        impact_verified_evidence=impact_verified,
        notes=[],
    )


def verify_finding_locally(finding,
                           poc_script: str, *,
                           binary_path: Optional[str] = None,
                           probes: Optional[list[str]] = None,
                           timeout_s: int = 30) -> VerificationResult:
    """Convenience wrapper for the common path: take a per-finding
    PoC script (from `exploit.render_finding_poc`), write it to a
    temp file, and run it via the local harness.

    Returns the same `VerificationResult` as `verify_local`.
    """
    import tempfile
    poc_path = Path(tempfile.gettempdir()) / f"argus_poc_{int(time.time())}.py"
    poc_path.write_text(poc_script, encoding="utf-8")
    try:
        plan = {
            "name": f"local verify {getattr(finding, 'category', '<unknown>')}",
            "mode": "local",
            "trigger": {
                "command": f'python -X utf8 "{poc_path}"',
                "timeout_s": timeout_s,
            },
            "probes": list(probes or []),
        }
        return verify_local(plan)
    finally:
        try:
            poc_path.unlink()
        except Exception:
            pass


__all__ = [
    "DEFAULT_CRASH_PATTERNS",
    "verify_local",
    "verify_finding_locally",
]
