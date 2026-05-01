"""Phase 4 — dynamic verification primitive.

Minimal slice landed for CVE-2026-31431 ("copy.fail") validation. The
shape generalises to any SSH-reachable Linux target where the operator
wants to:

1. Capture file state before a trigger (sha256 of named probe paths).
2. Drain the kernel ring buffer.
3. Run a trigger command (the PoC).
4. Capture file state after.
5. Diff the new dmesg lines for sanitizer / oops / KASAN signatures.
6. Recommend a Finding state transition based on the evidence.

The module is deliberately ABI-light:

- It does *not* know about specific PoCs. The caller passes a remote
  command string. CVE-2026-31431 happens to be the first consumer; it
  composes the PoC invocation in the cell-level `verification.json`.
- It does *not* mutate Findings. `verify/triage.py` consumes the
  `VerificationResult` and applies state transitions.
- It does *not* itself install KASAN / sanitizer kernels. The default
  shape is "stock kernel + dmesg + file delta" because that's what
  the lab runs today; KASAN-instrumented kernels are a deferred
  Phase 4 enhancement noted in `verify/README.md`.

Future enhancements (deferred, document and forward-ref only):

- ASan / UBSan / MSan / TSan integration for userspace targets
- GDB / LLDB / WinDbg launch harness for in-launch-chain validation
- Per-arch crash-site classification (RIP overwrite, vtable hijack,
  free-list cascade)
- Crash deduplication across runs (consume into `verify/triage.py`)

Knowledge anchor:
    `[[Memory/Knowledge/copy_fail_cve_2026_31431]]` (pending consolidation)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..lib.config import load_config, LabTargetConfig
from ..lib.state import FindingState
from ..output.finding import Evidence


# ─────────────────────────────────────────────────────────────────
# Default dmesg signatures we treat as "kernel-instrumentation
# evidence". A match elevates a Finding from CONFIRMED to
# IMPACT_VERIFIED on its own.
# Order matters only for the "first match wins" labelling in evidence.
# ─────────────────────────────────────────────────────────────────


DEFAULT_DMESG_PATTERNS: tuple[str, ...] = (
    r"\bKASAN:",
    r"\bUBSAN:",
    r"\bKFENCE:",
    r"\bBUG:",
    r"\bOops:",
    r"\bWARNING:",
    r"\bgeneral protection fault\b",
    r"\bunable to handle (kernel )?(paging request|page fault)\b",
    r"\bkernel BUG at\b",
    r"\bstack-out-of-bounds\b",
    r"\bslab-out-of-bounds\b",
    r"\bglobal-out-of-bounds\b",
    r"\buse-after-free\b",
    r"\bdouble-free\b",
)


# ─────────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────────


@dataclass
class FileSnapshot:
    """sha256 of a single probe path on the remote, captured at one point.

    `present=False` means stat returned non-zero — the file does not
    exist (or is unreadable) at that snapshot moment. A delta from
    present→absent is itself meaningful evidence (deleted/truncated by
    PoC) and is preserved here.
    """

    path: str
    sha256: str = ""
    size_bytes: int = -1
    present: bool = False
    error: str = ""


@dataclass
class FileDelta:
    """One file's before/after pair plus the verdict."""

    path: str
    before: FileSnapshot
    after: FileSnapshot
    changed: bool
    delta_kind: str = "unchanged"     # "unchanged" | "content" | "size" | "appeared" | "vanished" | "error"


@dataclass
class CommandResult:
    """Captured outcome of one auxiliary remote command (setup/teardown)."""

    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool = False
    skipped_reason: str = ""    # e.g. "operator denied confirmation"


@dataclass
class VerificationResult:
    """One Phase-4 verification run's evidence bundle.

    Self-contained: serialises to JSON and round-trips through the
    `triage.py` driver without losing structure. Each field is an
    independent piece of evidence the operator can audit.
    """

    # --- Run identity ------------------------------------------------
    started_at: str                        # ISO 8601 UTC
    finished_at: str
    duration_s: float

    # --- What we did -------------------------------------------------
    ssh_alias: str
    trigger_command: str                   # the remote shell command run
    probe_paths: list[str] = field(default_factory=list)

    # --- Setup / teardown -------------------------------------------
    setup_results: list[CommandResult] = field(default_factory=list)
    teardown_results: list[CommandResult] = field(default_factory=list)
    setup_failed: bool = False              # short-circuits the trigger

    # --- Trigger outcome --------------------------------------------
    trigger_returncode: int = -1
    trigger_stdout: str = ""
    trigger_stderr: str = ""
    trigger_timed_out: bool = False
    trigger_skipped_reason: str = ""

    # --- File state -------------------------------------------------
    file_deltas: list[FileDelta] = field(default_factory=list)
    any_file_changed: bool = False

    # --- Kernel ring buffer -----------------------------------------
    dmesg_new_lines: list[str] = field(default_factory=list)
    dmesg_matches: list[dict] = field(default_factory=list)   # [{pattern, line}]
    dmesg_capture_method: str = "dmesg-clear+dmesg"           # how we captured

    # --- Verdict ----------------------------------------------------
    confirmed_evidence: bool = False        # at least CONFIRMED-grade
    impact_verified_evidence: bool = False  # IMPACT_VERIFIED-grade

    # --- Diagnostics ------------------------------------------------
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        # FileDelta snapshots are nested dataclasses; asdict already flattens.
        return d

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def as_evidence(self, source: str = "verify.sanitizer") -> list[Evidence]:
        """Render as a list of Finding `Evidence` items for attachment.

        Splits the verification into discrete evidence kinds so renderers
        (markdown / SARIF / vendor reports) can present them
        individually.
        """
        items: list[Evidence] = []

        # Always include a run-summary blob as evidence kind="verify_run".
        items.append(Evidence(
            kind="verify_run",
            source=source,
            payload=self.to_json(indent=2),
            notes=f"trigger={self.trigger_command!r}; rc={self.trigger_returncode}; "
                  f"duration={self.duration_s:.2f}s; "
                  f"setup_steps={len(self.setup_results)}; "
                  f"teardown_steps={len(self.teardown_results)}",
        ))

        # File deltas — one Evidence per *changed* probe (skip unchanged).
        for fd in self.file_deltas:
            if not fd.changed:
                continue
            items.append(Evidence(
                kind="file_delta",
                source=source,
                payload=json.dumps(asdict(fd), indent=2, default=str),
                notes=f"{fd.path}: {fd.delta_kind} (before={fd.before.sha256[:12]}, "
                      f"after={fd.after.sha256[:12]})",
            ))

        # dmesg matches — one Evidence per matching pattern.
        for m in self.dmesg_matches:
            items.append(Evidence(
                kind="dmesg_match",
                source=source,
                payload=m["line"],
                notes=f"matched {m['pattern']!r}",
            ))

        return items


# ─────────────────────────────────────────────────────────────────
# Internals
# ─────────────────────────────────────────────────────────────────


_DESTRUCTIVE_PATTERNS: tuple[str, ...] = (
    "rmmod ", "modprobe ", "mkfs", "dd if=", "shred ", "rm -rf /",
    "sudo rm ", "sudo dd ", "> /dev/sd", "reboot", "shutdown",
)


def _looks_destructive(cmd: str) -> bool:
    return any(pat in cmd for pat in _DESTRUCTIVE_PATTERNS)


def _confirm_or_abort(cmd: str, ssh_alias: str) -> None:
    """Interactive confirmation gate for destructive remote commands.

    Mirrors `dev/lab_run.sh` semantics: env var ARGUS_LAB_NOCONFIRM=1
    bypasses; otherwise prompt. Triage sometimes runs non-interactively
    (e.g., from a longer batch); in that case the env var must be set
    explicitly so consent is durable rather than silent.
    """
    if os.environ.get("ARGUS_LAB_NOCONFIRM", "").strip():
        return
    sys.stderr.write(
        f"[verify] destructive pattern matched; confirm to proceed.\n"
        f"  target: {ssh_alias}\n"
        f"  cmd:    {cmd}\n"
        f"Confirm? [y/N] "
    )
    sys.stderr.flush()
    reply = sys.stdin.readline().strip().lower()
    if not reply.startswith("y"):
        raise RuntimeError("verification aborted by operator")


def _ssh(ssh_alias: str, remote_cmd: str, *,
         timeout_s: int = 60,
         input_data: Optional[str] = None) -> subprocess.CompletedProcess:
    """One SSH round-trip. BatchMode=yes — never prompt for password.

    Returns the completed process (rc, stdout, stderr). Raises only on
    operational failures (e.g., ssh binary missing); SSH connection
    errors bubble up as non-zero rc and stderr text.
    """
    args = ["ssh", "-o", "BatchMode=yes", ssh_alias, remote_cmd]
    return subprocess.run(
        args,
        input=input_data,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def _hash_remote_file(ssh_alias: str, remote_path: str,
                      timeout_s: int = 30) -> FileSnapshot:
    """Capture sha256 + size of a file on the remote.

    Uses `sha256sum`; absent files yield `present=False`. The shell
    quoting ensures spaces in paths survive.
    """
    qpath = shlex.quote(remote_path)
    cmd = (
        f"if [ -e {qpath} ]; then "
        f"  printf 'PRESENT '; "
        f"  stat -c '%s' {qpath} 2>/dev/null || echo -1; "
        f"  sha256sum {qpath} 2>/dev/null | awk '{{print $1}}'; "
        f"else "
        f"  printf 'ABSENT\\n'; "
        f"fi"
    )
    try:
        cp = _ssh(ssh_alias, cmd, timeout_s=timeout_s)
    except subprocess.TimeoutExpired:
        return FileSnapshot(path=remote_path, error="timeout")
    if cp.returncode != 0:
        return FileSnapshot(path=remote_path,
                            error=f"ssh rc={cp.returncode}: {cp.stderr.strip()}")
    out = cp.stdout.strip().splitlines()
    if not out or out[0].startswith("ABSENT"):
        return FileSnapshot(path=remote_path, present=False)
    # Expected: "PRESENT <size>" then "<sha256>"
    head = out[0].split()
    size = int(head[1]) if len(head) > 1 and head[1].lstrip("-").isdigit() else -1
    sha = out[1].strip() if len(out) > 1 else ""
    return FileSnapshot(path=remote_path, sha256=sha, size_bytes=size, present=True)


def _diff_snapshot(before: FileSnapshot, after: FileSnapshot) -> FileDelta:
    """Classify the change in one file."""
    if before.error or after.error:
        return FileDelta(path=before.path or after.path, before=before, after=after,
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
    if before.sha256 != after.sha256:
        kind = "size" if before.size_bytes != after.size_bytes else "content"
        return FileDelta(path=before.path, before=before, after=after,
                         changed=True, delta_kind=kind)
    return FileDelta(path=before.path, before=before, after=after,
                     changed=False, delta_kind="unchanged")


def _drain_dmesg(ssh_alias: str, timeout_s: int = 30) -> tuple[bool, str]:
    """Clear the kernel ring buffer.

    Returns (succeeded, error_or_method_note). Falls back through
    `dmesg --clear`, `dmesg -c`, then a no-op (capture-only mode) so
    a kernel that won't let us clear still produces some signal.
    """
    for cmd in ("sudo -n dmesg --clear", "sudo -n dmesg -c"):
        cp = _ssh(ssh_alias, cmd + " 2>&1 || true", timeout_s=timeout_s)
        if cp.returncode == 0 and "permission denied" not in cp.stdout.lower():
            return True, cmd
    return False, "drain-failed"


def _read_dmesg(ssh_alias: str, timeout_s: int = 30) -> str:
    """Read current dmesg. Plain `dmesg` is sufficient post-clear."""
    cp = _ssh(ssh_alias, "sudo -n dmesg 2>/dev/null || dmesg", timeout_s=timeout_s)
    return cp.stdout if cp.returncode == 0 else ""


def _match_dmesg(lines: list[str], patterns: tuple[str, ...]) -> list[dict]:
    """Return one entry per (pattern, line) that matches."""
    matches: list[dict] = []
    compiled = [(p, re.compile(p)) for p in patterns]
    for line in lines:
        for pat_str, rx in compiled:
            if rx.search(line):
                matches.append({"pattern": pat_str, "line": line.rstrip()})
                # break: report each line once, not multiple matches per line
                break
    return matches


def _run_aux_command(
    ssh_alias: str,
    cmd: str,
    *,
    timeout_s: int,
    confirm_destructive: bool,
) -> CommandResult:
    """Run one auxiliary command (setup or teardown step).

    Returns a CommandResult capturing rc/stdout/stderr/duration. Honours
    the destructive-pattern gate (operator confirmation, or
    ARGUS_LAB_NOCONFIRM=1 bypass). On confirmation refusal the command
    is skipped (recorded as such); the caller decides whether to abort.
    """
    if confirm_destructive and _looks_destructive(cmd):
        try:
            _confirm_or_abort(cmd, ssh_alias)
        except RuntimeError as e:
            return CommandResult(
                command=cmd, returncode=-1, stdout="", stderr=str(e),
                duration_s=0.0, skipped_reason=str(e),
            )
    t = time.monotonic()
    try:
        cp = _ssh(ssh_alias, cmd, timeout_s=timeout_s)
        return CommandResult(
            command=cmd,
            returncode=cp.returncode,
            stdout=cp.stdout,
            stderr=cp.stderr,
            duration_s=time.monotonic() - t,
        )
    except subprocess.TimeoutExpired as e:
        return CommandResult(
            command=cmd, returncode=-1,
            stdout=e.stdout or "", stderr=(e.stderr or "") + "\n[verify] timed out",
            duration_s=time.monotonic() - t, timed_out=True,
        )


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


def verify_remote(
    trigger_command: str,
    *,
    probe_paths: Optional[list[str]] = None,
    dmesg_patterns: Optional[list[str]] = None,
    timeout_s: int = 120,
    ssh_alias: Optional[str] = None,
    confirm_destructive: Optional[bool] = None,
    setup_commands: Optional[list[str]] = None,
    teardown_commands: Optional[list[str]] = None,
    setup_timeout_s: int = 60,
    teardown_timeout_s: int = 60,
) -> VerificationResult:
    """Run one verification cycle on the configured lab target.

    Sequence:
        setup_commands (in order, abort on first non-zero rc)
        ↓
        probe pre-snapshot + dmesg drain
        ↓
        trigger_command
        ↓
        probe post-snapshot + dmesg read
        ↓
        teardown_commands (always run, even on failure, for state
        restoration)

    `setup_commands` / `teardown_commands` let a verification plan
    declare its own preconditions (e.g., "remove this modprobe.d
    block + load the vulnerable module") and post-conditions (e.g.,
    "rmmod and re-apply the block") so the run is self-contained
    and reversible. The destructive-pattern gate fires on each
    command independently — operators see the explicit shell a
    plan will run before approving.

    State-transition heuristic:

    - any sanitizer-pattern match in dmesg → IMPACT_VERIFIED evidence
      (kernel instrumentation flagged the bug at the call site)
    - any probe-file content change → IMPACT_VERIFIED evidence (the
      bug's primitive was demonstrated end-to-end)
    - trigger ran with rc=0 and produced *no* file delta and *no*
      dmesg evidence → CONFIRMED only (PoC ran, side-effect not
      observed; could mean PoC parameter mismatch or already-patched
      kernel)
    - trigger ran with rc!=0 → unchanged Finding state, error logged

    `probe_paths` defaults to `[]` (dmesg-only mode). `dmesg_patterns`
    defaults to `DEFAULT_DMESG_PATTERNS`.

    `confirm_destructive` defaults to the lab_target config value;
    pass False to bypass (e.g., during a dry run that's known-safe).
    """
    cfg = load_config()
    lab: LabTargetConfig = cfg.lab_target
    alias = ssh_alias or lab.ssh_alias
    if not alias:
        raise RuntimeError(
            "verify_remote: no ssh_alias resolved. "
            "Set [lab_target].ssh_alias in config/argus.local.toml or pass ssh_alias=..."
        )

    if confirm_destructive is None:
        confirm_destructive = lab.require_confirm_destructive

    probe_paths = list(probe_paths or [])
    dmesg_patterns = tuple(dmesg_patterns or DEFAULT_DMESG_PATTERNS)
    setup_commands = list(setup_commands or [])
    teardown_commands = list(teardown_commands or [])

    started = datetime.now(timezone.utc)
    started_iso = started.isoformat()

    result = VerificationResult(
        started_at=started_iso,
        finished_at="",
        duration_s=0.0,
        ssh_alias=alias,
        trigger_command=trigger_command,
        probe_paths=probe_paths,
    )

    # 0. Setup commands. Abort cycle on first non-zero rc; teardown
    #    still runs for whatever state the partial setup left behind.
    for cmd in setup_commands:
        cr = _run_aux_command(alias, cmd, timeout_s=setup_timeout_s,
                              confirm_destructive=confirm_destructive)
        result.setup_results.append(cr)
        if cr.skipped_reason:
            result.setup_failed = True
            result.notes.append(f"setup skipped: {cr.command!r} ({cr.skipped_reason})")
            break
        if cr.timed_out or cr.returncode != 0:
            result.setup_failed = True
            result.notes.append(
                f"setup failed: {cr.command!r} rc={cr.returncode} "
                f"stderr={cr.stderr.strip()[:200]!r}"
            )
            break

    # If setup didn't fully succeed, mark the trigger as skipped and
    # only run teardown. This preserves audit clarity: the result shows
    # exactly which step failed.
    if result.setup_failed:
        result.trigger_skipped_reason = "setup_failed"
    else:
        # 1. Probe-file pre-snapshot
        pre_snaps: dict[str, FileSnapshot] = {
            p: _hash_remote_file(alias, p) for p in probe_paths
        }
        for p, snap in pre_snaps.items():
            if snap.error:
                result.notes.append(f"pre-snapshot error for {p}: {snap.error}")

        # 2. Drain dmesg
        drained, drain_method = _drain_dmesg(alias)
        result.dmesg_capture_method = (
            f"clear:{drain_method}+dmesg" if drained else "no-clear+dmesg"
        )
        if not drained:
            result.notes.append(
                "dmesg --clear unavailable (need NOPASSWD sudo); "
                "diff against prior content may include unrelated lines"
            )
        pre_dmesg = "" if drained else _read_dmesg(alias)

        # 3. Trigger gate (the trigger itself may match destructive pattern)
        if confirm_destructive and _looks_destructive(trigger_command):
            try:
                _confirm_or_abort(trigger_command, alias)
            except RuntimeError as e:
                result.trigger_skipped_reason = str(e)
                result.notes.append(f"trigger skipped: {e}")

        # 4. Run trigger (only if not skipped)
        if not result.trigger_skipped_reason:
            try:
                cp = _ssh(alias, trigger_command, timeout_s=timeout_s)
                result.trigger_returncode = cp.returncode
                result.trigger_stdout = cp.stdout
                result.trigger_stderr = cp.stderr
            except subprocess.TimeoutExpired as e:
                result.trigger_timed_out = True
                result.trigger_returncode = -1
                result.trigger_stdout = e.stdout or ""
                result.trigger_stderr = (e.stderr or "") + "\n[verify] trigger timed out"
                result.notes.append(f"trigger timed out after {timeout_s}s")

        # 5. Post-snapshot
        post_snaps: dict[str, FileSnapshot] = {
            p: _hash_remote_file(alias, p) for p in probe_paths
        }
        deltas: list[FileDelta] = []
        for p in probe_paths:
            deltas.append(_diff_snapshot(pre_snaps[p], post_snaps[p]))
        result.file_deltas = deltas
        result.any_file_changed = any(
            d.changed for d in deltas if d.delta_kind != "error"
        )

        # 6. dmesg post-read + diff
        post_dmesg = _read_dmesg(alias)
        if drained:
            new_lines = post_dmesg.splitlines()
        else:
            pre_set = set(pre_dmesg.splitlines())
            new_lines = [ln for ln in post_dmesg.splitlines() if ln not in pre_set]
        result.dmesg_new_lines = new_lines
        result.dmesg_matches = _match_dmesg(new_lines, dmesg_patterns)

    # 7. Teardown — always run, even on setup failure or trigger skip,
    #    so the lab is left in a known state. Failures are recorded
    #    but do not block verdict roll-up.
    for cmd in teardown_commands:
        cr = _run_aux_command(alias, cmd, timeout_s=teardown_timeout_s,
                              confirm_destructive=confirm_destructive)
        result.teardown_results.append(cr)
        if cr.skipped_reason:
            result.notes.append(f"teardown skipped: {cr.command!r} ({cr.skipped_reason})")
        elif cr.timed_out or cr.returncode != 0:
            result.notes.append(
                f"teardown step rc!=0: {cr.command!r} rc={cr.returncode} "
                f"stderr={cr.stderr.strip()[:200]!r}"
            )

    # 8. Verdict roll-up
    if result.setup_failed or result.trigger_skipped_reason:
        result.confirmed_evidence = False
        result.impact_verified_evidence = False
    else:
        result.impact_verified_evidence = (
            bool(result.dmesg_matches) or result.any_file_changed
        )
        result.confirmed_evidence = (
            (not result.trigger_timed_out and result.trigger_returncode == 0)
            or result.impact_verified_evidence
        )

    # 9. Finalise timing
    finished = datetime.now(timezone.utc)
    result.finished_at = finished.isoformat()
    result.duration_s = (finished - started).total_seconds()
    return result


def recommend_state(current: FindingState, vr: VerificationResult) -> Optional[FindingState]:
    """Pure helper: given a Finding's current state and a VerificationResult,
    suggest the target state.

    Returns None when no transition is recommended. Caller decides whether
    to act; this never mutates anything.

    Rules:

    - DETECTED + impact_verified_evidence → IMPACT_VERIFIED
      (state machine allows DETECTED → CONFIRMED → IMPACT_VERIFIED, so
      callers must apply two transitions if they want full audit trail.
      `verify/triage.py` does this.)
    - DETECTED + confirmed_evidence (only) → CONFIRMED
    - CONFIRMED + impact_verified_evidence → IMPACT_VERIFIED
    - IMPACT_PENDING + impact_verified_evidence → IMPACT_VERIFIED
    - All other current states: no transition
    """
    if vr.impact_verified_evidence:
        if current is FindingState.DETECTED:
            # Caller drives the two-step transition.
            return FindingState.IMPACT_VERIFIED
        if current is FindingState.CONFIRMED:
            return FindingState.IMPACT_VERIFIED
        if current is FindingState.IMPACT_PENDING:
            return FindingState.IMPACT_VERIFIED
        return None
    if vr.confirmed_evidence and current is FindingState.DETECTED:
        return FindingState.CONFIRMED
    return None


# ─────────────────────────────────────────────────────────────────
# CLI for ad-hoc operator use
# ─────────────────────────────────────────────────────────────────


def _cli() -> int:                                  # pragma: no cover
    import argparse
    ap = argparse.ArgumentParser(
        prog="verify.sanitizer",
        description="One Phase-4 verification cycle against the configured lab target.",
    )
    ap.add_argument("--trigger", required=True,
                    help="remote shell command to run as the trigger")
    ap.add_argument("--probe", action="append", default=[],
                    help="remote file path to hash before/after; repeatable")
    ap.add_argument("--setup", action="append", default=[],
                    help="remote command to run before the trigger; repeatable")
    ap.add_argument("--teardown", action="append", default=[],
                    help="remote command to run after the trigger (always); repeatable")
    ap.add_argument("--timeout", type=int, default=120,
                    help="seconds before the trigger is killed (default: 120)")
    ap.add_argument("--ssh-alias", default=None,
                    help="override the configured lab_target.ssh_alias")
    ap.add_argument("--no-confirm", action="store_true",
                    help="bypass the destructive-pattern confirmation gate")
    ap.add_argument("--out", default=None,
                    help="write the JSON result to this path; default stdout")
    args = ap.parse_args()

    vr = verify_remote(
        trigger_command=args.trigger,
        probe_paths=args.probe,
        setup_commands=args.setup,
        teardown_commands=args.teardown,
        timeout_s=args.timeout,
        ssh_alias=args.ssh_alias,
        confirm_destructive=not args.no_confirm,
    )
    out = vr.to_json(indent=2)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(f"[verify] wrote {args.out}", file=sys.stderr)
    else:
        sys.stdout.write(out + "\n")
    # Exit code: 0 on impact, 1 on confirmed-only, 2 on no-evidence/error
    if vr.impact_verified_evidence:
        return 0
    if vr.confirmed_evidence:
        return 1
    return 2


if __name__ == "__main__":                          # pragma: no cover
    raise SystemExit(_cli())
