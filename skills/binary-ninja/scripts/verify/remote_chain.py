"""Phase 4 — Windows-lab remote harness.

SSH-driven execution harness for Windows targets (HMDXIN). Parallel to
`sanitizer.py` (Linux / dmesg) and `local.py` (local subprocess) — same
`VerificationResult` output shape so the existing triage state machine
consumes it without modification.

Windows-specific adaptations vs. sanitizer.py:

- Commands route through PowerShell (base64-encoded to survive SSH quote
  layers). Raw SSH is available for simple one-liners that don't need PS.
- File probing: PowerShell Get-FileHash (SHA256) replaces sha256sum.
- "dmesg equivalent": Windows Event Log captured time-bounded pre/post via
  Get-WinEvent; stored in the existing dmesg_new_lines / dmesg_matches
  fields with dmesg_capture_method = "windows-evtlog:<log_name>".
- Defender status snapshot: Get-MpComputerStatus recorded in notes.
- Script upload: scp to a remote staging path before the trigger.
- Destructive gate: same _DESTRUCTIVE_PATTERNS logic as sanitizer.py,
  extended for Windows-specific destructive operations.

Plan JSON (mode: "windows_remote") adds:

  mode: "windows_remote"
  ssh_alias: "hmdxin"                  # or null → lab_target.ssh_alias
  ssh_key: null                         # null = SSH config handles it
  trigger:
    upload: "D:/local/path/poc.py"      # scp this before running
    remote_path: "C:/Users/Public/..."  # destination on Windows target
    command: "python C:/Users/Public/poc.py"
    timeout_s: 120
  defender_status: true                 # probe Get-MpComputerStatus
  event_log:
    log_name: "Microsoft-Windows-Windows Defender/Operational"
    max_events: 50
    levels: [2, 3]                      # 2=Error, 3=Warning, 4=Info
  crash_patterns: [...]                 # augment DEFAULT_WIN_PATTERNS

Verdict roll-up mirrors sanitizer.py:
  - CONFIRMED:       trigger ran without timeout (any rc)
  - IMPACT_VERIFIED: probe file appeared/changed + OR stdout pattern match
                     OR evtlog match after trigger.

Knowledge anchors:
  [[Memory/Knowledge/argus_detector_design_principles]] (§ Phase vocabulary)
  [[Memory/Knowledge/windows_defender_attack_surface]] (§ HMDXIN lab target)
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .sanitizer import (
    CommandResult,
    Evidence,
    FileDelta,
    FileSnapshot,
    VerificationResult,
)


# ── Constants ─────────────────────────────────────────────────────────────────

# Success and crash patterns matched against trigger stdout+stderr.
DEFAULT_WIN_PATTERNS: tuple[str, ...] = (
    r"\[\+\] EXPLOIT RAN",          # Argus PoC success marker
    r"REDSUN_SYSTEM_EXEC",          # RedSun payload marker
    r"UNDEFEND_DOS",                # UnDefend DoS marker
    r"Access violation",
    r"Stack overflow",
    r"Application Error",
    r"The process cannot access the file",
    r"STATUS_ACCESS_VIOLATION",
    r"STATUS_STACK_OVERFLOW",
)

# Windows event log patterns that indicate Defender or system impact.
DEFAULT_EVTLOG_PATTERNS: tuple[str, ...] = (
    r"update.*fail(ed)?",
    r"signature.*fail(ed)?",
    r"definition.*fail(ed)?",
    r"The Windows Defender.*failed",
    r"Windows Defender.*error",
    r"MpCmdRun",
    r"Error\s+\d+",
)

_WINDOWS_DESTRUCTIVE: tuple[str, ...] = (
    "Format-Volume",
    "Remove-Partition",
    "Clear-Disk",
    "Stop-Service MpsSvc",
    "Stop-Service WinDefend",
    "reg delete HKLM\\SYSTEM\\CurrentControlSet\\Services",
    "Remove-Item -Recurse -Force C:\\Windows\\",
    "sc delete ",
    "bcdedit /set",
)

_DEFAULT_EVENT_LOG = "Microsoft-Windows-Windows Defender/Operational"
_DEFAULT_SSH_TIMEOUT = 30


# ── SSH / PowerShell primitives ───────────────────────────────────────────────


def _ssh(alias: str, raw_cmd: str, *,
         key: Optional[str] = None,
         timeout_s: int = _DEFAULT_SSH_TIMEOUT) -> subprocess.CompletedProcess:
    """Raw SSH round-trip (BatchMode=yes, no password prompts).

    `raw_cmd` is passed directly to the remote shell (cmd.exe on Windows
    OpenSSH). Use _ps() when PowerShell is required.
    """
    args = ["ssh", "-o", "BatchMode=yes"]
    if key:
        args += ["-i", key]
    args += [alias, raw_cmd]
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout_s,
    )


def _ps(alias: str, ps_script: str, *,
        key: Optional[str] = None,
        timeout_s: int = _DEFAULT_SSH_TIMEOUT) -> subprocess.CompletedProcess:
    """Run a PowerShell script on the remote via SSH.

    Encodes the script as base64 UTF-16LE and passes it via
    -EncodedCommand — avoids quoting issues through the SSH pipe.
    """
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    cmd = f"powershell.exe -NonInteractive -EncodedCommand {encoded}"
    return _ssh(alias, cmd, key=key, timeout_s=timeout_s)


def _scp_upload(local_path: str, alias: str, remote_path: str, *,
                key: Optional[str] = None,
                timeout_s: int = 60) -> Optional[str]:
    """SCP a local file to the remote target.

    Returns None on success, or an error string on failure.
    """
    args = ["scp", "-o", "BatchMode=yes"]
    if key:
        args += ["-i", key]
    args += [local_path, f"{alias}:{remote_path}"]
    try:
        cp = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout_s,
        )
        if cp.returncode != 0:
            return f"scp rc={cp.returncode}: {cp.stderr.strip()[:200]}"
        return None
    except subprocess.TimeoutExpired:
        return "scp timed out"
    except FileNotFoundError:
        return "scp binary not found"


# ── Windows probing ───────────────────────────────────────────────────────────


def _hash_win_file(alias: str, remote_path: str, *,
                   key: Optional[str] = None,
                   timeout_s: int = 20) -> FileSnapshot:
    """SHA-256 probe of a Windows file via Get-FileHash.

    Returns FileSnapshot with present=False if the file is absent or
    the probe command fails.
    """
    ps = (
        f"if (Test-Path '{remote_path}') {{"
        f"  $h = Get-FileHash -Path '{remote_path}' -Algorithm SHA256;"
        f"  $s = (Get-Item '{remote_path}').Length;"
        f"  Write-Output \"PRESENT $s $($h.Hash.ToLower())\""
        f"}} else {{"
        f"  Write-Output 'ABSENT'"
        f"}}"
    )
    try:
        cp = _ps(alias, ps, key=key, timeout_s=timeout_s)
    except subprocess.TimeoutExpired:
        return FileSnapshot(path=remote_path, error="probe timeout")

    if cp.returncode != 0:
        return FileSnapshot(
            path=remote_path,
            error=f"probe rc={cp.returncode}: {cp.stderr.strip()[:200]}",
        )

    out = cp.stdout.strip()
    if not out or out.startswith("ABSENT"):
        return FileSnapshot(path=remote_path, present=False)

    parts = out.split()
    if len(parts) < 3 or parts[0] != "PRESENT":
        return FileSnapshot(path=remote_path, error=f"unexpected probe output: {out[:80]}")

    try:
        size = int(parts[1])
    except ValueError:
        size = -1

    return FileSnapshot(
        path=remote_path, sha256=parts[2], size_bytes=size, present=True,
    )


def _diff_snapshots(before: FileSnapshot, after: FileSnapshot) -> FileDelta:
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
    if before.sha256 != after.sha256 or before.size_bytes != after.size_bytes:
        kind = "content" if before.sha256 != after.sha256 else "size"
        return FileDelta(path=before.path, before=before, after=after,
                         changed=True, delta_kind=kind)
    return FileDelta(path=before.path, before=before, after=after,
                     changed=False, delta_kind="unchanged")


def _read_evtlog(alias: str, log_name: str, since_dt: datetime, *,
                 max_events: int = 50,
                 levels: Optional[list[int]] = None,
                 key: Optional[str] = None,
                 timeout_s: int = 30) -> list[str]:
    """Read Windows Event Log entries newer than since_dt.

    Returns one string per event: "<timestamp> <level>: <first-line-of-message>"

    Levels: 2=Error, 3=Warning, 4=Information (default: 2 and 3).
    """
    lvl_list = levels or [2, 3]
    lvl_str = ",".join(str(l) for l in lvl_list)
    since_str = since_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    ps = (
        f"$since = [DateTime]::Parse('{since_str}').ToUniversalTime();"
        f"try {{"
        f"  Get-WinEvent -FilterHashtable @{{LogName='{log_name}';"
        f"    StartTime=$since; Level={lvl_str}}} -MaxEvents {max_events}"
        f"    -ErrorAction SilentlyContinue"
        f"  | ForEach-Object {{"
        f"      $ts = $_.TimeCreated.ToString('o');"
        f"      $lvl = $_.LevelDisplayName;"
        f"      $msg = ($_.Message -split \"`n\")[0].Trim();"
        f"      \"$ts $lvl`: $msg\""
        f"  }}"
        f"}} catch {{}}"
    )
    try:
        cp = _ps(alias, ps, key=key, timeout_s=timeout_s)
    except subprocess.TimeoutExpired:
        return []

    if cp.returncode != 0:
        return []

    return [ln.strip() for ln in cp.stdout.splitlines() if ln.strip()]


def _match_evtlog(lines: list[str], patterns: tuple[str, ...]) -> list[dict]:
    matches: list[dict] = []
    compiled = [(p, re.compile(p, re.IGNORECASE)) for p in patterns]
    for line in lines:
        for pat_str, rx in compiled:
            if rx.search(line):
                matches.append({"pattern": pat_str, "line": line.rstrip()})
                break
    return matches


def _get_defender_status(alias: str, *,
                         key: Optional[str] = None,
                         timeout_s: int = 20) -> dict:
    """Snapshot Defender status via Get-MpComputerStatus → JSON."""
    ps = (
        "try {"
        "  Get-MpComputerStatus | Select-Object AMRunningMode,"
        "    AntivirusEnabled,AntivirusSignatureVersion,"
        "    AntivirusSignatureLastUpdated,RealTimeProtectionEnabled,"
        "    AntispywareEnabled,AMServiceEnabled | ConvertTo-Json -Compress"
        "} catch { Write-Output '{}' }"
    )
    try:
        cp = _ps(alias, ps, key=key, timeout_s=timeout_s)
    except subprocess.TimeoutExpired:
        return {"error": "timeout"}
    if cp.returncode != 0 or not cp.stdout.strip():
        return {"error": f"rc={cp.returncode}"}
    try:
        return json.loads(cp.stdout.strip())
    except json.JSONDecodeError:
        return {"raw": cp.stdout.strip()[:400]}


# ── Destructive gate ──────────────────────────────────────────────────────────


def _looks_destructive(cmd: str) -> bool:
    combined = _WINDOWS_DESTRUCTIVE + (
        "rmmod ", "mkfs", "dd if=", "shred ", "rm -rf /",
        "sudo rm ", "sudo dd ", "reboot", "shutdown",
    )
    return any(pat.lower() in cmd.lower() for pat in combined)


def _confirm_or_abort(cmd: str, alias: str) -> None:
    if os.environ.get("ARGUS_LAB_NOCONFIRM", "").strip():
        return
    sys.stderr.write(
        f"[remote_chain] destructive pattern matched; confirm to proceed.\n"
        f"  target: {alias}\n"
        f"  cmd:    {cmd}\n"
        f"Confirm? [y/N] "
    )
    sys.stderr.flush()
    reply = sys.stdin.readline().strip().lower()
    if not reply.startswith("y"):
        raise RuntimeError("verification aborted by operator")


# ── Aux command runner ────────────────────────────────────────────────────────


def _run_win_cmd(alias: str, cmd: str, *,
                 timeout_s: int,
                 key: Optional[str],
                 use_powershell: bool = True,
                 confirm_destructive: bool = True) -> CommandResult:
    """Run one auxiliary command on the Windows remote.

    Commands that start with 'powershell' or 'python' are routed through
    _ps(); everything else goes through _ssh() as raw cmd.exe input.
    """
    if confirm_destructive and _looks_destructive(cmd):
        try:
            _confirm_or_abort(cmd, alias)
        except RuntimeError as e:
            return CommandResult(
                command=cmd, returncode=-1, stdout="", stderr=str(e),
                duration_s=0.0, skipped_reason=str(e),
            )

    t = time.monotonic()
    try:
        if use_powershell and not cmd.lower().startswith(("cmd ", "cmd.exe")):
            # Treat as a PowerShell one-liner
            cp = _ps(alias, cmd, key=key, timeout_s=timeout_s)
        else:
            cp = _ssh(alias, cmd, key=key, timeout_s=timeout_s)
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
            stdout=e.stdout or "", stderr=(e.stderr or "") + "\n[remote_chain] timed out",
            duration_s=time.monotonic() - t, timed_out=True,
        )


# ── Public API ─────────────────────────────────────────────────────────────────


def verify_windows_remote(plan: dict, *,
                          win_patterns: Optional[tuple] = None,
                          evtlog_patterns: Optional[tuple] = None) -> VerificationResult:
    """Run one verification cycle on a Windows SSH target.

    Plan schema (windows_remote):

        {
          "name": "<run id>",
          "mode": "windows_remote",
          "ssh_alias": "hmdxin",           // null → ARGUS_LAB_SSH_ALIAS or "hmdxin"
          "ssh_key": null,                  // null → SSH config handles it

          "setup_commands": ["...PS..."],   // PowerShell; abort on first failure
          "trigger": {
            "command": "python C:/path/poc.py",
            "upload": "D:/local/poc.py",   // scp this first (optional)
            "remote_path": "C:/Users/Public/poc.py",
            "timeout_s": 120
          },
          "probes": ["C:/Users/Public/exploit_ran.txt"],
          "event_log": {
            "log_name": "Microsoft-Windows-Windows Defender/Operational",
            "max_events": 50,
            "levels": [2, 3]
          },
          "defender_status": true,
          "crash_patterns": [regex, ...],  // augment DEFAULT_WIN_PATTERNS
          "teardown_commands": [...]
        }

    Returns `VerificationResult` with Windows-specific fields stored in:
      dmesg_new_lines  → Event Log lines (post-trigger)
      dmesg_matches    → Event Log pattern matches
      dmesg_capture_method → "windows-evtlog:<log_name>"
    """
    if (plan.get("mode") or "windows_remote").lower() != "windows_remote":
        raise ValueError(
            f"verify_windows_remote invoked on plan with mode={plan.get('mode')!r}"
        )

    alias = (plan.get("ssh_alias")
             or os.environ.get("ARGUS_LAB_SSH_ALIAS", "")
             or "hmdxin")
    key: Optional[str] = plan.get("ssh_key") or None
    confirm_destructive: bool = plan.get("confirm_destructive", True)

    evtlog_cfg = plan.get("event_log") or {}
    evtlog_name = evtlog_cfg.get("log_name", _DEFAULT_EVENT_LOG)
    evtlog_max = int(evtlog_cfg.get("max_events", 50))
    evtlog_levels: list[int] = evtlog_cfg.get("levels", [2, 3])

    all_win_patterns = tuple(win_patterns or DEFAULT_WIN_PATTERNS)
    for extra in (plan.get("crash_patterns") or []):
        all_win_patterns = all_win_patterns + (extra,)

    all_evtlog_patterns = tuple(evtlog_patterns or DEFAULT_EVTLOG_PATTERNS)

    started_dt = datetime.now(timezone.utc)
    started_iso = started_dt.isoformat()
    t0 = time.time()

    result = VerificationResult(
        started_at=started_iso,
        finished_at="",
        duration_s=0.0,
        ssh_alias=alias,
        trigger_command=plan.get("trigger", {}).get("command", ""),
        probe_paths=list(plan.get("probes") or []),
        dmesg_capture_method=f"windows-evtlog:{evtlog_name}",
    )

    # 0 ── Defender status snapshot (pre-trigger)
    if plan.get("defender_status"):
        pre_def = _get_defender_status(alias, key=key)
        result.notes.append(
            f"defender_status_pre={json.dumps(pre_def, default=str)[:400]}"
        )

    # 1 ── Setup commands
    for cmd in plan.get("setup_commands", []) or []:
        cr = _run_win_cmd(alias, cmd, timeout_s=60, key=key,
                          confirm_destructive=confirm_destructive)
        result.setup_results.append(cr)
        if cr.skipped_reason:
            result.setup_failed = True
            result.notes.append(f"setup skipped: {cmd!r} ({cr.skipped_reason})")
            break
        if cr.timed_out or cr.returncode != 0:
            result.setup_failed = True
            result.notes.append(
                f"setup failed: {cmd!r} rc={cr.returncode} "
                f"stderr={cr.stderr.strip()[:200]!r}"
            )
            break

    if result.setup_failed:
        result.trigger_skipped_reason = "setup_failed"
    else:
        # 2 ── Pre-snapshots
        probe_paths = list(plan.get("probes") or [])
        pre_snaps: dict[str, FileSnapshot] = {
            p: _hash_win_file(alias, p, key=key) for p in probe_paths
        }
        for p, snap in pre_snaps.items():
            if snap.error:
                result.notes.append(f"pre-snapshot error for {p}: {snap.error}")

        # 3 ── Event-log baseline timestamp (just before trigger)
        evtlog_since = datetime.now(timezone.utc)

        # 4 ── SCP upload (if trigger.upload is specified)
        trigger_cfg = plan.get("trigger") or {}
        upload_local = trigger_cfg.get("upload")
        upload_remote = trigger_cfg.get("remote_path")
        if upload_local and upload_remote:
            err = _scp_upload(upload_local, alias, upload_remote, key=key)
            if err:
                result.notes.append(f"scp upload failed: {err}")
                result.setup_failed = True
                result.trigger_skipped_reason = "scp_upload_failed"

        # 5 ── Trigger
        trigger_cmd = trigger_cfg.get("command", "")
        trigger_timeout = int(trigger_cfg.get("timeout_s", 120))

        if not result.trigger_skipped_reason:
            if confirm_destructive and _looks_destructive(trigger_cmd):
                try:
                    _confirm_or_abort(trigger_cmd, alias)
                except RuntimeError as e:
                    result.trigger_skipped_reason = str(e)
                    result.notes.append(f"trigger skipped: {e}")

        if not result.trigger_skipped_reason:
            t_start = time.monotonic()
            try:
                # Trigger runs as a raw SSH command — the PoC script's own
                # shebang / python invocation handles the PowerShell context.
                cp = _ssh(alias, trigger_cmd, key=key, timeout_s=trigger_timeout)
                result.trigger_returncode = cp.returncode
                result.trigger_stdout = cp.stdout
                result.trigger_stderr = cp.stderr
            except subprocess.TimeoutExpired as e:
                result.trigger_timed_out = True
                result.trigger_returncode = -1
                result.trigger_stdout = e.stdout or ""
                result.trigger_stderr = (e.stderr or "") + "\n[remote_chain] trigger timed out"
                result.notes.append(f"trigger timed out after {trigger_timeout}s")

        # 6 ── Post-snapshots
        post_snaps: dict[str, FileSnapshot] = {
            p: _hash_win_file(alias, p, key=key) for p in probe_paths
        }
        deltas = [
            _diff_snapshots(pre_snaps[p], post_snaps[p]) for p in probe_paths
        ]
        result.file_deltas = deltas
        result.any_file_changed = any(
            d.changed for d in deltas if d.delta_kind != "error"
        )

        # 7 ── Event log (post-trigger — time-bounded to post-evtlog_since)
        evtlog_lines = _read_evtlog(
            alias, evtlog_name, evtlog_since,
            max_events=evtlog_max, levels=evtlog_levels, key=key,
        )
        result.dmesg_new_lines = evtlog_lines
        result.dmesg_matches = _match_evtlog(evtlog_lines, all_evtlog_patterns)

        # 8 ── Stdout/stderr pattern matching
        combined_out = (result.trigger_stdout or "") + "\n" + (result.trigger_stderr or "")
        for pat in all_win_patterns:
            try:
                for m in re.finditer(pat, combined_out, re.IGNORECASE):
                    result.dmesg_matches.append({
                        "pattern": pat,
                        "match": m.group(0)[:160],
                        "source": "stdout",
                    })
            except re.error:
                continue

    # 9 ── Teardown (always run)
    for cmd in plan.get("teardown_commands", []) or []:
        cr = _run_win_cmd(alias, cmd, timeout_s=60, key=key,
                          confirm_destructive=confirm_destructive)
        result.teardown_results.append(cr)
        if cr.skipped_reason:
            result.notes.append(f"teardown skipped: {cmd!r} ({cr.skipped_reason})")
        elif cr.timed_out or cr.returncode != 0:
            result.notes.append(
                f"teardown rc!=0: {cmd!r} rc={cr.returncode} "
                f"stderr={cr.stderr.strip()[:200]!r}"
            )

    # 10 ── Defender status (post-trigger)
    if plan.get("defender_status") and not result.setup_failed:
        post_def = _get_defender_status(alias, key=key)
        result.notes.append(
            f"defender_status_post={json.dumps(post_def, default=str)[:400]}"
        )

    # 11 ── Verdict roll-up
    if result.setup_failed or result.trigger_skipped_reason:
        result.confirmed_evidence = False
        result.impact_verified_evidence = False
    else:
        result.impact_verified_evidence = (
            result.any_file_changed or bool(result.dmesg_matches)
        )
        result.confirmed_evidence = (
            not result.trigger_timed_out
            or result.impact_verified_evidence
        )

    result.finished_at = datetime.now(timezone.utc).isoformat()
    result.duration_s = round(time.time() - t0, 3)
    return result


def verify_chain_poc_on_windows(
    poc_local_path: str,
    *,
    ssh_alias: str = "hmdxin",
    ssh_key: Optional[str] = None,
    remote_staging_dir: str = r"C:\Users\Public\argus_verify",
    probe_files: Optional[list[str]] = None,
    timeout_s: int = 180,
    teardown: bool = True,
    defender_status: bool = True,
) -> VerificationResult:
    """Convenience wrapper: SCP a chain PoC to HMDXIN and run it.

    Puts the PoC at `remote_staging_dir/<basename>`, runs it via
    `python <remote_path>`, and cleans up on exit (unless teardown=False).

    Returns the VerificationResult for triage state-machine consumption.
    """
    poc_path = Path(poc_local_path)
    remote_path = remote_staging_dir.rstrip("\\/") + "\\" + poc_path.name

    plan: dict = {
        "name": f"chain_poc:{poc_path.stem}",
        "mode": "windows_remote",
        "ssh_alias": ssh_alias,
        "ssh_key": ssh_key,
        "setup_commands": [
            f"New-Item -ItemType Directory -Force -Path '{remote_staging_dir}' | Out-Null"
        ],
        "trigger": {
            "command": f"python {remote_path}",
            "upload": str(poc_local_path),
            "remote_path": remote_path,
            "timeout_s": timeout_s,
        },
        "probes": list(probe_files or []),
        "event_log": {
            "log_name": _DEFAULT_EVENT_LOG,
            "max_events": 50,
            "levels": [2, 3],
        },
        "defender_status": defender_status,
        "teardown_commands": (
            [f"Remove-Item -Force -ErrorAction SilentlyContinue '{remote_path}'"]
            if teardown else []
        ),
    }
    return verify_windows_remote(plan)


__all__ = [
    "DEFAULT_WIN_PATTERNS",
    "DEFAULT_EVTLOG_PATTERNS",
    "verify_windows_remote",
    "verify_chain_poc_on_windows",
]
