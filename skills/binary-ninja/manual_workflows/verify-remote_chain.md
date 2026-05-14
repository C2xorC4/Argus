# `verify/remote_chain.py` — Manual-Workflow Companion

## Purpose

Phase 4 Windows-lab execution harness. SSH-driven PoC runner for the
HMDXIN target, parallel to `sanitizer.py` (Linux) and `local.py` (local
subprocess). Produces the same `VerificationResult` output shape consumed
by the triage state machine.

Key Windows-specific adaptations vs. `sanitizer.py`:

- Commands route through PowerShell (base64-encoded to survive SSH quote
  layers).
- File-integrity probe: `Get-FileHash` (SHA256) replaces `sha256sum`.
- Event Log capture: time-bounded pre/post via `Get-WinEvent`; stored in
  `dmesg_new_lines` / `dmesg_matches` with
  `dmesg_capture_method = "windows-evtlog:<log_name>"`.
- Defender status snapshot: `Get-MpComputerStatus` recorded in notes.
- Script upload: `scp` to staging path before trigger.

Verdict roll-up (same gate definitions as `sanitizer.py`):

- `CONFIRMED` — trigger ran without timeout (any exit code).
- `IMPACT_VERIFIED` — probe file appeared/changed, OR stdout pattern
  matched, OR Event Log entry matched after trigger.

## Programmatic invocation

```python
# plan.json (mode: "windows_remote")
{
  "mode": "windows_remote",
  "ssh_alias": "hmdxin",
  "trigger": {
    "upload": "D:/Repos/Security/NightmareEclipse/_poc/bluehammer_poc.py",
    "remote_path": "C:/Users/Public/bluehammer_poc.py",
    "command": "python C:/Users/Public/bluehammer_poc.py",
    "timeout_s": 120
  },
  "defender_status": true,
  "event_log": {
    "log_name": "Microsoft-Windows-Windows Defender/Operational",
    "max_events": 50,
    "levels": [2, 3]
  }
}
```

```bash
python -m scripts.verify.remote_chain --plan plan.json
```

Or via the NightmareEclipse harness:

```bash
python NightmareEclipse/run_sections_7_9.py --ssh hmdxin
```

## Manual workflow

Remote chain verification has no Binja UI component — it is a shell
execution step. The manual workflow is the pre-run checklist:

1. **SSH connectivity.** Confirm `C:\Windows\System32\OpenSSH\ssh.exe`
   (not Git Bash `ssh`) is in PATH for the session. The mcp-binja
   ED25519 key has a documented incompatibility with the Git Bash libcrypto
   build — always use the system OpenSSH binary.

2. **HMDXIN authorization gate.** HMDXIN is authorized for destructive
   Windows testing; worst-case is a reinstall. Confirm the PoC is a
   NightmareEclipse / BlueHammer / RedSun / UnDefend-class payload before
   remote execution. Do not use HMDXIN for primary-workstation-sensitive
   tests.

3. **Pre-run state capture.** For probed-file tests: record the target
   file's SHA256 before trigger. For Event Log tests: record the most
   recent event ID in the target log before trigger. `remote_chain.py`
   does this automatically via `_pre_trigger_snapshot`.

4. **Trigger and observe.** Watch for:
   - Exit code 0 + probe file changed → `IMPACT_VERIFIED`.
   - Exit code non-zero + expected error string in stdout → `CONFIRMED`
     (patch mitigation documented).
   - Timeout → retry with larger `timeout_s` or investigate hang (may
     indicate stall primitive fired but release not triggered).

5. **Post-run triage.** Check `result.event_log_matches` for Defender
   operational events (error level 2/3 during update or scan). A
   `dmesg_matches` entry naming `MpUpdateEngineSignature` at error level
   confirms the RPC call reached the Defender handler.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/windows_defender_attack_surface]]` — HMDXIN lab
  target, SSH alias, BlueHammer/RedSun/UnDefend chain specifications.
- `[[Memory/Knowledge/argus_detector_design_principles]]` — CONFIRMED →
  IMPACT_PENDING → IMPACT_VERIFIED gate definitions.

## Divergence policy

- **Programmatic authoritative for:** SSH command routing, base64
  encoding, Event Log capture, SHA256 file-hash comparison, verdict
  roll-up logic.
- **Manual authoritative for:** interpreting ambiguous results —
  e.g., a non-zero exit code that is a known-benign Windows error
  code (0xC0000005 is a crash, not a successful exploit; 0x80070005
  is Access Denied, which may indicate the patch closed the window).
- **Both must agree for:** the `IMPACT_VERIFIED` verdict. Programmatic
  gate fires on probe-file change OR Event Log match. If neither fires
  but the operator has out-of-band evidence (e.g., SYSTEM shell obtained
  interactively), update the plan JSON to add the appropriate probe
  condition and re-run before marking `IMPACT_VERIFIED`.

## Operator-validation checklist

- [ ] `ssh hmdxin echo ok` returns `ok` via
      `C:\Windows\System32\OpenSSH\ssh.exe`.
- [ ] UnDefend PoC on HMDXIN: `IMPACT_VERIFIED` — Defender definition-
      update failure in Event Log during run; clean resume after exit.
- [ ] BlueHammer PoC (post-patch HMDXIN): `CONFIRMED` with patch
      mitigation documented; probe file not changed.
- [ ] RedSun IMPACT_VERIFIED: requires Cloud Files placeholder step
      (`cloudfiles_primitive.py`) — deferred from 2026-05-14 session.
