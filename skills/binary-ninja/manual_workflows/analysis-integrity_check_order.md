# `analysis/integrity_check_order.py` — Manual-Workflow Companion

## Purpose

Detects the canonical "commit-before-verify with no rollback" CFG
shape: a function performs a data commit (writes attacker-supplied
bytes to a file or allocates and fills a buffer) BEFORE running an
integrity check, AND the failure branch of the check does not roll
back the write. The committed data persists when verification fails,
giving an attacker a primitive for poisoning trusted state.

Emits `pre_verification_write`. Canonical real-world example: the
EAC EOS arbitrary-write chain (Sub 01) — `WriteFile` to a
SYSTEM-trusted path before `WinVerifyTrust` runs, no `DeleteFileW`
on the verify-fail label.

## Detector revisions

- **v1** — function-level: commit + has-conditional + no rollback
  import. High-recall, FP-prone.
- **v2** — added `_rollback_dominates_all_exits_after_commit`
  CFG-dominance check on rollback APIs.
- **v3** — added `_scan_verify_calls` order check: if a verify-
  flavoured call dominates the commit, suppress (verify-then-write
  is safe).
- **v4 (current, 2026-05-07)** — also requires SOME verify-
  flavoured call to exist in the function. Without any verify call,
  the bug isn't "wrong order" — it's "no cleanup," which is
  `cleanup_dominance`'s job. Closes 13 FPs on the clean-corpus
  sweep (reg/sc/cmd/notepad).

## Programmatic invocation

```bash
python -m scripts.analysis.integrity_check_order \
    --binary <path-to-target.exe>
```

Or via `dev/validate.py` / `vulntest/runner.py`.

## Manual workflow (Binary Ninja UI)

1. Open binary; wait for analysis.
2. **Imports panel:** identify commit APIs (`WriteFile`,
   `WriteFileEx`, `NtWriteFile`, POSIX `write`/`pwrite`).
3. **Each commit call site:** in HLIL, walk the containing function
   and identify:
   - Verify call (e.g., `WinVerifyTrust`, custom `verify_payload`,
     hash-compare via `memcmp` after a `BCryptHashData` block).
   - Rollback call (`DeleteFileW`, POSIX `unlink`, or
     `MoveFileEx` to a backup name).
4. **CFG inspection:** does the rollback dominate every return
   reachable from the commit? If yes → safe. Does the verify
   dominate the commit? If yes → safe (verify-first pattern).
5. **Stop conditions:**
   - Commit + verify-AFTER-commit + no rollback dominance →
     `pre_verification_write` fires.
   - No verify call anywhere in the function → suppress (this
     module's territory ends).
   - Verify dominates commit → suppress (verify-first is correct).

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — canonical
  pattern (EAC EOS Component 2).
- `[[Memory/Knowledge/argus_detector_design_principles]]` —
  `commit-before-validate` is one of the locked-in CFG primitives
  shared across heap-OF and write-then-verify detectors.

### Reference book chapters

- *Effective C*, ch. on signal and resource cleanup — broader
  context on cleanup-on-failure as a structural concern.

## Divergence policy

- **Programmatic authoritative for:** the structural CFG check
  (commit / verify / rollback dominance). The v4 fix specifically
  closes a class of FPs that human review would also miss.
- **Manual authoritative for:** patterns where the verify is in a
  different function reached via a function pointer the programmatic
  detector can't resolve. Human-reviewable, programmatically opaque.
- **Both must agree for:** novel cleanup APIs. The
  `_ROLLBACK_BY_RESOURCE` table needs explicit entries; new resource
  classes (e.g., MMIO commits, registry transactions) need both
  module and review to confirm the rollback set is complete.

## Operator-validation checklist

- [ ] `vulntest/tier1-single/pre-verify-write/c/` — vuln binary
      fires, remediation (verify-first) silent.
- [ ] `vulntest/tier2-chains/eac-permissive-prewrite-cleanup-cache/c/`
      — fires alongside `permissive_sddl`, `missing_cleanup_on_failure`,
      `trusted_path_cache_load`, `chain_pattern`.
- [ ] Clean-corpus sweep — gate-2 CLEAN as of 2026-05-07 (0 FPs
      across 15 Windows binaries after v4 fix).
- [ ] Substrate-coherence: `jm associate "pre_verification_write
      EAC arbitrary write"` surfaces the EAC chain Knowledge entry.
