# `analysis/cleanup_dominance.py` — Manual-Workflow Companion

## Purpose

Detects functions that perform a data commit but do not import any
matching rollback API. Distinct from `pre_verification_write`
(which adds the order constraint — commit-before-verify); both can
co-fire on the canonical EAC pattern.

Emits `missing_cleanup_on_failure`.

## Detector character

- **v1 (current, coarse-recall):** structural — commit-class import
  present + no rollback-class import in function call set. Documented
  v1 FP class: fires on routine file-write binaries (notepad, reg,
  sc, cmd) that write but don't delete by design.
- **v2 (planned):** verify-call-presence gate — emit only when the
  function has a commit + no rollback + verify call elsewhere
  (suggesting an EAC-class shape rather than benign no-cleanup).

## Programmatic invocation

```bash
python -m scripts.analysis.cleanup_dominance --binary <path>
```

## Manual workflow (Binary Ninja UI)

1. Open binary; settle analysis.
2. **Imports panel:** locate commit APIs (`WriteFile`, `write`, etc.).
3. **For each commit-using function:** check if it imports any
   rollback API for the matching resource class — `DeleteFileW` /
   `MoveFileExW` / POSIX `unlink` for filesystem commits.
4. **Confirm absence is meaningful:** does the function have an
   error-return path where the commit's effects would persist? If
   yes, missing rollback is a real concern. If no (e.g., the
   function's contract is "write file, return success/fail to
   caller for caller-managed cleanup"), the missing rollback is
   delegated, not absent.
5. **Stop conditions:**
   - Commit + no rollback + error-return path AND function looks
     security-relevant → finding is real.
   - Same shape on a benign utility (notepad, file copy) → v1 FP.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — the
  canonical missing-cleanup pattern in EAC.
- `[[Memory/Knowledge/argus_detector_design_principles]]` — the
  layered "high-recall + high-precision" pairing pattern this
  module participates in (paired with `integrity_check_order` v3
  / v4 for precision).

## Divergence policy

- **Manual authoritative for:** all cases until v2. The v1
  detector intentionally over-reports; human review classifies
  each finding as EAC-class vs benign. Treat findings as
  "candidates for further review" rather than confirmed bugs.
- **Programmatic authoritative for:** the structural shape itself
  — if the detector says no rollback API is imported, that's a
  reliable mechanical claim.

## Known v1 FP classes

Documented from the 2026-05-07 clean-corpus sweep:

- **File-write utilities:** notepad (saves files), reg (writes
  registry exports), sc (writes service config), cmd (general
  shell). All commit-without-cleanup by design — the OS cleans
  up via process-exit / user delete, not in-function rollback.
  v2 verify-call gate will suppress these.

## Operator-validation checklist

- [ ] `vulntest/tier2-chains/eac-permissive-prewrite-cleanup-cache/c/`
      — fires twice (one per WriteFile call site) alongside
      `pre_verification_write`.
- [ ] Clean-corpus sweep — 12 findings across notepad/reg/sc/cmd,
      documented as v1 FPs in `TESTING.md`. v2 fix tracked at
      `docs/PROGRESSION.md` Tier 1.3.
- [ ] Substrate-coherence: `jm associate "missing cleanup on
      failure EAC"` surfaces the cited EAC entry.
