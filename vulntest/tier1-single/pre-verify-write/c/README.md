# Pre-verification write with no cleanup — C / Windows

## Brief

The privileged service `WriteFile`s attacker-supplied bytes to the
target path, *then* runs verification. On verification failure, the
function returns — but the file remains on disk with the
attacker's content. Downstream code (or a future privileged read,
or a cache-loader process) trusts the path because the privileged
service touched it.

This is the canonical EAC EOS chain primitive: the privileged
service was supposed to be the only writer to the directory, so
downstream code skipped re-validation. Pre-verification write +
missing cleanup violated that invariant.

**Difficulty:** `1.0.0`.

## Detection

Detector: `scripts/analysis/chains.py`. Pattern:

- `WriteFile` / `fwrite` / `WriteProcessMemory` to a path-derived
  handle.
- Subsequent verification call (hash compare, signature check,
  schema parse) on the same path.
- Verification-failure branch lacks `DeleteFileW` /
  `MoveFileExW(MOVEFILE_DELAY_UNTIL_REBOOT)` / equivalent cleanup.

The "no cleanup" check is an absence-test: the failure-branch BB
(basic block) does not call any deletion API. False positives where
cleanup happens via a finalizer or RAII wrapper need additional
analysis (vtable lookups, destructor inspection).

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Imports → `WriteFile` and a verification helper.**
2. **HLIL of caller.** Confirm WriteFile precedes the verification
   conditional.
3. **Inspect failure branch.** Returns / continues without
   `DeleteFileW`.

## Reference

- LJM: `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` —
  the canonical real-world manifestation.

## Exploitation

**Primitive class:** trusted-path write on verification failure.

## Chain potential

- [`Permissive SDDL → pre-verify-write → missing cleanup → cache poison`](../../../tier2-chains/) —
  the EAC chain.

## Remediation

```c
// before
WriteFile(h, attacker_bytes, ...);
CloseHandle(h);
if (!verify(...)) return 1;          // file persists

// after — verify input before write
if (!verify_bytes(attacker_bytes)) return 1;
WriteFile(h, attacker_bytes, ...);

// or — write-to-staging, atomic rename on verify success
WriteFile(staging_h, attacker_bytes, ...);
CloseHandle(staging_h);
if (!verify_path(staging_path)) {
    DeleteFileW(staging_path);
    return 1;
}
MoveFileExW(staging_path, target_path, MOVEFILE_REPLACE_EXISTING);
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Privileged services do not commit attacker-influenceable bytes to
trusted-write paths. Either verify the input before writing or use
a staging-and-rename pattern. Code review template: every
write-then-check pair must have an explicit cleanup branch.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags WriteFile-then-verify-no-cleanup pattern
- [ ] PoC confirms the file persists after verification failure
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
