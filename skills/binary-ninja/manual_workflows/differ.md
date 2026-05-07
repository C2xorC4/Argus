# `differ/` — Manual-Workflow Companion

## Purpose

Phase 5 cross-cutting — binary-diff workflow for 1-day analysis
and Patch-Tuesday work. Compares two BinaryViews (typically pre-
patch / post-patch of the same module) and emits a typed diff
describing what changed.

Skeleton in this revision: data shapes + entry-point API. Full
implementation (byte / HLIL / callgraph / string diff) deferred to
a future Phase 5 build-out.

## Public API

```python
from scripts.differ import diff, BinaryDiff, FunctionDelta

bd = diff(bv_a, bv_b, binary_a="pre.exe", binary_b="post.exe")
print(bd.summary)
# {'functions': {'added': N, 'removed': N, 'modified': N},
#  'strings':   {'added': N, 'removed': N},
#  'imports':   {'added': N, 'removed': N}}
```

The skeleton returns a `BinaryDiff` with empty delta lists; real
implementations populate via the deferred submodules
(`byte_diff`, `hlil_diff`, `callgraph_diff`, `string_diff`,
`fix_patterns`).

## Manual workflow (Binary Ninja UI)

1. Open both binaries side-by-side in two Binja instances.
2. **Function-level diff:** compare function counts; identify
   added / removed functions by name.
3. **String-table diff:** strings changed between revisions often
   reveal security-fix changes (new error messages, hardened
   format strings, removed debug-only paths).
4. **Import diff:** new imports of mitigation APIs (e.g., post-
   patch newly imports `BCryptVerifySignature`) often flag where
   the fix landed.
5. **HLIL diff at suspect functions:** for each function the
   high-level diff flags as modified, decompile both versions and
   identify the semantic change. Bounds check tightening, new
   verify call before commit, added cleanup on the fail label
   are all common shapes.
6. **Stop conditions:**
   - Modified function with security-relevant API changes →
     candidate for 1-day exploit.
   - Modified function with refactoring / cosmetic changes only →
     drop.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — example
  of a fix-pattern (added cleanup on verify-fail) the diff
  detector should recognise.

### Reference book chapters

- *Practical Binary Analysis* — chapters on binary diffing.

## Divergence policy

- **Programmatic authoritative for:** byte / function / string /
  import deltas (mechanical comparisons).
- **Manual authoritative for:** semantic interpretation of HLIL
  changes — what the code now does that it didn't do before, and
  why. The diff catalog tells you WHERE to look; the security
  analysis still needs human judgement.

## Operator-validation checklist

- [ ] `diff(bv_a, bv_b)` returns a `BinaryDiff` skeleton without
      raising.
- [ ] When real submodules land: function-delta count matches
      naive bsdiff function-by-function comparison.
- [ ] Fix-pattern matcher (future) recognises EAC-class
      "verify-then-write reorder" as a known security fix.
