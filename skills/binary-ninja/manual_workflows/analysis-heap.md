# `analysis/heap.py` — Manual-Workflow Companion

## Purpose

Detects four heap-pattern classes:
- **Use-after-free** — same SSA var used after a free callsite
- **Double-free** — same SSA var passed to ≥ 2 free callsites
- **Heap buffer overflow** — copy whose dst is a malloc handle and
  whose length argument is not the same SSA var as the alloc size
- **Unchecked allocation** — alloc returns whose first use isn't
  a comparison against zero (null-deref candidate)

Allocator / free / copy tables in `heuristics/imports.py`.

## Programmatic invocation

```python
from scripts.analysis import heap
findings = heap.analyze(session, binary=path)
```

## Manual workflow (Binary Ninja UI)

1. **Imports → `free` (and `HeapFree`, `RtlFreeHeap`,
   `operator delete`).** Cross-ref each callsite.
2. **For UAF:**
   - In MLIL SSA view at each free callsite, identify the freed
     pointer's SSA variable.
   - Check the SSA variable's uses (`get_ssa_var_uses` in the side
     panel). If any use after the free address is on a reachable
     path from the free, it's a UAF candidate.
   - Confirm by walking control-flow: the free site dominates the
     use site, no intervening reassignment to the SSA name.
3. **For double-free:**
   - Same as UAF but the suspect uses are themselves free callsites.
4. **For heap-OF:**
   - Imports → `malloc` / `calloc` / `HeapAlloc` / `operator new`.
   - At each callsite, the returned SSA var is the alloc handle.
   - Imports → `memcpy` / `strcpy` / `memmove`. Cross-ref each.
   - For each copy callsite where dst is an alloc handle (or a
     downstream SSA version), inspect the length argument. If the
     length SSA var ≠ alloc-size SSA var (or copy is unbounded
     like strcpy), heap-OF candidate.
5. **For unchecked alloc:**
   - At each malloc-class callsite, look at the immediate-next use
     of the returned pointer in the function. If the next use is
     not a comparison-against-zero (CMP/CONST), null-deref candidate.
6. **Decision points:**
   - Reassignment between free and use → no UAF (the SSA version
     changed; programmatic catches this; manual confirms).
   - Length argument has a clamp / check on the path → no heap-OF.
   - Null check exists in a different function or via a wrapper
     → not unchecked-alloc (programmatic Phase 1 misses; manual
     catches).

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/wnapi_heap_internals]]` — Win LFH chunk
  layout, freelist invariants, the metadata fields each class
  corrupts.
- `[[Memory/Knowledge/em_advanced_injection_variants]]` — UAF as
  injection primitive.

### Reference book chapters

- *Windows Native API Programming* — heap chapter.
- *Heavy Wizardry* — heap exploitation primitives.
- glibc malloc internals (Phantasmal Phantasmagoria's papers,
  Shellphish's how2heap).

## Divergence policy

- **Pointer aliasing:** manual is authoritative. Programmatic
  Phase 1 tracks SSA versions only; aliased frees (`q = p; free(p);
  use(q)`) are missed.
- **Loop-carried bugs:** require both to agree. Loops produce both
  FPs and FNs in programmatic; manual catches them but is slower.
- **Null check in wrapper / different function:** manual is
  authoritative. Programmatic Phase 1 doesn't follow into wrapper
  helpers for null checks.
- **Constant-folded length:** programmatic is authoritative — when
  the length is a compile-time constant equal to alloc size, no
  finding. Manual eyeballing can mistake constants.

## Operator-validation checklist

- [ ] Run on `vulntest/tier1-single/use-after-free/c/build/vuln-asan` —
      expect 1 use_after_free finding at the dangling read.
- [ ] Run on `vulntest/tier1-single/double-free/c/build/vuln-asan` —
      expect 1 double_free finding (and possibly the UAF that
      precedes it).
- [ ] Run on `vulntest/tier1-single/heap-overflow/c/build/vuln-asan` —
      expect 1 heap_buffer_overflow finding at the memcpy.
- [ ] Substrate-coherence check.
- [ ] FP-rate spot-check on `python.exe` — expect 0 findings.
