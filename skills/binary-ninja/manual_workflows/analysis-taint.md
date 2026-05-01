# `analysis/taint.py` — Manual-Workflow Companion

## Purpose

Inter-procedural MLIL SSA forward propagation from sources (argv,
recv, fread, getenv, ...) to sinks (strcpy, system, fopen, printf,
malloc-class). Source / sink tables curated in
`heuristics/imports.py`. Emits `Finding` objects categorised by
sink class (buffer_overflow, format_string, command_injection,
path_traversal, sql_injection, alloc_size).

## Programmatic invocation

```python
from scripts.analysis import taint
findings = taint.analyze(session, binary=path, max_depth=2)
```

`max_depth` controls inter-procedural hops. Default 2 (one-hop
into callees). Raise for deeper recall, lower for tight scope.

## Manual workflow (Binary Ninja UI)

1. **Identify a tainted entry point.** Filter Symbols → Imports for
   one of the sources (e.g., `recv`, `read`, `fgets`, `getenv`,
   `argv` parameter to `main`). Cross-ref each.
2. **Open the calling function in MLIL SSA view.** `View →
   Linear → Medium Level IL (SSA)`. Locate the source call.
3. **Trace the SSA output variable.** Right-click the result of
   the source call → `Show All Cross-Refs` (or use the SSA
   variable's def-use chain in the side panel).
4. **Walk uses forward.** For each use:
   - If it's a sink call (one of `heuristics/imports.py:SINKS`) and
     the tainted variable is at the *dangerous-arg* index, this is
     a bug.
   - If it's an arithmetic or assignment op, follow the new SSA
     output forward.
   - If it's a call into another function, jump into that function
     and propagate the tainted parameter (the inter-proc hop).
5. **Stop conditions / decision points:**
   - **Sanitisation predicate:** an explicit check (`strlen <= N`,
     a regex / allow-list match) on the tainted value before the
     sink → no finding (Phase 1 detector misses this; manual catches
     it).
   - **Constant-folded branch:** taint is bounded by a compile-time
     constant on every reaching path → safe.
   - **Sink reached with tainted arg:** finding (manual confirms or
     contradicts the programmatic emission).

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/hw_stack_overflow_mechanics]]` — buffer-OF
  primitives at sink sites.
- `[[Memory/Knowledge/em_advanced_injection_variants]]` — format-
  string-as-leak primitive flagged by this detector.
- `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` — UB classes
  the alloc-size sink detects (CWE-190, CWE-680).

### Reference book chapters

- *Heavy Wizardry*, ch. 4 — stack-OF primitive structure.
- *Practical Binary Analysis*, ch. on data-flow analysis.

## Divergence policy

- **Sanitisation logic:** manual is authoritative. Programmatic
  Phase 1 has no path-sensitivity; sanitised paths produce FPs the
  operator must filter.
- **Inter-procedural depth:** programmatic is authoritative
  *up to* `max_depth`; for deeper chains the manual walk is the
  only reliable approach. Bump `max_depth` only when the FP rate
  on the corpus stays acceptable.
- **Indirect calls (function pointer / vtable):** require both to
  agree. Programmatic follows only resolved targets; manual is
  necessary for runtime-resolved call sites.
- **Pointer aliasing:** manual is authoritative. Programmatic
  treats SSA versions as identity; aliased flow (`q = p; sink(q)`)
  may not be tracked.

## Operator-validation checklist

- [ ] Run on `vulntest/tier1-single/stack-overflow/c/build/vuln` —
      expect 1 buffer_overflow finding at `greet:strcpy`.
- [ ] Run on `vulntest/tier1-single/format-string/c/build/vuln` —
      expect 1 format_string finding at `log_message:printf`.
- [ ] Run on `vulntest/tier1-single/command-injection/c/build/vuln` —
      expect 1 command_injection finding at `backup:system`.
- [ ] Substrate-coherence check on any emitted finding.
- [ ] FP-rate spot-check on `python.exe` — expect 0 findings (no
      CLI-arg-to-sink flow on the standard Python interpreter).
