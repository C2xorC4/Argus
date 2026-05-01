# Use-after-free — C variant

## Brief

Classic lifetime-tracking error. `session_close()` frees the global
`g_session` pointer but does not null it. A subsequent `session_log()`
sees the (still non-null) pointer, passes the null-check guard, and
dereferences the dangling memory.

UAF is the most-exploited memory-safety class in modern offense
because the freed chunk's contents are attacker-influenceable
(through subsequent allocations of similar size on the same
freelist).

**Difficulty:** `1.0.0`.

## Build

```bash
make           # standard
make asan      # ASan-instrumented build
```

## Detection

### Programmatic

Detector: `scripts/analysis/heap.py`. Pattern: free-site followed by
a use-site of the same pointer / global, where no intervening
assignment to NULL or reassignment exists on any feasible path.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Imports → `free`.** Cross-ref to `session_close`.
2. **Inspect `session_close`.** `free(g_session)` then function
   returns — no zeroing.
3. **Cross-ref `g_session`.** Read in `session_log` after the
   `free` site is reachable.
4. **Decision point.** Read of pointer that was freed on a feasible
   path with no clearing.

### Reference

- LJM: `[[Memory/Knowledge/wnapi_heap_internals]]` — Windows LFH
  freelist behaviour after free; how reuse positions attacker bytes
  at the dangling pointer.
- LJM: `[[Memory/Knowledge/em_advanced_injection_variants]]` — UAF
  as injection primitive.

## Exploitation

**Primitive class:** UAF read/write → controlled-content dereference.

**Mitigation considerations.**

- **glibc `MALLOC_CHECK_=3`** — catches double-free / heap
  corruption at runtime; doesn't directly catch UAF read but
  hardens against follow-on chunk-corruption exploits.
- **Windows Type Isolation Heap** — UAF read of one type's chunk
  cannot return another type's bytes; targets browsers, drivers.
- **GuardedHeap (Win10+)** — page-granularity quarantine; freed
  pages are unmapped. UAF triggers AV.
- **MarkUs / GC-style heap** — defers free until no live pointers.
  Defeats UAF but at memory cost.

## Chain potential

- [`info-leak → UAF → ROP`](../../../tier2-chains/) — heap leak
  positions attacker content at the dangling chunk; UAF call-site
  becomes controlled function pointer or vtable.

## Remediation

```c
// before
free(g_session);

// after
free(g_session);
g_session = NULL;
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Compiler / linker mitigations

- ASan / HWASan — runtime detection.
- Static analysis: clang-tidy `bugprone-use-after-move`, GCC's
  `-Wuse-after-free`, Microsoft's SDV.

### Architectural fix

Project-wide pattern: free-and-null helpers (`SAFE_FREE(p)` macro).
Better: RAII / smart-pointer abstraction even in C-like code (e.g.,
glib `g_clear_pointer`).

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector finds the bug at `session_log` referencing
      `session_close` free
- [ ] ASan PoC reports use-after-free
- [ ] Manual reproduction in Binja UI matches
- [ ] Substrate-coherence check via `jm associate`
