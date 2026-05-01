# Double-free — C variant

## Brief

`entry_destroy()` frees `e.name`. `main()` then frees `e.name` again.
The double-free corrupts the allocator's free list; on glibc tcache,
this is exploitable into arbitrary write by allocating from a
poisoned bin.

The source is ownership ambiguity: the destroy helper does not null
the pointer, and the caller doesn't know whether the helper "took
ownership." Both end up freeing.

**Difficulty:** `1.0.0`.

## Build

```bash
make
make asan
```

## Detection

### Programmatic

Detector: `scripts/analysis/heap.py`. Pattern: two `free()` sites
reachable on the same control-flow path with the same pointer
(modulo aliasing); no intervening reassignment.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Imports → `free`.** Multiple cross-refs.
2. **Inspect each free site.** `entry_destroy:free(e->name)` and
   `main:free(e.name)`.
3. **Decision point.** Both reachable on the linear path
   `main → entry_destroy → main:free(e.name)`. Same target.

### Reference

- LJM: `[[Memory/Knowledge/wnapi_heap_internals]]` — chunk-state
  invariants; tcache_perthread metadata.

## Exploitation

**Primitive class:** double-free → arbitrary-write via tcache
poisoning (modern glibc) or unsorted-bin attack (older glibc).

**Mitigation considerations.**

- **glibc 2.29+ tcache key** — second free of the same chunk in
  tcache is detected and aborted.
- **Windows LFH** — encoded chunk header validation on free.
- **Hardened allocators (scudo, mimalloc-secure)** — quarantine +
  freelist randomisation defeat the canonical primitive.

## Chain potential

- Tcache poisoning → arbitrary-write → ROP-via-`__free_hook`
  (legacy glibc) or function-pointer overwrite.

## Remediation

```c
// before
free(e->name);                       // entry_destroy
free(e.name);                        // main — second free

// after — establish single owner
free(e->name);
e->name = NULL;                      // entry_destroy invalidates
// main does not free; transferred ownership
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Adopt single-owner discipline. Document ownership explicitly: every
heap pointer has exactly one free site. Helpers either *take*
ownership (caller must not free) or *borrow* (helper must not free).
RAII / smart pointers in C++; `cleanup` attribute or `g_autofree` in
C/glib.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector finds two free sites for the same pointer
- [ ] ASan run reports double-free / double free or corruption
- [ ] Manual reproduction in Binja UI matches
- [ ] Substrate-coherence check via `jm associate`
