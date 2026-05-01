# Heap buffer overflow — C variant

## Brief

`handle()` allocates a 64-byte buffer with `malloc()` then `memcpy`s
attacker-controlled bytes into it without checking the length. The
overflow corrupts adjacent heap chunks and (under glibc) the next
chunk's `size` and `prev_size` metadata, opening the door to chunk
overlap, free-list corruption, and the House-of-X family.

**Difficulty:** `1.0.0`.

## Build

```bash
make            # default
make asan       # ASan-instrumented build at build/vuln-asan
```

Run the ASan build for deterministic detection of the overflow.

## Detection

### Programmatic

Detector: `scripts/analysis/heap.py`.

Pattern: `malloc(constant_size)` followed by length-unbounded
`memcpy` / `memmove` / `strcpy` into the returned pointer, with the
length argument tainted by argv / fread / recv.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Imports → `malloc`, `memcpy`.**
2. **Cross-ref `malloc`.** `handle()` is the caller; constant
   argument 64.
3. **Trace the returned pointer.** Used as `dst` for `memcpy`.
4. **Inspect `memcpy`'s `n` argument.** Sourced from `len` parameter
   → `strlen(argv[1])` in `main`.
5. **Decision point.** Allocation is 64; copy length unbounded.

### Reference

- LJM: `[[Memory/Knowledge/wnapi_heap_internals]]` — Windows Low
  Fragmentation Heap chunk layout, freelist invariants, the
  metadata fields an overflow corrupts.
- Book: *Windows Native API Programming*, heap chapter.

## Exploitation

**Primitive class:** heap-OF → adjacent-chunk corruption.

**Mitigation considerations.**

- **glibc tcache** — recent glibc adds tcache key/count metadata in
  the chunk; corruption is detected on free under safe-linking. Bug
  still triggers, exploit harder.
- **Windows LFH** — encoded chunk headers. Without leak, blind
  corruption likely to crash; with leak, full primitive.
- **Heap-isolation / GuardedHeap** — adjacent allocations may be on
  different pages with guard pages between. Defeats trivial overflow.

**Idiomatic exploit walkthrough.**

```bash
make asan
python3 poc/trigger.py build/vuln-asan
```

## Chain potential

- [`heap-OF → vtable-hijack → ROP`](../../../tier2-chains/) — when
  the adjacent chunk holds a C++ object with a vtable.
- [`info-leak → UAF → ROP`](../../../tier2-chains/) — info-leak
  from heap metadata feeds the next link.

## Remediation

```c
// before
memcpy(buf, input, len);

// after
if (len > BUF_SIZE) len = BUF_SIZE;
memcpy(buf, input, len);
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Compiler / linker mitigations

- `-D_FORTIFY_SOURCE=2` — `memcpy` becomes `__memcpy_chk` when
  destination size is statically knowable.
- ASan / HWASan — runtime detection.
- Windows: `/Qspectre` does not help here; `__sanitizer-coverage`
  with libfuzzer is the dynamic equivalent.

### Architectural fix

Allocation size and copy length must be derived from the same source.
Pattern: `malloc(n); memcpy(p, src, n);` — never let the two diverge.

## Operator-validation checklist

- [ ] Build clean (`make` and `make asan`)
- [ ] Detector finds the bug at `handle`
- [ ] Programmatic Finding matches `expected.json`
- [ ] ASan PoC reports `heap-buffer-overflow`
- [ ] Manual reproduction in Binja UI matches
- [ ] Substrate-coherence check via `jm associate`
