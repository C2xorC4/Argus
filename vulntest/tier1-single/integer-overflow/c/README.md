# Integer overflow → allocation — C variant

## Brief

`alloc_records()` computes `count * sizeof(record_t)` as `size_t` and
feeds the result to `malloc`. When `count` is large enough, the
multiplication wraps and `malloc` allocates a tiny buffer. The
caller, assuming the full requested capacity, walks the buffer with
the original `count` value and overflows the heap allocation.

This is the canonical pattern UE5's FString-allocation-amplification
research surfaces: small mismatch between size used for allocation
and size used for write produces the overflow.

**Difficulty:** `1.0.0`.

## Build

```bash
make
make asan
make ubsan       # UBSan catches the overflow at the multiplication
```

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py` with arithmetic-to-allocation
pattern. Looks for:

- `mul` / `add` with `size_t` operands
- result feeds an allocator call (`malloc`, `calloc`, `realloc`,
  `new`, `HeapAlloc`, ...)
- no overflow check on the path (no comparison against `SIZE_MAX`,
  no `__builtin_*_overflow`, no equivalent runtime guard).

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Imports → `malloc`.** Cross-ref `alloc_records`.
2. **Inspect `alloc_records`.** Argument to `malloc` is the result
   of a multiply.
3. **Look for guard.** No comparison-against-overflow before the
   multiply.
4. **Trace count.** Walks back to `argv`/`strtoull`.

### Reference

- LJM: `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` —
  signed-overflow UB; unsigned overflow is defined wrap but still
  a logic error.
- LJM: `[[Memory/Knowledge/ue5_fstring_allocation_amplification]]` —
  real-world manifestation of the alloc-vs-write size divergence.

## Exploitation

**Primitive class:** integer-overflow → heap-OF (composite).

**Mitigation considerations.**

- **UBSan unsigned-integer-overflow** — catches at runtime; not in
  production.
- **`-ftrapv` / `-fwrapv` / `-fsanitize=signed-integer-overflow`** —
  signed only; does not help unsigned multiplication.
- **safeint / `kalloc_array_size`** — kernel-style checked arithmetic
  helpers, when adopted.

## Chain potential

This bug is itself a chain primitive (overflow → undersized alloc
→ heap-OF). Pair with vtable-hijack or function-pointer overwrite
for full control.

## Remediation

```c
// before
size_t bytes = count * sizeof(record_t);
return malloc(bytes);

// after
size_t bytes;
if (__builtin_mul_overflow(count, sizeof(record_t), &bytes)) {
    return NULL;                       // overflow guard
}
return malloc(bytes);
```

Or use `calloc(count, sizeof(record_t))` — glibc's calloc has an
internal overflow check.

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Adopt typed-size APIs that combine alloc-size and copy-size into a
single value. Better: avoid raw arithmetic on size_t — use containers
(`std::vector<record_t>(count)` in C++) that handle this internally.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags arithmetic-to-allocation without overflow guard
- [ ] UBSan or ASan PoC reports overflow / heap-OF
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
