# Off-by-one — C variant

## Brief

`normalize()` iterates `for (size_t i = 0; i <= len; ++i)` and writes
`out[i]`. The inclusive bound writes `len+1` bytes; the destination
holds only `len`. The single byte past the buffer typically lands on
the saved frame pointer's low byte (stack) or the next chunk's size
LSB (heap) — both meaningful targets in further chains.

The off-by-one is the iconic "small bug, big consequences" class:
stack-OF level damage from a single character difference.

**Difficulty:** `1.0.0`.

## Build

```bash
make
make asan
```

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py`. Pattern: loop in HLIL where
the bound expression compares the iterator with a quantity related
to a buffer size, using `<=` rather than `<`. The "related to a
buffer size" part is the heuristic — typically the same value
appears as `malloc` argument or array dimension.

This is hard to detect with high recall; many `<=` loops are
correct. The heuristic relies on cross-referencing the loop bound
against allocation / declaration sites.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **HLIL of caller (`main`).** Note `buf[64]` declaration and
   `normalize(buf, ..., len)`.
2. **HLIL of `normalize`.** Loop condition is `i <= len`.
3. **Decision point.** Caller passes the same `len` it computes for
   the source's strlen, but the loop writes `len+1`.

### Reference

- LJM: `[[Memory/Knowledge/ue5_fstring_allocation_amplification]]` —
  related class: small mismatch between size used for allocation and
  size used for write.

## Exploitation

**Primitive class:** off-by-one → frame-pointer-LSB overwrite (stack)
or chunk-size LSB overwrite (heap).

**Mitigation considerations.**

- **Stack canary** — single-byte overrun typically does not reach
  the canary (lies between buf and saved RBP; canary lies between
  saved RBP and saved RIP). Defeats nothing; this primitive can
  bypass canary-protected stack-OFs.
- **`-fstack-clash-protection`** — irrelevant for single-byte over.
- **glibc safe-linking** — heap-side off-by-one corrupts the chunk
  metadata; safe-linking validates and aborts.

## Chain potential

Standalone off-by-one is rarely directly exploitable — typically
chained with an info-leak or a more substantial primitive.

## Remediation

```c
// before
for (size_t i = 0; i <= len; ++i) { ... }

// after
for (size_t i = 0; i < len; ++i) { ... }
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Banner-rule: never use `<=` against a buffer size. Linter rules
(`bugprone-misplaced-widening-cast` family) flag the pattern.
Container iteration via range-for or iterators eliminates the class
in C++.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags `<=` loop bound against buffer size
- [ ] ASan PoC reports stack-buffer-overflow
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
