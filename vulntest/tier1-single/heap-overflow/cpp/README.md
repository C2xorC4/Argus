# Heap buffer overflow — C++ variant

## Brief

`Buffer` allocates `new char[64]` in its constructor and stores
attacker bytes via `memcpy(data_, input.data(), input.size())` with
no clamp. The C++ shape adds the C++-classical exploit avenue:
overflow into an adjacent heap object overwrites that object's
vtable pointer, hijacking the next virtual call.

**Difficulty:** `1.0.0`.

## Build

```bash
make           # standard
make asan      # ASan build at build/vuln-asan
```

## Detection

### Programmatic

Detector: `scripts/analysis/heap.py` with the
`alloc_vs_copy_size_mismatch` pattern: allocation argument and copy
length are sourced from different variables, with no clamp on the
path between.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Functions → `Buffer::Buffer` constructor.** Notice
   `operator new[]` with constant argument 64.
2. **Cross-ref the field write to `data_`.** Used in `Buffer::store`.
3. **Inspect `Buffer::store`.** `memcpy(data_, ...)` with length
   from `std::string::size()` of input — input is `getline` from
   `std::cin`.
4. **Decision point.** Allocation 64 fixed; copy length tainted.

### Reference

- LJM: `[[Memory/Knowledge/wnapi_heap_internals]]`
- Book: *Windows Native API Programming*, heap chapter; *Heavy
  Wizardry* C++-vtable case study.

## Exploitation

**Primitive class:** heap-OF → vtable hijack (when adjacent chunk
holds a C++ object).

**Mitigation considerations.** Same as C variant. Additionally:

- **CFG / `/guard:cf`** — corrupted vtable pointer to non-CFG-valid
  target triggers `__guard_check_icall_fptr`. Bypass: target an
  existing CFG-valid function whose semantics are useful (LOLBin
  pattern at code level).
- **CET IBT (`endbranch`)** — indirect-call target must start with
  `endbranch`. Most code does after `/CETCOMPAT`; gadget set shrinks.

## Chain potential

- [`heap-OF → vtable-hijack → ROP`](../../../tier2-chains/) — the
  canonical C++ chain. Heap-feng-shui ensures the adjacent chunk is
  the target object.

## Remediation

```cpp
// before
char* data_ = new char[n];
std::memcpy(data_, input.data(), input.size());   // unbounded

// after
std::vector<char> data_(n);
const size_t cnt = std::min(input.size(), data_.size());
std::copy_n(input.begin(), cnt, data_.begin());   // clamped
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector finds the bug at `Buffer::store`
- [ ] ASan run reports heap-buffer-overflow
- [ ] PoC triggers
- [ ] Manual reproduction in Binja UI matches
- [ ] Substrate-coherence check via `jm associate`
