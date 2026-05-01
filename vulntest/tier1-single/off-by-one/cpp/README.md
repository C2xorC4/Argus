# Off-by-one — C++ variant

## Brief

Same algorithmic class as the C variant. Idiomatic C++ would use
range-for or `std::transform`, eliminating the index entirely; this
cell deliberately mixes C-style indexed iteration with std::array
to reproduce the bug in code that *looks* C++ but isn't.

**Difficulty:** `1.0.0`.

## Build / Detection / Remediation

See [`../c/README.md`](../c/README.md). The C++-specific architectural
fix: use range-based for or STL algorithms; they cannot off-by-one.

```cpp
// before — C-style indexed
for (size_t i = 0; i <= len; ++i) { out[i] = ...; }

// after — STL algorithm
std::transform(in.begin(), in.begin() + n, out.begin(), [](char c){...});
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags `<=` loop bound
- [ ] ASan PoC reports overflow
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
