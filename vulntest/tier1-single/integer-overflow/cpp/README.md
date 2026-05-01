# Integer overflow → allocation — C++ variant

## Brief

`new Record[count]` with attacker-controlled `count` relies on the
implementation throwing `std::bad_array_new_length` on overflow.
Modern compilers do this correctly; older toolchains and
custom-allocator paths frequently do not, reducing the bug to the
C variant.

**Difficulty:** `1.0.0`.

## Build / Detection / Exploitation

Same pattern as C variant; symbol is `operator new[]` instead of
`malloc`. See [`../c/README.md`](../c/README.md).

## Remediation

```cpp
// before
Record* recs = new Record[count];

// after
std::vector<Record> recs(count);     // throws length_error on overflow
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags `new[]` with tainted count and no overflow guard
- [ ] PoC triggers heap overflow under ASan
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
