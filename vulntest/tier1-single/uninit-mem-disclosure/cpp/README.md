# Uninitialised memory disclosure — C++ variant

## Brief

Same class as the C variant; the C++ shape exposes a language-level
distinction. Default-initialisation of POD members yields
indeterminate values; value-initialisation (`{}` or `Status s{};`)
zeros them. The bug is forgetting the braces.

**Difficulty:** `1.0.0`.

## Build / Detection

See [`../c/README.md`](../c/README.md). The C++-specific architectural
fix:

```cpp
// before
Status s;                       // default-init; PODs indeterminate
// after
Status s{};                     // value-init; PODs zero

// or — default member initialisers
struct Status {
    uint16_t state{};           // explicit default
    ...
};
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags default-init + full-size output
- [ ] Hex-dump shows non-zero bytes
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
