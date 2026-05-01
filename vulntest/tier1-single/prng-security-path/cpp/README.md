# Weak PRNG in security-relevant path — C++ variant

## Brief

`std::mt19937` is a high-quality non-cryptographic PRNG. Seeded
from `system_clock`, it produces predictable output the moment the
attacker can approximate the seed time. C++ documentation often
treats mt19937 as the "good random" choice — a misframing for
security purposes, where only `std::random_device` (or platform
CSPRNGs) is appropriate.

**Difficulty:** `1.0.0`.

## Build

```bash
make
```

## Detection

Detector: `scripts/analysis/crypto.py`. Pattern: instantiation of
`std::mt19937`, `std::mt19937_64`, `std::minstd_rand`, or other
`<random>` engines (excluding `std::random_device`) where the
output flows into a security-tagged sink.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Functions → `std::mersenne_twister_engine` constructor.** Hits
   in `issue_token`.
2. **Inspect the seed argument.** `system_clock::now().time_since_epoch().count()`
   chain confirms time-seeded.
3. **Trace the engine output.** Used to index hex character table;
   result is the token.

### Reference

- LJM: `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]`
- ISO C++ Standard `<random>` discussion of CSPRNG vs. PRNG.

## Exploitation / Chain potential / Remediation

Same as C variant. See [`../c/README.md`](../c/README.md).

C++-specific remediation:

```cpp
// before
std::mt19937 rng{seed_from_time};

// after
std::random_device rd;          // OS CSPRNG
// or platform-direct: BCryptGenRandom / getrandom
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags non-CSPRNG `<random>` engine in security path
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
