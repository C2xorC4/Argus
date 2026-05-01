# LCG / XOR string cipher — C++ variant

## Brief

Same obfuscation as the C variant in idiomatic C++ shape. C++14+
allows the encryption to happen at compile time via `constexpr`,
producing a binary indistinguishable from the C variant at the
machine-code level — the detector finds the same LCG arithmetic,
the same XOR loop, the same constants.

**Difficulty:** `1.0.0`.

See [`../c/README.md`](../c/README.md) for the full mechanics. The
C++-specific note is that C++20 `consteval` / C++17 `constexpr`
strings allow the LCG to be unrolled at compile time, leaving only
the ciphertext in `.rodata` and a tight decrypt loop. Detection of
the loop is unchanged; recovery emulates it.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector recognises LCG constants
- [ ] Emulator recovers plaintext
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
