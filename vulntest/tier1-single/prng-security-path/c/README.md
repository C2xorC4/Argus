# Weak PRNG in security-relevant path — C variant

## Brief

`issue_token()` seeds `srand()` with `time(NULL)` and uses `rand()`
output to assemble a 32-hex-char session token. `rand()` is a
non-cryptographic linear congruential generator; its output is fully
determined by the seed. An attacker observing the connection time
within a small skew window can replay the seed sequence and recover
the token.

This pattern is the failure that produced the UE5 HandshakeSecret
recovery exploit: a non-CSPRNG fed a security-critical secret, and
the secret was offline-recoverable.

**Difficulty:** `1.0.0`.

## Build

```bash
make
```

## Detection

### Programmatic

Detector: `scripts/analysis/crypto.py`. Pattern: data-flow from
`rand()` / `random()` / `mt19937` / language-equivalent non-CSPRNG
into a security-relevant sink (token, key material, IV, nonce,
session ID).

The "security-relevant sink" classifier is the heuristic: the
detector tags variables whose names match `token|secret|key|nonce|iv|
session|csrf|salt|cookie` (configurable in
`heuristics/crypto.py`) as security-relevant.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Imports → `rand`, `srand`, `time`.** All three present is the
   smoke signal.
2. **Cross-ref `rand`.** Result feeds an indexing operation into a
   character table; output stored into a buffer.
3. **Trace the buffer.** Used as a token / written to network /
   compared against attacker-supplied token.

### Reference

- LJM: `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]` —
  the canonical real-world example. UE5's `FMath::Rand()` is
  initialised with `FPlatformTime::Cycles()`, low-entropy and
  predictable; HandshakeSecret derived from it was recoverable.

## Exploitation

**Primitive class:** PRNG prediction → token forgery / key recovery.

**Mitigation considerations.**

- **`getrandom(2)` / `BCryptGenRandom` / `arc4random`** — CSPRNGs.
  Adopt at the API boundary.
- **Static analysers** — clang-tidy
  `cert-msc30-c` / `cert-msc32-c` / `cert-msc50-cpp`. Compile-time
  detection.
- **Runtime CSPRNG enforcement** — sandbox / seccomp policy that
  refuses access to `rand()` family.

## Chain potential

- [`PRNG → cookie-forge → amplification`](../../../tier2-chains/) —
  the canonical UE5 chain; predict cookie + signed-token bypass +
  amplification DoS.

## Remediation

```c
// before
srand(time(NULL));
out[i] = hex[rand() & 0xF];

// after — POSIX
unsigned char raw[16];
read(open("/dev/urandom", O_RDONLY), raw, sizeof(raw));

// after — Windows
BCryptGenRandom(NULL, raw, sizeof(raw),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Project-wide policy: any random-bytes usage in a security path
goes through a single CSPRNG wrapper. Ban direct `rand()` from
security-tagged modules via static analysis or codeowner gating.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags `rand()` flowing to a security-tagged sink
- [ ] PoC predicts the token within a 60-second window
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
