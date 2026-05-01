# `analysis/crypto.py` — Manual-Workflow Companion

## Purpose

Detects:
- Weak-PRNG-to-security-sink flows (`rand()` → BCryptEncrypt /
  HMAC_Init / similar)
- LCG / MT19937 constants in code (custom RNG / string cipher)
- Hardcoded weak crypto material (DES weak keys, zero IVs)
- AES / SHA-256 / MD5 implementation markers
- CSPRNG-vs-non-CSPRNG balance

Pattern data in `heuristics/crypto.py`.

## Programmatic invocation

```python
from scripts.analysis import crypto
findings = crypto.analyze(session, binary=path)
```

## Manual workflow (Binary Ninja UI)

1. **Imports → PRNG family.** Filter for `rand`, `srand`, `random`,
   `srandom`, `drand48`, etc. Cross-ref each.
2. **At each PRNG callsite, walk the SSA output forward.** Same
   technique as taint analysis. Look for:
   - Use as argument to a crypto sink (BCryptEncrypt, EVP_*,
     HMAC_Init, gcry_*) → high-severity weak_prng_in_security_path.
   - Use in a comparison / printout → likely benign (game RNG, log
     ID, etc.).
3. **Constants tab / Strings tab.** Look for canonical bad constants:
   - `0x41C64E6D` (1103515245) + `0x3039` (12345) — glibc rand LCG
   - `0x343FD` (214013) + `0x269EC3` (2531011) — MSVC rand LCG
   - `0x9908B0DF` — MT19937 matrix
   - `0x67452301` — MD5 init constant (broken hash; flag in security
     paths)
   - `0x6A09E667` — SHA-256 init
4. **Hardcoded keys / IVs.** Strings tab — look for hex strings of
   the right length (16 bytes for AES-128, 32 for AES-256, 8 for
   DES); weak DES keys (`0101010101010101`, `FEFEFEFEFEFEFEFE`);
   zero IVs (`00000000000000000000000000000000`).
5. **Decision points:**
   - PRNG output flows to log / display / non-security path → no
     finding.
   - PRNG output flows to a `(token|secret|key|nonce|iv|session|
     cookie|csrf|salt|hmac)` variable (when symbols available) →
     finding even if no crypto-sink call follows.
   - LCG constants in a function clearly tagged "string_decrypt"
     → obfuscation finding (cross-ref to `analysis/obfuscation.py`),
     not crypto.
   - MD5 init constant in a non-security path (e.g., file
     deduplication) → no finding.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]` — the
  canonical real-world weak-PRNG-in-security-path finding.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — LCG-XOR
  string cipher case (also covered by obfuscation).

### Reference book chapters

- *Cryptography Engineering* (Ferguson/Schneier/Kohno) — PRNG vs
  CSPRNG distinction.
- *Real World Cryptography* (Wong) — implementation pitfalls
  including IV reuse.

## Divergence policy

- **Variable-name-driven escalation** (`token = rand()` →
  high-severity even without explicit crypto sink): manual is
  authoritative when symbols are stripped; programmatic Phase 1
  needs symbols.
- **Custom cipher recognition:** require both. LCG constants
  programmatic detects; the pattern's *purpose* (string decrypt
  vs game RNG vs hash function) is interpretation.
- **MD5/SHA1 in security path:** require both. Marker presence
  programmatic detects; security-path classification is contextual.
- **Hardcoded key recognition:** programmatic via known-bad list;
  manual via context (a hex string in a config-loader function is
  config, not key material).

## Operator-validation checklist

- [ ] Run on `vulntest/tier1-single/prng-security-path/c/build/vuln` —
      expect 1 weak_prng_in_security_path finding flowing to the
      session-token assembly.
- [ ] Run on `vulntest/tier1-single/lcg-xor-cipher/c/build/vuln` —
      expect lcg_constants finding.
- [ ] Substrate-coherence check.
- [ ] FP-rate spot-check on a Python script that uses `random`
      legitimately (game-code style) — expect at most info-tier
      `non_csprng_use` Finding, no high-severity emission.
