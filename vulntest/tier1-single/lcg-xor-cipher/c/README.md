# LCG / XOR string cipher — C variant

## Brief

Anti-analysis obfuscation. Strings are stored as ciphertext in `.rodata`;
a runtime stub decrypts them via `state = state * A + C; out = in ^ (state >> N)`.
The constants `1103515245` and `12345` are the glibc `rand()` LCG —
their literal presence in `.rodata` or as immediates in the
decryption loop is a structural fingerprint.

This pattern appears prominently in **GameGuard's runtime**: every
sensitive string (driver paths, anti-cheat capability checks, kernel
function names) is XOR-encrypted with the same family of LCG
sequences, decrypted lazily.

This cell is **not a vulnerability** — it's a detection / deobfuscation
target. The detector recognises the pattern and emulates the stub
to recover plaintext before downstream import / string analysis.

**Difficulty:** `1.0.0`.

## Build

```bash
make
python3 poc/trigger.py build/vuln    # binary self-decrypts; PoC verifies recovery
```

## Detection

### Programmatic

Detector: `scripts/analysis/obfuscation.py`. Pattern:

- LCG arithmetic: `multiply by constant; add constant; shift; XOR with byte
  from buffer`. Constants from a table of known PRNG-family multipliers
  (glibc `rand`, MSVC `rand`, BSD `random`, MT19937 substitutes).
- XOR loop indexed by byte counter, output to a stack / heap buffer.
- Source operand of XOR is a memory read from `.rodata` (for static
  ciphertext) or a parameter (for dynamic).

Once the pattern is recognised, the detector **emulates** the loop
and writes plaintext back into the analysis database as a virtual
string section. Downstream import / taint detectors then see the
plaintext and produce real findings.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Look for high-entropy `.rodata` sections.** Encrypted strings
   stand out from plaintext by entropy.
2. **Find xref to the encrypted bytes.** Lands in the decrypt stub.
3. **Recognise the LCG.** `mul reg, 0x41C64E6D` / `add reg, 0x3039` —
   classical `1103515245 / 12345` constants.
4. **Emulate.** Binja's emulator-plugin or a manual Python script
   replays the LCG and recovers plaintext.

### Reference

- LJM: `[[Memory/Knowledge/gameguard_research_22_findings]]` — full
  GameGuard decryption-stub analysis with constants and recovery
  workflow.
- Book: *Heavy Wizardry* on string-cipher analysis patterns.

## "Exploitation"

Not a vulnerability — but the **deobfuscation primitive** is what
unlocks downstream analysis. Recovering plaintext is the chain
multiplier: every other detector on the binary improves.

## Chain potential

When this pattern obfuscates a malicious binary, recovery feeds:
- Import / taint / heuristics analysis (now sees real strings)
- String-based YARA rules (now match decrypted plaintext)
- IOC extraction (now produces network indicators / paths)

## Remediation

See [`remediation/README.md`](remediation/README.md) — there is no
"fix" for this code; the equivalent question is whether string
encryption is justified as a layer.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector recognises LCG constants in decryption stub
- [ ] Emulator recovers plaintext (`/etc/passwd`) for downstream
      analysis
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
