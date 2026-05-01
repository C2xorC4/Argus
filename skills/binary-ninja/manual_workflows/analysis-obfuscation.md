# `analysis/obfuscation.py` — Manual-Workflow Companion

## Purpose

Detects:
- Packer markers (UPX, Themida, VMProtect, ASPack, Petite section
  names)
- High-entropy code sections (Shannon entropy ≥ 7.0 in `.text`)
- RWX section permissions (R+W+X simultaneously set)
- Control-flow-flattening dispatcher candidates (single block with
  high outdegree whose successors converge back)
- LCG-XOR string-cipher constants in code (also in `analysis/crypto.py`)

Pattern data in `heuristics/obfuscation.py`.

## Programmatic invocation

```python
from scripts.analysis import obfuscation
findings = obfuscation.analyze(session, binary=path)
```

## Manual workflow (Binary Ninja UI)

1. **Sections tab.**
   - Look for `UPX0`, `UPX1`, `.themida`, `.vmp0..2`, `.aspack`,
     `.petite` — known packer signatures.
   - Note any section with R+W+X permissions — runtime-decoded
     payload candidate.
2. **Section entropy.** For each section, compute or eyeball:
   - `.text` ≥ 7.0 bits/byte (highly random) → packed / encrypted
     code.
   - `.rdata` ≥ 7.5 → encrypted resources or compressed data
     (lower priority — can be legitimate).
3. **Strings sparsity.** If `bv.strings` returns very few hits
   relative to binary size, runtime decryption is likely (see
   crypto.md for LCG-XOR).
4. **Control-flow flattening.** Identify functions with:
   - Single dominator basic block with high outdegree (≥ 10).
   - Successors that all loop back to the dominator.
   - State-variable switch (constant compared at the dispatcher).
   View → Linear → Disassembly Graph → look for the "spider" shape
   (dispatcher in the centre, all blocks pointing in/out).
5. **Opaque predicates.** Conditional branches where one side is
   provably unreachable. Hard to spot manually; requires SMT or
   symbolic execution. Phase 1 programmatic doesn't yet detect.
6. **Decision points:**
   - Packer signature present → unpack first (manual or via tools
     like `upx -d`); then re-run identification on the unpacked
     binary.
   - High entropy + RWX → likely runtime-decoded payload. Set
     breakpoint at section base, run under debugger, dump on
     decryption.
   - CFF candidate → operator review; some CFF is legitimate
     (compiler-driven LLVM passes); some is malware-protective.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/gb_obfuscated_code_analysis]]` — Ghidra
  Book's CFF / opaque-predicate / dummy-code patterns.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — LCG-XOR
  string cipher in production anti-cheat.

### Reference book chapters

- *Practical Binary Analysis* — packer recognition and unpacking.
- *Ghidra Book* — obfuscated-code analysis chapter.
- *Heavy Wizardry* — string-cipher patterns.

## Divergence policy

- **Packer signatures:** programmatic is authoritative; section
  names are unambiguous.
- **High entropy:** programmatic Shannon calculation is ground
  truth; threshold (7.0) is operator-tunable.
- **RWX detection:** programmatic via section permissions; trust it.
- **CFF dispatcher candidates:** require both. Programmatic
  heuristic is FP-prone; operator review distinguishes
  compiler-driven CFF (legitimate, e.g., LLVM ObfusCATE) from
  malware-protective CFF.

## Operator-validation checklist

- [ ] Run on a UPX-packed sample (`upx --best /tmp/test`) — expect
      packer_upx finding + high_entropy_section finding.
- [ ] Run on `vulntest/tier1-single/lcg-xor-cipher/c/build/vuln` —
      expect lcg_xor_cipher constant finding.
- [ ] Run on a normal Microsoft binary (e.g., `notepad.exe`) —
      expect 0 findings.
- [ ] Substrate-coherence check.
