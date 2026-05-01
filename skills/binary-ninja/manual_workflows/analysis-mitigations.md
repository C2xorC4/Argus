# `analysis/mitigations.py` — Manual-Workflow Companion

## Purpose

Header-driven extraction of the binary's hardening profile (PE
DllCharacteristics + LoadConfig; ELF ET_DYN / PT_GNU_STACK / RELRO
+ canary symbol presence + FORTIFY pair detection), plus
`score_finding(finding, profile)` that applies a per-bug-class
weight table to compute `mitigation_weighted_exploitability`.

## Programmatic invocation

```python
from scripts.analysis import mitigations
profile = mitigations.extract_mitigations(binary_path, bv=session.bv)
mitigations.score_findings(findings, profile)    # mutates in place
```

Or via `surface.analyze()` which calls `extract_mitigations` +
`score_findings` automatically.

## Manual workflow (Binary Ninja UI)

1. **Open binary in Binja UI.** Wait for analysis.
2. **PE binaries:**
   - `View → Headers → Optional Header` → look at
     `DllCharacteristics` field. Decode bits per the values in
     `heuristics/mitigations.py:PE_HARDENING_MAP`.
   - `View → Headers → Load Config` → `SecurityCookie`
     (non-zero = /GS canary), `SEHandlerTable` (non-zero = SafeSEH).
   - `Symbols` filter: presence of `__security_check_cookie` /
     `__security_init_cookie` confirms /GS at the symbol level.
3. **ELF binaries:**
   - `View → Headers → ELF Header` → `e_type` (`ET_DYN` = PIE).
   - `Program Headers` → `PT_GNU_STACK` (look at `Flags`; no
     `PF_X` = NX); `PT_GNU_RELRO` presence.
   - `Symbols` filter:
     - `__stack_chk_fail` import = canary enabled
     - `__strcpy_chk` / `__memcpy_chk` family = FORTIFY enabled
4. **Decision points:**
   - All mitigations present → memory-corruption findings score
     low; focus on logic / crypto bugs.
   - GS missing → trivial stack-OF findings score high.
   - CET missing on a Win10+ binary → return-address overwrite is
     the canonical primitive.
   - All mitigations missing (the GameGuard pattern) → any
     memory-corruption bug is deterministically exploitable.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/hw_stack_overflow_mechanics]]` — canary
  mechanics; how each mitigation interacts with the canonical
  primitive.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — the
  mitigation-absence-as-finding case. Real-world example where the
  weighted-exploitability score elevates an otherwise mid-tier bug
  to critical.

### Reference book chapters

- *Heavy Wizardry*, ch. 4 — stack-OF + canary interaction.
- Microsoft Compiler / Linker reference — DllCharacteristics flag
  semantics.
- *Linkers and Loaders* — ELF program header flags.

## Divergence policy

- **Raw header parsing:** programmatic is authoritative. Binja UI
  can be out of date on newer flag values (CET, MTE).
- **FORTIFY detection on ELF:** programmatic checks symbol pairs
  (`memcpy` vs `__memcpy_chk`). Manual eyeballing of imports works
  but is error-prone; trust the code.
- **GS / canary detection on PE:** require both to agree. Symbol
  presence (`__security_check_cookie`) is the strong signal;
  Binja's UI shows it but operator should verify.
- **Mitigation-weighted scoring values:** these are heuristics
  (`heuristics/mitigations.py:EXPLOITABILITY_WEIGHTS`). Disagreements
  between operator judgement and the score should drive a tuning
  PR rather than a one-off override.

## Operator-validation checklist

- [ ] Run against `python.exe` — expect `CFG=False, ASLR=True,
      DEP=True, SAFESEH=True, HighEntropyVA=True`.
- [ ] Run against `notepad.exe` (Win10/11) — expect full Win10/11
      hardening profile.
- [ ] Run against a known unhardened ELF (`make` from VulnTest with
      all flags off) — expect `PIE=False, NX=False, GS=None, FORTIFY=False`.
- [ ] Score the same Finding against both profiles — confirm ≥ 10×
      spread on memory-corruption categories.
