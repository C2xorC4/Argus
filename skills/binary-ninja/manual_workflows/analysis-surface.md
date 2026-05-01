# `analysis/surface.py` — Manual-Workflow Companion

## Purpose

Recon-stage scan: produce a `TargetProfile` (file format, arch,
platform, entry, sections + entropy, imports, strings count,
mitigation profile) and emit binary-scope Findings from the
heuristics modules. Every other detector in the pipeline consumes
this profile.

## Programmatic invocation

```bash
cd skills/binary-ninja
python -m scripts.analysis.surface <path-to-target> [--no-heuristics] [--json]
```

Output: human-readable profile + Findings (default), or full JSON
with `--json`. Findings carry `mitigation_weighted_exploitability`
auto-scored against the extracted mitigation profile.

## Manual workflow (Binary Ninja UI)

1. **Open binary in Binja UI.** `File → Open` → target. Wait for
   analysis.
2. **Triage Summary.** `View → Triage Summary` (or open the Triage
   tab) — gives format / arch / entry / hardening flags at a glance.
3. **Inspect headers.** `View → Headers` (PE/ELF). Note:
   - PE: `OptionalHeader.DllCharacteristics` flags (DYNAMIC_BASE,
     NX_COMPAT, GUARD_CF, CET_COMPAT, HIGH_ENTROPY_VA).
   - ELF: `e_type` (ET_DYN = PIE), `PT_GNU_STACK.p_flags`
     (no PF_X = NX), `PT_GNU_RELRO`.
4. **Sections tab.** Inspect each section's permissions and size.
   Compute entropy for high-entropy candidates (`.text` ≥ 7.0
   suggests packing).
5. **Symbols → Imports.** Cross-check against expected libraries
   for the binary's role. Outliers (`NtCreateThreadEx` in a non-
   debugger; `BCryptGenRandom` absent in something that should
   crypto) are the recon signals.
6. **Strings tab.** Filter for IPs, paths, NTDLL function names,
   anti-cheat / debugger names.
7. **Decision points:**
   - All mitigations present + minimal suspicious imports → low-
     priority target; identification stage looks for logic bugs.
   - One+ mitigations missing + sensitive imports → higher-priority
     target; identification stage looks for matching exploit class.
   - High-entropy `.text` + RWX section → escalate to obfuscation
     analysis before deeper detection.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/hw_stack_overflow_mechanics]]` — canary /
  mitigation mechanics referenced in profile interpretation.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — the
  canonical mitigation-absence-as-finding case.
- `[[Memory/Knowledge/wnapi_peb_teb_structures]]` — PE structural
  context for header walks.

### Reference book chapters

- *Heavy Wizardry*, ch. 4 — stack-frame layout; the header flags
  that defeat the canonical exploit.
- *Practical Binary Analysis* / *Ghidra Book* — recon methodology;
  what to read off PE/ELF headers first.

## Divergence policy

When programmatic and manual disagree:

- **Section permissions / RWX detection:** programmatic is
  authoritative. Manual UI display can collapse non-trivial section
  flags into a simplified view; the raw bytes don't lie.
- **High-entropy assessment:** programmatic computes the actual
  Shannon entropy; manual is approximate. Trust the number.
- **Import-table interpretation:** require both to agree. Imports
  are factual but their *significance* is interpretation; programmatic
  matches against heuristics, manual catches contextual cues a
  pattern table doesn't have.
- **Mitigation profile:** programmatic from raw header bytes is
  ground truth; UI display can lag on newer flag bits (CET, MTE).
  Defer to programmatic, file the UI as outdated.

If the divergence is consistent across multiple targets, file an
update either to `heuristics/mitigations.py` or to this companion
doc. Record in the module's commit log.

## Operator-validation checklist

- [ ] Run on `vulntest/tier1-single/stack-overflow/c/build/vuln` —
      profile shows `GS=False ASLR=False DEP=True` (build flags from
      Makefile).
- [ ] Run on `C:\Windows\System32\notepad.exe` — profile shows full
      Win10/11 hardening (CFG/ASLR/DEP/SAFESEH/HighEntropyVA).
- [ ] Substrate-coherence check on any emitted Finding — `jm associate`
      surfaces cited Knowledge entry as top match.
- [ ] Mitigation-weighted scoring sanity check: same Finding on
      hardened vs unhardened target produces materially different
      score (≥ 10× spread expected on memory-corruption classes).
