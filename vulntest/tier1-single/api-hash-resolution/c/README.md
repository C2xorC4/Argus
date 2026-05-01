# API hash resolution — C / Windows

## Brief

Resolves NTDLL exports by hash rather than name. Walks
`IMAGE_EXPORT_DIRECTORY`, hashes each name, compares against a
constant. Function names never appear in the binary — only the
hash constants do, which look like arbitrary 32-bit values to
string-fingerprinting analysis.

Hell's Gate, SysWhispers, Cobalt Strike, and most modern shellcode
runtimes use this pattern. The hash function family is djb2, FNV-1a,
ROR13, or a custom variant — Argus's heuristics include the common
families.

**Difficulty:** `1.0.0`.

## Detection

Detector: `scripts/analysis/obfuscation.py`. Signals:

- Hash function: tight loop with `(h << 5) + h` (djb2),
  `h * 0x01000193` (FNV-1a), `ror eax, 13; add eax, ebx` (ROR13),
  with characteristic init constants (5381, 0x811c9dc5, 0).
- Loop walks an array of relative virtual addresses (RVAs) in
  `.text` or via PEB-derived module-base addressing.
- Comparison against an immediate 32-bit value.

### Reference

- LJM: `[[Memory/Knowledge/em_hook_evasion_three_approaches]]` — the
  three primary hook-evasion approaches (PEB walk, syscall stub,
  NTDLL unhook); API hash resolution is the entrypoint.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector recognises djb2 pattern + export-walk loop
- [ ] PoC confirms hash constant in binary
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
