# PEB anti-debug field check — C / Windows

## Brief

Reads `PEB.BeingDebugged` (offset 0x02) via `GS:[0x60]` on x64 (or
`FS:[0x30]` on x86). The PEB is mapped per-process; user-mode
debuggers cause `BeingDebugged` to be set on attach. `NtGlobalFlag`
at PEB offset 0xBC similarly reflects debugger heap flags.

These checks are pure user-mode — no API call, just a segment-
register read and immediate test. They survive function-level
hooking and require kernel-level countermeasures (PEB faking) to
defeat.

**Difficulty:** `1.0.0`.

## Detection

Detector: `scripts/analysis/surface.py`. Pattern:

- Segment-register read: `mov rax, gs:[0x60]` (x64) or
  `mov eax, fs:[0x30]` (x86).
- Subsequent indirect read at offset 0x02 (`BeingDebugged`) or
  0xBC (`NtGlobalFlag`).

The pattern is structurally distinctive — segment register reads
to immediate offsets are uncommon outside TLS access (which uses
different offsets).

### Reference

- LJM: `[[Memory/Knowledge/em_peb_antidebug_fields]]` — the full
  PEB anti-debug field catalogue.
- LJM: `[[Memory/Knowledge/wnapi_segment_register_teb_bootstrap]]` —
  segment-register / TEB / PEB bootstrap convention.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags GS:[0x60] read + offset 0x02 / 0xBC indirect
- [ ] PoC confirms "no debugger" path
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
