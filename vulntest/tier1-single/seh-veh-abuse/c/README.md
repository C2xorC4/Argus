# SEH / VEH handler abuse — C / Windows

## Brief

`AddVectoredExceptionHandler` registers a callback that runs on every
first-chance exception in the process. A handler that mutates
`ContextRecord->Rip` and returns `EXCEPTION_CONTINUE_EXECUTION`
becomes a covert execution slot — code lives inside the handler,
control flows there via exception trigger, and returns to a chosen
location.

Combined with hardware breakpoints in TEB-DR registers (the
`em_veh_hwbp_hook_evasion` pattern), this becomes a powerful
hook-evasion primitive: install a hwbp on a hooked NTDLL stub, the
hook is bypassed when execution flows through the VEH instead.

**Difficulty:** `1.0.0`.

## Detection

Detector: `scripts/analysis/surface.py`. Signals:

- Import: `AddVectoredExceptionHandler` /
  `RtlAddVectoredExceptionHandler`.
- Handler function reads / writes `ContextRecord->Rip` /
  `ContextRecord->Dr0..7`.

### Reference

- LJM: `[[Memory/Knowledge/em_covert_execution_tls_seh]]`
- LJM: `[[Memory/Knowledge/em_veh_hwbp_hook_evasion]]`

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags `AddVectoredExceptionHandler` import
- [ ] PoC confirms import in PE
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
