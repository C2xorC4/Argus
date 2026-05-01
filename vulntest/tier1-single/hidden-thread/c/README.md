# Hidden-from-debugger thread — C / Windows

## Brief

`NtSetInformationThread(thread, ThreadHideFromDebugger=0x11, NULL, 0)`
sets a kernel flag that prevents the thread's events from reaching
attached debuggers. Thread runs and exits without producing
debugger callbacks. Combined with TLS-callback first-stage and
direct-syscall stubs, forms the canonical malware evasion stack.

**Difficulty:** `1.0.0`.

## Detection

Detector: `scripts/analysis/surface.py`. Signal: import string
`NtSetInformationThread` + call site with `ThreadInformationClass == 0x11`.

The constant 0x11 in any `NtSetInformationThread` call site is
high-confidence; the class has no legitimate non-tracing use.

### Reference

- LJM: `[[Memory/Knowledge/em_covert_execution_tls_seh]]`

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags `NtSetInformationThread` import + 0x11 constant
- [ ] PoC confirms string presence
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
