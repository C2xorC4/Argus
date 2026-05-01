# TLS callback first-stage — C / Windows

## Brief

Registers a TLS callback in `.CRT$XLB`. The PE loader walks
`IMAGE_TLS_DIRECTORY.AddressOfCallBacks`, calls each function with
`DLL_PROCESS_ATTACH`, then jumps to the entry point. The callback
fires **before** any user-mode anti-debug / EDR instrumentation
that hooks via entry-point patching — unless the EDR also
instruments TLS callbacks (modern EDR does, but not all of it).

**Difficulty:** `1.0.0`.

## Detection

Detector: `scripts/analysis/surface.py`. Signal: PE
`IMAGE_DIRECTORY_ENTRY_TLS` populated and `AddressOfCallBacks`
points to a non-empty array.

Caveat: legitimate Visual C++ binaries also use TLS callbacks for
runtime init. Pair with other signals (small entry, suspicious
imports, packer indicators) to discriminate.

### Manual (Binary Ninja UI)

1. **Symbols → "TLS Directory"** (Binja parses this automatically).
2. **Open the callback function.** Inspect for behaviour beyond
   trivial init.

### Reference

- LJM: `[[Memory/Knowledge/em_covert_execution_tls_seh]]`

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags TLS directory presence
- [ ] `pefile` PoC confirms TLS directory exists in the binary
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
