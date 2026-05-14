# `analysis/source_surface.py` — Manual-Workflow Companion

## Purpose

Phase-2 source enrichment. Given a `source/` directory alongside the
binary cell, extracts three classes of signal from C/C++ headers and
Python PoC files:

1. **Source ↔ binary function alignment** — parses C-shaped source
   (Ghidra/IDA decompiled output, partial RE notes, upstream source)
   for top-level function bodies; matches each to a binary function
   by kernel-API callee signature; applies source names to binary
   functions.

2. **IOCTL constant extraction** (full four-path coverage):
   - `IoControlCode == 0xXXXX` or `IoControlCode == <decimal>`
     comparison expressions (IDA/Ghidra decompiler output, signed
     or unsigned)
   - `switch(IoControlCode) { case 0x.../decimal: ... }` dispatch
     blocks (brace-matched, filters `case 0:` noise via device-type
     heuristic)
   - `CTL_CODE(DeviceType, Function, Method, Access)` macro
     invocations in header files (24 named device-type constants,
     all `METHOD_*` and `FILE_*_ACCESS` names resolved)
   - `DeviceIoControl(handle, IOCTL, ...)` call-site argument in
     both C source and Python ctypes PoCs

3. **K7-style Python PoC parsing** — scans `*.py` files for:
   - Uppercase constant assignments whose values pass the IOCTL
     heuristic filter (device-type field non-zero, i.e. code ≥ 0x10000)
   - `DeviceIoControl(handle, literal, ...)` call-site arguments
   - Win32 device paths in raw (`r"\\.\Device"`) and escaped
     (`"\\\\.\\Device"`) Python string literals

4. **UE5 source patterns** — off-by-one cap check, allocate-before-read,
   and PRNG-mod-N in security context (Plan D; scoped to UE5 cells).

Findings emitted:
- `source_function_alignment` (INFO) — per matched binary rename
- `kernel_ioctl_handler_classified` (MEDIUM/HIGH) — per unique IOCTL
  code from C source; HIGH when `METHOD_NEITHER`
- `standalone_poc_ioctl` (INFO) — per unique IOCTL code from `.py` PoC
- `phase2_source_summary` (INFO) — pipeline-run metadata
- `ue5_offbyone_cap_check` (MEDIUM), `ue5_allocate_before_read` (HIGH),
  `ue5_rand_mod_in_security_path` (HIGH)

## Detector character

**Source alignment** matches only when the callee signature is unique
(one binary function shares all kernel-API callees of the source
function). Ambiguous matches are silently dropped — this prevents
confident-wrong renames on dispatcher functions that share call sets.

**IOCTL extraction** is pattern-based and permissive; it doesn't
validate that the extracted code is actually dispatched by the binary
under analysis. Use the `windows_drivers` detector for binary-side
dispatch confirmation. The Phase-2 IOCTL findings are enrichment
context for pairing with taint/UAF/OOB findings from Phase-1.

**Python PoC extraction** tells you which IOCTLs are known to be
exercised by existing public or internal exploit tools — a shortcut
to the attack-surface entry points worth focusing Phase-1 taint on.

**CTL_CODE macro decoding** is computed:
`code = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method`

## Programmatic invocation

```bash
# Phase 2 runs automatically when source_dir is detected.
# Explicit source directory override:
python -m scripts.analysis.source_surface --binary <path> --source-dir <dir>
```

`source_dir` is auto-discovered as `<binary_dir>/../source/` when the
binary lives under a `*/binary/<file>.sys` cell layout.

## Manual workflow — IOCTL surface mapping (Windows drivers)

1. **Collect source.** Place decompiled output, upstream source, or
   RE notes in the cell's `source/` directory. For decompiler output:
   export from IDA (File → Produce File → Create C File) or Ghidra
   (Decompile all functions → Export). Raw output is fine — the
   parser is permissive.

2. **Collect PoC files.** Place any known BYOVD PoCs (Python ctypes
   scripts, standalone C exploit files) in `source/` or a
   `source/poc/` subdirectory. Name them freely — all `*.py` files
   are scanned.

3. **Run Phase 2.** The `analyze()` entry point returns findings.
   Check `phase2_source_summary` first: confirm the parse counts
   look reasonable (function count, IOCTL count).

4. **Review IOCTL findings.** For each `kernel_ioctl_handler_classified`:
   - `method_name == METHOD_NEITHER` → HIGH; raw user pointer
     dereferences through `Type3InputBuffer` / `UserBuffer` are the
     strongest kernel attack surface for arbitrary-read/write.
   - `method_name == METHOD_BUFFERED` → MEDIUM; attacker still
     controls the system buffer bytes, so length/type confusion bugs
     (dbutil-class) are in scope.
   - Cross-reference the IOCTL code against Phase-1 taint findings
     in the same binary: a `taint` finding whose source address is
     inside the handler for this IOCTL code is a confirmed attack path.

5. **Review PoC findings.** `standalone_poc_ioctl` findings include
   `poc_device_names` (the driver device path strings from the PoC).
   Use these to confirm the cell's binary is the same driver the PoC
   targets. If it matches, the PoC IOCTLs are ground-truth attack
   surface — prioritise Phase-1 findings that touch those IOCTL
   handler entry points.

6. **Binary-side confirmation.** Cross the extracted IOCTL codes
   against `windows_drivers` findings (`kernel_ioctl_dispatch_handler`)
   to confirm the binary's dispatch table covers them. Discrepancies
   indicate decompiler noise in the source or a different binary
   version.

7. **Stop conditions:**
   - Phase-2 IOCTL code that also appears in a `standalone_poc_ioctl`
     AND has a Phase-1 taint/OOB/UAF finding in the handler function
     → candidate for IMPACT_PENDING escalation.
   - Phase-2 IOCTL code with `METHOD_NEITHER` and no Phase-1 finding
     → the handler deserves a manual taint walk from the
     `Type3InputBuffer` parameter.

## Manual workflow — CTL_CODE macro decoding

When reviewing driver header files (`.h`) or SDK headers:

1. Search for `CTL_CODE(` — each macro invocation is an IOCTL
   definition. Phase 2 decodes all of them automatically.
2. Confirm `DeviceType` matches the binary's `IoCreateDevice` call
   (same value in the `DeviceType` argument). Mismatches indicate
   the header belongs to a different driver.
3. `METHOD_NEITHER` IOCTLs without bounds checking on the
   `Parameters.DeviceIoControl.InputBufferLength` field are
   highest-priority for kernel arbitrary-read/write research.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]` — IRP
  major-function dispatch table layout; `IRP_MJ_DEVICE_CONTROL` is
  the IOCTL dispatch vector.
- `[[Memory/Knowledge/windows_defender_attack_surface]]` — defender
  RPC + IOCTL surface mapped during NightmareEclipse sprint.

## Divergence policy

- **Programmatic authoritative for:** the literal IOCTL codes
  extracted from source or PoC files; the CTL_CODE field decoding.
- **Manual authoritative for:** whether a given IOCTL code is actually
  reachable and exploitable in the binary under analysis. Phase-2 is
  enrichment, not confirmation — the Phase-1 binary analysis is the
  ground truth for exploitability.
- **Conflict resolution:** if Phase-2 reports an IOCTL code that
  Phase-1 taint traces through a handler with a vulnerability finding,
  trust Phase-1's address-level evidence; Phase-2's contribution is
  naming and method-class context.

## Operator-validation checklist

- [ ] Cell with a `source/` dir containing a driver `.h` file with
  `CTL_CODE()` definitions — confirm `kernel_ioctl_handler_classified`
  findings appear with correct decoded fields.
- [ ] Source dir containing a Python PoC with `DeviceIoControl(hDev,
  0xXXXX, ...)` — confirm `standalone_poc_ioctl` fires; check
  `poc_device_names` contains the `\\.\DeviceName` string.
- [ ] Decompiler output for a dispatch function with
  `switch(IoControlCode)` and decimal case values — confirm
  `kernel_ioctl_handler_classified` fires for each case with
  correct code value (and `case 0` is absent).
- [ ] Clean-corpus sweep (non-driver Windows EXE without source dir):
  `analyze()` must return `[]` immediately (no source_dir → early
  return path).
