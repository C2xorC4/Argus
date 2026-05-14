# `analysis/rpc_interface.py` — Manual-Workflow Companion

## Purpose

Locates native RPC server interfaces in Windows binaries and enumerates
their dispatch tables. Input: a UUID (as binary GUID bytes or canonical
string). Output: one finding per dispatch entry naming the method index and
handler address; a second `remote_callable_path_method` finding for entries
whose NDR format string encodes a `wchar_t*` parameter (path-taking methods).

This module is the structural anchor for BlueHammer-class PoC construction:
it produces the procnum a caller must invoke to reach a path-taking handler.
Combined with `composition.py`'s `rpc_callable_path_toctou` rule, it
closes the gap between "TOCTOU exists" and "here is the RPC call that
triggers it."

Findings emitted:

- `rpc_interface_dispatch` — one per (interface, method) pair. Lists
  method index + handler function address.
- `remote_callable_path_method` — subset of dispatch entries where the
  NDR TypeFormatString encodes a PWSTR (`FC_WSTRING` / `FC_C_WSTRING`,
  with or without an FC_RP/FC_UP pointer chain).

## Programmatic invocation

```bash
# from skills/binary-ninja/ — UUID passed as canonical string
python -m scripts.analysis.rpc_interface \
    --binary <path-to-MpSvc.dll> \
    --uuid "2781761e-28e0-4abb-a6fd-a5bce7df6b89"
```

Or via the validate / runner pipelines which pass `rpc_uuid` from the
session configuration.

## Manual workflow (Binary Ninja UI)

1. **Locate the UUID** in the binary. Open Binja; Strings panel → filter
   `{` or search for the UUID string in hex (`1e768127 e028 bb4a ...`).
   The UUID lives at offset +4 of `RPC_SERVER_INTERFACE` on x64 PE.

2. **Find the dispatch table pointer.** From the `RPC_SERVER_INTERFACE`
   struct:
   - `+0x00`: vtable pointer
   - `+0x04`: UUID (16 bytes)
   - `+0x14`: `RPC_DISPATCH_TABLE*` pointer

3. **Read the dispatch table.** At `RPC_DISPATCH_TABLE`:
   - `+0x00`: UINT DispatchTableCount
   - `+0x08`: pointer to array of function pointers (one per procnum)

4. **Walk method handlers.** For each entry in the function-pointer array:
   - Navigate to the handler in the HLIL view.
   - Look for path-string parameters (`wchar_t*` first argument after
     binding handle). If the handler calls into an NDR unmarshal stub,
     use the TypeFormatString walker (below).

5. **NDR TypeFormatString walk** (for PWSTR detection, v3b scanner):
   - Locate the proc format string for the method (in `.rdata`).
   - Oif format: scan 2-byte aligned WORDs as potential TypeFormatString
     offsets. For each offset value, read `TypeFormatString[offset]`.
   - `FC_WSTRING` (0x25) or `FC_C_WSTRING` (0x22) at depth 0 → direct
     PWSTR. FC_RP/FC_UP/FC_FP/FC_OP pointer chains (depth 1–6) leading
     to FC_WSTRING → indirect PWSTR.
   - Proc idx=42 in Defender's `ServerMpUpdateEngineSignature`:
     TF[0x05ce] = FC_WSTRING (0x25) directly. No pointer chain.

6. **Stop conditions:**
   - Method takes PWSTR and interface SDDL is permissive → emit both
     `remote_callable_path_method` and (via composition) `rpc_callable_path_toctou`.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/windows_defender_attack_surface]]` — IMpService UUID,
  procnum table, confirmed BlueHammer procnum (idx=42,
  `ServerMpUpdateEngineSignature`).
- `[[Memory/Knowledge/argus_detector_design_principles]]` — Phase vocabulary,
  CONFIRMED → IMPACT_VERIFIED gate definitions.

### MIDL / NDR references

- *Windows RPC Internals* (Dowd, McDonald, Schuh) — NdrServerCall2,
  TypeFormatString layout, Oif encoding.
- MSDN: `MIDL TypeFormatString`, `MIDL ProcFormatString` — grammar tables.

## Divergence policy

- **Programmatic authoritative for:** UUID location (exact byte scan),
  dispatch-table pointer extraction, NDR format-string walking (v3b).
  All three are mechanical and byte-exact; manual review adds no precision.
- **Manual authoritative for:** indirect dispatch (COM v-table, ALPC
  port dispatch, ETW provider callback). Binja's static callgraph does not
  model table-driven dispatch; procnum→implementation mapping requires
  manual cross-reference against the stub code.
- **Both must agree for:** procnum count. If the programmatic walker
  counts N methods and the manual walk counts M, the discrepancy is a
  sentinel for struct-size padding or version-specific layout change.

## Operator-validation checklist

- [ ] Re-run `rpc_interface` against `MpSvc.dll`: confirm UUID
      `2781761e-28e0-4abb-a6fd-a5bce7df6b89` found; proc_idx=42
      (`ServerMpUpdateEngineSignature`) emits `remote_callable_path_method`.
- [ ] 56 `remote_callable_path_method` findings on the validated DLL
      version (v3b baseline from 2026-05-14).
- [ ] Substrate-coherence check: `jm associate "remote_callable_path_method"`
      surfaces `windows_defender_attack_surface`.
- [ ] No `remote_callable_path_method` findings on binaries without RPC
      registration imports.
