# `analysis/cloud_files.py` — Manual-Workflow Companion

## Purpose

Detects Windows binaries that import the Cloud Files API (CldApi.dll) in
contexts where an attacker-controlled path argument could route a
SYSTEM-privileged write through an NTFS junction or mount point, or stall
a SYSTEM-privileged scan thread in a TOCTOU race window.

Two exploitation shapes detected:

- **BlueHammer stall shape** — `CfRegisterSyncRoot` + `CfConnectSyncRoot`
  used as a blocking callback to hold Defender's scan thread in the TOCTOU
  window between `GetFileAttributesW` and `CreateFileW`.
- **RedSun write-proxy shape** — Cloud Files placeholder + NTFS junction to
  route Defender's cloud-restore write (as SYSTEM, with `SeRestorePrivilege`)
  to an attacker-chosen destination, bypassing ACL enforcement.

Findings emitted:

- `cloud_files_import` (INFO) — binary imports at least one Cloud Files API.
  Weak alone; becomes exploitation-grade when combined with TOCTOU or SDDL.
- `cloud_files_write_proxy` (HIGH) — binary imports Cloud Files write-proxy
  APIs (`CfRegisterSyncRoot`, `CfConnectSyncRoot`, `CfExecute`,
  `CfHydratePlaceholder`, `CfCreatePlaceholders`) AND has either a co-located
  `toctou` finding (stall shape) OR a `permissive_sddl` finding (write-proxy
  shape).

## Programmatic invocation

```bash
python -m scripts.analysis.cloud_files --binary <path-to-target.dll>
```

Or via `analyze()` in the pipeline after `race.py` and `sddl.py` have run
(the module needs existing findings as `findings=` input).

## Manual workflow (Binary Ninja UI)

1. **Imports panel.** Filter for `Cf` prefix. Relevant imports:
   - Write-proxy capable: `CfRegisterSyncRoot`, `CfConnectSyncRoot`,
     `CfExecute`, `CfHydratePlaceholder`, `CfCreatePlaceholders`
   - Cleanup-only (not directly exploitable): `CfDisconnectSyncRoot`,
     `CfUnregisterSyncRoot`
   - Metadata-only: `CfOpenFileWithOplock`, `CfGetPlaceholderStateFromFileInfo`

2. **Stall shape check.** For `CfConnectSyncRoot` call sites:
   - Verify the binary also has a TOCTOU finding (path-race between a
     check and a use). The Cloud Files callback fires as an APC to the
     thread that called `CfConnectSyncRoot` — it blocks that thread.
   - If the TOCTOU function is in the same binary or in an imported
     binary (`remote_callable_path_method` finding), emit `cloud_files_write_proxy`
     with `exploitation_shapes: ["bluehammer_stall"]`.

3. **Write-proxy shape check.** For `CfCreatePlaceholders` + `CfExecute`
   call sites:
   - Verify the binary also has a `permissive_sddl` finding (attacker can
     invoke the RPC path that triggers cloud-restore).
   - Confirm `CfExecute` is called with `CF_OPERATION_TYPE_TRANSFER_DATA`
     and the `SyncRootPath` is not locked down to a fixed directory.
   - Emit `cloud_files_write_proxy` with
     `exploitation_shapes: ["redsun_write_proxy"]`.

4. **Stop conditions:**
   - Import only, no TOCTOU or SDDL co-location → `cloud_files_import` (INFO).
   - Write-proxy import + TOCTOU → HIGH with `bluehammer_stall`.
   - Write-proxy import + permissive SDDL → HIGH with `redsun_write_proxy`.
   - Only `CfDisconnectSyncRoot` / `CfUnregisterSyncRoot` → INFO only
     (cleanup path, not attack-capable).

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/windows_defender_attack_surface]]` — BlueHammer
  (CfConnectSyncRoot stall shape) and RedSun (CfExecute write-proxy shape)
  are both Defender-specific manifestations of this general class.
- `[[Memory/Knowledge/argus_detector_design_principles]]` — Phase vocabulary.

### Windows API references

- MSDN: `CfConnectSyncRoot`, `CfRegisterSyncRoot`, `CfExecute`,
  `CF_OPERATION_PARAMETERS` — Cloud Files API reference.
- `cloudfiles_primitive.py` in `NightmareEclipse/_poc/` — ctypes wrapper
  for CldApi.dll; stall callback and write-proxy shapes implemented and
  tested against HMDXIN.

## Divergence policy

- **Programmatic authoritative for:** import-table presence (exact name
  match), write-proxy vs. cleanup-only subset classification, co-location
  detection with `toctou` / `permissive_sddl` findings.
- **Manual authoritative for:** whether the Cloud Files callback is
  actually reachable from a low-privilege entry point (the programmatic
  detector fires on import presence + co-located primitives, not on proven
  callgraph reachability to the callback registration site).
- **Both must agree for:** `exploitation_shapes` list. If manual review
  identifies a third exploitation shape beyond `bluehammer_stall` and
  `redsun_write_proxy`, add it to `CATEGORY_META` and the detector.

## Operator-validation checklist

- [ ] `test_cloud_files.py` — 35 tests pass (full suite green).
- [ ] Binary with `CfRegisterSyncRoot` + co-located `toctou` → HIGH with
      `bluehammer_stall` in `exploitation_shapes`.
- [ ] Binary with `CfCreatePlaceholders` + co-located `permissive_sddl` →
      HIGH with `redsun_write_proxy`.
- [ ] Binary with only `CfDisconnectSyncRoot` → INFO only, no HIGH.
- [ ] Substrate-coherence: `jm associate "cloud_files_write_proxy"` surfaces
      `windows_defender_attack_surface`.
- [ ] `composition.py`'s `rpc_callable_cloud_stall` rule fires when
      `cloud_files_write_proxy` + `remote_callable_path_method` both present.
