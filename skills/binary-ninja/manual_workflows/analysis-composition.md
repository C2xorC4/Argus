# `analysis/composition.py` — Manual-Workflow Companion

## Purpose

Reads the full per-binary finding set produced by upstream detectors and
emits exploitation-grade combination findings. Individual Argus detectors
emit information-grade signals; composition names the combinations that have
explicit exploitation pathways in the public research record.

Findings emitted:

- `remote_callable_toctou` (HIGH) — TOCTOU race reachable within N
  callgraph hops from a permissive-SDDL function (callgraph-proven, same
  binary). The BlueHammer-class shape.
- `rpc_hosted_toctou_cooccurrence` (MEDIUM) — TOCTOU + permissive SDDL in
  the same binary but callgraph reachability NOT proven (table-driven
  dispatch bypasses static analysis). Manual verification required.
- `rpc_callable_path_toctou` (HIGH) — NDR-confirmed path-taking RPC method
  (procnum with `wchar_t*` param) + permissive SDDL. Names the exact
  procnum for PoC construction.
- `rpc_callable_cloud_stall` (HIGH) — RPC path-taking method + Cloud Files
  write-proxy imports. Stall-and-race PoC shape named explicitly.
- `cross_binary_remote_callable_toctou` (HIGH) — SDDL in binary A + TOCTOU
  in binary B, bridged by A's import table containing the specific TOCTOU
  function name from B. Confidence 0.75 (import-proven, not callgraph-proven).

## Programmatic invocation

```python
from scripts.analysis.composition import analyze, compose_cross_binary

# Same-binary composition (requires prior detector runs)
result = analyze(session, findings=all_findings,
                 binary="MpSvc.dll", arch="x86_64", platform="windows-x86_64")

# Cross-binary composition (multi-DLL service cluster)
cluster = [
    {"bv": bv_a, "binary": "MpSvc.dll", "arch": "x86_64",
     "platform": "windows-x86_64", "findings": findings_a},
    {"bv": bv_b, "binary": "MpClient.dll", "arch": "x86_64",
     "platform": "windows-x86_64", "findings": findings_b},
]
cross = compose_cross_binary(cluster)
# Or via analyze() with peer_cluster=:
result = analyze(session, findings=all_findings, peer_cluster=cluster)
```

## Manual workflow (Binary Ninja UI)

Composition is post-detection — there is no direct Binary Ninja UI gesture.
The manual workflow is a triage pass after programmatic composition fires:

1. **Confirm SDDL rights.** For each `remote_callable_toctou` finding,
   check the `sddl_text` detail field. Verify the ACE grants write/create/
   execute to a low-privilege SID (not read-only `GR`/`KR`). If the ACE
   is read-only, this is a FP (fix 2.7 gate: read-only grants produce no
   HIGH finding as of 2026-05-14).

2. **Confirm TOCTOU reach.** For `rpc_hosted_toctou_cooccurrence` (not
   callgraph-proven): open the binary; navigate to the SDDL-containing
   function; trace callee chain up to 12 hops looking for the TOCTOU
   function name in the `race_function` field. If unreachable after manual
   walk, downgrade to informational.

3. **Confirm procnum.** For `rpc_callable_path_toctou`: verify the
   `proc_idx` in details matches the NDR dispatch entry. Cross-check with
   `rpc_interface.py` output — the procnum must be present in the dispatch
   table for the interface UUID.

4. **Cross-binary finding triage.** For `cross_binary_remote_callable_toctou`:
   confirm that binary A genuinely imports the function named in
   `toctou_function` (check Imports panel in A's BV). The import-table
   match is necessary but not sufficient — also verify the SDDL function's
   callee tree in A eventually reaches the import call site.

5. **Stop conditions:**
   - All composition findings confirmed → escalate to PoC construction.
   - SDDL is read-only → dismiss `remote_callable_toctou` as FP.
   - TOCTOU unreachable via manual walk → downgrade cooccurrence to LOW.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/windows_defender_attack_surface]]` — BlueHammer
  (remote_callable_toctou shape) and RedSun (rpc_callable_cloud_stall shape).
- `[[Memory/Knowledge/argus_detector_design_principles]]` — composition is
  the gate-1 → gate-2 transition for multi-primitive findings.

## Divergence policy

- **Programmatic authoritative for:** callgraph-reachability (same-binary
  BFS up to depth 12), import-table bridge (cross-binary v2), NDR procnum
  identification, SDDL co-location.
- **Manual authoritative for:** table-driven dispatch reachability (COM
  v-table, ALPC, RPC via `RpcServerRegisterIf` with dynamic method
  resolution). The programmatic cooccurrence track signals these cases;
  manual walk confirms or dismisses.
- **Both must agree for:** the `lpe_class` classification in finding
  details (`path-race` vs `token-race`). If manual analysis finds a
  different race type than `_classify_lpe_shape` computed, update the
  TOCTOU evidence payload or the classification logic.

## Operator-validation checklist

- [ ] `test_composition.py` — 30 tests pass (full suite green, 154 total).
- [ ] `remote_callable_toctou` fires on MpSvc.dll with permissive SDDL +
      TOCTOU in same binary; `reachability_hops` ≤ 12 in details.
- [ ] `cross_binary_remote_callable_toctou` fires when A imports B's TOCTOU
      function; does NOT fire when function names don't match.
- [ ] `rpc_callable_path_toctou` fires on MpSvc.dll after NDR v3b scan;
      `proc_idx=42` present in emitted findings.
- [ ] Substrate-coherence: `jm associate "remote_callable_toctou"` surfaces
      `windows_defender_attack_surface`.
- [ ] Read-only SDDL (GR/KR on WD) does not propagate to composition
      findings (fix 2.7 regression guard passes in `test_sddl.py`).
