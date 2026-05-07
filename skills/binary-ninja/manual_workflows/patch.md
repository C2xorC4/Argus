# `patch/` — Manual-Workflow Companion

## Purpose

Phase 5 cross-cutting — authorised binary modification for CTF /
RE / authorised security testing. Per `docs/PIPELINE.md`, the
binary-patcher is gated behind operator confirmation regardless of
which stage invokes it.

Skeleton in this revision: data shapes + entry-point API with
`dry_run=True` default. Full implementation (NOP / branch /
string / redirect / code-cave / metadata fixup) deferred.

## Public API

```python
from scripts.patch import Patch, PatchPlan, apply_patch

plan = PatchPlan(
    target_binary="vuln.exe",
    target_sha1="abc123...",
    patches=[
        Patch(kind="nop", offset=0x1000, new_bytes=b"\x90\x90"),
    ],
    operator_authorised=True,        # explicit gate
)
result = apply_patch(bv, plan, dry_run=False, output_path="patched.exe")
```

The `dry_run=True` default refuses to write bytes; explicit opt-out
is required to mutate the binary.

## Manual workflow (Binary Ninja UI)

1. Open the target binary.
2. Locate the instruction(s) to modify.
3. Inspect surrounding context — confirm the patch site is the
   intended one and the new bytes don't break adjacent flow.
4. **Patch via Binja:** Edit → "Convert to nop" / "Always branch"
   / Patch bytes. Or programmatically via `bv.write(addr, bytes)`.
5. **Save:** File → Save as... (or programmatic export). For PE,
   verify the resulting binary's sections still align with the
   PE optional header; for ELF, ensure section headers are still
   coherent.
6. **Test the patched binary:** run + verify the patch achieves
   its goal (bypass, NOP, redirect, etc.) without breaking
   unrelated functionality.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/em_covert_execution_tls_seh]]` — covert-
  execution context where patching is sometimes used as research
  tooling (TLS-callback redirects, SEH chain modifications).

### Reference book chapters

- *Practical Binary Analysis* — chapters on binary patching.

## Divergence policy

- **Programmatic authoritative for:** the byte-level edit (offset,
  new_bytes) — mechanical accuracy.
- **Manual authoritative for:** patch-site selection (which
  instruction to modify) and metadata fixup (PE checksums,
  signatures, ELF section headers).
- **Always require explicit operator authorisation** for live
  apply (dry_run=False). The pipeline default is dry-run; mutating
  bytes requires deliberate intent recorded in the
  `PatchPlan.operator_authorised` flag.

## Operator-validation checklist

- [ ] `apply_patch(bv, plan, dry_run=True)` returns
      `PatchResult(applied=False)` with at least one entry in
      `failures` describing the dry-run gate.
- [ ] `apply_patch(bv, plan_with_authorised_false, dry_run=False)`
      refuses to apply (operator_authorised gate).
- [ ] Live apply with both gates set produces a patched binary
      that loads correctly.
