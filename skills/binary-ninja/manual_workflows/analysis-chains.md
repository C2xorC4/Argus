# `analysis/chains.py` — Manual-Workflow Companion

## Purpose

Composes Tier-2 chain Findings from Tier-1 primitives produced by
upstream modules (taint, heap, crypto, obfuscation, attack_surface).
Chain templates in `heuristics/chains.py`:

- `eac_permissive_prewrite_cleanup_cache` — EAC arbitrary-write chain
- `ue5_prng_cookie_amplification` — UE5 server-crash chain
- `infoleak_uaf_rop` — classical heap chain
- `fmtleak_stack_rop` — format-string + stack-OF chain
- `heapof_vtable_rop` — C++ heap-OF + vtable-hijack chain
- `toctou_junction_system_write` — TOCTOU + junction redirect chain
- `typeconf_arbread_deref` — type-confusion → RCE chain
- `deserialization_gadget_rce` — deserialisation gadget chain
- `malware_evasion_stack` — direct-syscall + TLS + hidden-thread

A chain composes only when *all* listed primitive categories appear
in the upstream Findings.

## Programmatic invocation

```python
from scripts.analysis import chains
chain_findings = chains.analyze(session, existing_findings=upstream_findings)
# Or run upstream automatically:
chain_findings = chains.analyze(session)   # gathers upstream itself
```

## Manual workflow (Binary Ninja UI)

Chains are *composed*, not *discovered* in the UI. The manual
workflow is to confirm a programmatically-emitted chain by
verifying the per-primitive findings on the underlying binary:

1. **Open binary.** Pull up the upstream findings list (from
   programmatic identification stage).
2. **For each primitive in the chain template:**
   - Locate the primitive Finding's `address` and `function`.
   - Navigate to the function in HLIL.
   - Confirm the primitive's structural evidence (per the relevant
     analysis module's manual workflow doc).
3. **Verify ordering and connection** (Phase 1+ — currently the
   programmatic detector is set-based, not order-aware):
   - For EAC chain: the privileged service path must reach all four
     primitives; trace from the IPC handler through the write to
     the verify-fail branch to the cache loader.
   - For UE5 chain: HandshakeSecret must flow from the PRNG into
     cookie validation into the amplifier.
4. **Decision points:**
   - All primitives present + structural connection verified →
     CONFIRMED state for the chain Finding (operator promotes).
   - All primitives present but no structural connection (separate
     bugs that coincidentally share the right shapes) → DISMISSED
     for the chain Finding; the per-primitive Findings remain.
   - Some primitives missing → chain template doesn't match;
     review for variant chain shapes.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — full EAC
  chain analysis with mechanics per primitive.
- `[[Memory/Knowledge/ue5_server_crash_chain_prng_fstring]]` — UE5
  chain analysis with composition.
- `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]` and
  `[[Memory/Knowledge/ue5_fstring_allocation_amplification]]` — the
  per-primitive entries.

### Reference book chapters

- *The Art of Software Security Assessment* — chain composition
  patterns.
- *A Bug Hunter's Diary* — real-world chain assemblies.

## Divergence policy

- **Set-based composition (Phase 1):** programmatic is presence-
  matching only; manual must confirm structural connection. Phase
  1+ adds reachability validation.
- **Chain templates as data:** programmatic catalog is in
  `heuristics/chains.py` and is the source of truth. Disagreements
  drive a tuning PR (add a missing chain shape, refine a primitive
  list).
- **Severity inheritance:** chain Findings emit at the highest
  severity in their template (typically critical). Manual review
  may downgrade for partial matches.

## Operator-validation checklist

- [ ] Run on `vulntest/tier2-chains/eac-permissive-prewrite-cleanup-cache/c/`
      build → expect chain_pattern Finding citing
      `eac_eos_arbitrary_write_chain`.
- [ ] Run on `vulntest/tier2-chains/ue5-prng-cookie-amplification/cpp/`
      build → expect chain_pattern Finding citing the UE5
      Knowledge entries.
- [ ] Synthetic-test scenario: feed in only 3/4 EAC primitives →
      expect 0 chain Findings.
- [ ] Substrate-coherence check on every emitted chain Finding.
