# EAC chain — permissive SDDL → pre-verify-write → missing cleanup → cache poison

## Brief

Skeleton of the EAC EOS arbitrary-write chain. Four linked
primitives, each individually a Tier-1 cell, composed into the
end-to-end exploitation path.

```
[permissive SDDL on named IPC]   ← T1: tier1-single/permissive-sddl
            │
            ▼  unprivileged process connects to privileged service
[pre-verification write]          ← T1: tier1-single/pre-verify-write
            │
            ▼  privileged service writes attacker bytes to trusted path
[missing cleanup on verify fail]  ← T1: pre-verify-write (failure branch)
            │
            ▼  attacker bytes persist in trusted-path
[cache load trusts trusted-path]  ← chain-specific: downstream loader
            │
            ▼  attacker code reaches privileged context
        IMPACT
```

Knowledge: `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]`.

**Difficulty:** `2.0.4` (Tier 2, no obfuscation, 4-link chain).

## Layout

- `components/` — symbolic links / cross-references to Tier-1 cells
  for each primitive
- `source/` — minimal composed program with all four primitives
- `expected.json` — findings manifest: 4 primitive findings + 1
  chain-pattern finding from `analysis/chains.py`
- `poc/` — full-chain exploit (Phase 3 work) + per-primitive
  sub-PoCs
- `remediation/` — one fix per link

## Phase 0 status

This skeleton commits the directory structure and links to source
Tier-1 cells. Phase 1 builds the composed source/ program; Phase 3
builds the full-chain exploit.

## Cross-links

- [`tier1-single/permissive-sddl/c/`](../../../tier1-single/permissive-sddl/c/)
- [`tier1-single/pre-verify-write/c/`](../../../tier1-single/pre-verify-write/c/)
- (cleanup-on-fail covered by pre-verify-write failure-branch absence)
- (cache-load is chain-specific; no Tier-1 isolated form)

## Operator-validation checklist

- [ ] All four primitive findings present in expected.json
- [ ] `analysis/chains.py` emits the chain-pattern finding
- [ ] Per-primitive sub-PoCs link to Tier-1 cell PoCs
- [ ] Substrate-coherence check: `jm associate "EAC arbitrary write
      chain"` surfaces the canonical Knowledge entry
