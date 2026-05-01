# UE5 chain — PRNG → cookie-forge → amplification

## Brief

Skeleton of the UE5 server-crash chain. Three linked primitives:

```
[weak PRNG seeds HandshakeSecret]   ← T1: tier1-single/prng-security-path
            │
            ▼  attacker recovers HandshakeSecret offline
[cookie-forge → signed-token bypass]
            │
            ▼  attacker forges signed connection cookies
[FString allocation amplification]
            │
            ▼  size amplifier triggers server crash / DoS
        IMPACT
```

Knowledge: `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]`,
`[[Memory/Knowledge/ue5_fstring_allocation_amplification]]`,
`[[Memory/Knowledge/ue5_server_crash_chain_prng_fstring]]`.

**Difficulty:** `2.0.3` (Tier 2, no obfuscation, 3-link chain).

## Layout

- `components/` — cross-links to Tier-1 cells (PRNG, integer-OF
  → allocation as nearest analog for FString amplification)
- `source/` — composed C++ program with all three primitives
- `expected.json` — findings manifest
- `poc/` — full-chain PoC (Phase 3) + per-primitive sub-PoCs
- `remediation/` — one fix per link

## Phase 0 status

Skeleton only.

## Cross-links

- [`tier1-single/prng-security-path/cpp/`](../../../tier1-single/prng-security-path/cpp/)
- [`tier1-single/integer-overflow/cpp/`](../../../tier1-single/integer-overflow/cpp/)
  (related to FString amplification — multiplication wrap into
  allocator)

## Operator-validation checklist

- [ ] All three primitive findings in expected.json
- [ ] `analysis/chains.py` emits chain-pattern finding
- [ ] Substrate-coherence check via `jm associate`
