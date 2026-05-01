# Tier 2 — Commonly-chained vulnerabilities

After Tier 1 lands in good shape, Tier 2 builds out the matrix for
**commonly-chained** vulnerability patterns. Real-world findings
increasingly require chain composition; the toolchain's chain-
detection (`scripts/analysis/chains.py`) and chain-construction
(Phase 3 `scripts/exploit/chain.py`) need a corpus to validate
against.

## Layout per chain

```
<chain-name>/<language>/
├── source/             ← minimal program with all chain primitives
├── components/         ← standalone trigger for each primitive in
│                          isolation (cross-link to Tier 1 cells)
├── Makefile
├── expected.json       ← findings manifest covering EACH primitive
│                          PLUS the chain pattern (chains.py emission)
├── poc/                ← full-chain exploit + per-primitive sub-PoCs
├── README.md
└── remediation/        ← one fix per link in the chain (defence-
                          in-depth: any fix breaks the chain, all
                          fixes are recommended)
```

## Initial chain catalogue

See [`../INDEX.md`](../INDEX.md) §Tier 2 for the full table with
Knowledge anchors. Highest-priority Phase 1 build-outs:

1. **Permissive SDDL → pre-verify-write → missing cleanup → cache poison**
   — the EAC chain. Validates against the operator's already-
   confirmed `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]`
   research.
2. **PRNG → cookie-forge → amplification** — the UE5 chain.
   Validates against
   `[[Memory/Knowledge/ue5_server_crash_chain_prng_fstring]]`.
3. **Direct-syscall + TLS-callback + hidden-thread** — full evasion
   stack as a chain (malware variant).

## Phase 0 status

Empty. Phase 0 commits the directory + README + INDEX entries.
Phase 1 builds the EAC and UE5 skeleton chains as the first two
cells (they are validated by real-world research already in the
corpus).
