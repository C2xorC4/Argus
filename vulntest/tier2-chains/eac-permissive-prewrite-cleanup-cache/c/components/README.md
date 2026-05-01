# Components — per-primitive Tier-1 cross-links

Each link in this chain is also documented as an isolated Tier-1
cell. Operators validating the chain can solve each Tier-1
challenge first, then compose them here.

| # | Primitive | Tier-1 cell |
|---|---|---|
| 1 | Permissive SDDL on named IPC | [`../../../../tier1-single/permissive-sddl/c/`](../../../../tier1-single/permissive-sddl/c/) |
| 2 | Pre-verification write | [`../../../../tier1-single/pre-verify-write/c/`](../../../../tier1-single/pre-verify-write/c/) |
| 3 | Missing cleanup on fail | (covered by pre-verify-write failure branch) |
| 4 | Trusted-path cache load | (chain-specific; no isolated Tier-1) |

## Phase 0 status

Skeleton only — full composed source / PoC are Phase 1+ work.
