# PoC — Phase 3 build target

The full-chain PoC connects to the named pipe as an unprivileged
user, sends a payload that triggers the pre-verification write,
ensures the verification check fails (so cleanup-skip applies),
then waits for the cache loader to consume the dropped bytes.

Phase 0 commits this README; Phase 3 builds the full chain. Per-
primitive sub-PoCs cross-link to Tier-1 cell PoCs.
