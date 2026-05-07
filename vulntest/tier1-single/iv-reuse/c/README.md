# IV reuse — C / Windows

Two `BCryptEncrypt` calls passing the same statically-allocated
zero-initialised IV buffer. Detector: `analysis/crypto.py:find_iv_reuse`.
Heuristic: same IV identity (`("addr", &shared_iv)`) used at 2+ cipher-init
sites — emits `iv_reuse`.

The remediation generates a fresh CSPRNG IV per encryption via
`BCryptGenRandom`. The IVs are stack-local — the IV-reuse identity
extractor correctly returns `None` for stack-relative addresses, so
no `iv_reuse` finding fires.

Knowledge: `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]`
CWE: 329, 323.
