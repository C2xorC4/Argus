# VulnTest Challenge Index

Generated index of all VulnTest cells by class, language, tier, and
difficulty. Phase 0 builds the C/C++ baseline plus headline-four
managed-language variants and chain skeletons. Phase 1 fills out
the rest as detector modules mature.

Each row links to a cell's `README.md` (challenge brief).

## Tier 1 — Isolated single-vulnerability variants

| Class | Knowledge anchor | C | C++ | C# | Rust | Go |
|---|---|---|---|---|---|---|
| Stack buffer overflow | `[[Memory/Knowledge/hw_stack_overflow_mechanics]]` | [10](tier1-single/stack-overflow/c/) | [10](tier1-single/stack-overflow/cpp/) | [10](tier1-single/stack-overflow/csharp/) | [10](tier1-single/stack-overflow/rust/) | [10](tier1-single/stack-overflow/go/) |
| Heap buffer overflow | `[[Memory/Knowledge/wnapi_heap_internals]]` | [10](tier1-single/heap-overflow/c/) | [10](tier1-single/heap-overflow/cpp/) | — | — | — |
| Use-after-free | `[[Memory/Knowledge/wnapi_heap_internals]]` | [10](tier1-single/use-after-free/c/) | [10](tier1-single/use-after-free/cpp/) | [10](tier1-single/use-after-free/csharp/) | [10](tier1-single/use-after-free/rust/) | [10](tier1-single/use-after-free/go/) |
| Double-free | `[[Memory/Knowledge/wnapi_heap_internals]]` | [10](tier1-single/double-free/c/) | [10](tier1-single/double-free/cpp/) | — | — | — |
| Format-string | (legacy baseline) | [10](tier1-single/format-string/c/) | [10](tier1-single/format-string/cpp/) | — | — | — |
| Integer overflow → allocation | `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` | [10](tier1-single/integer-overflow/c/) | [10](tier1-single/integer-overflow/cpp/) | — | — | — |
| Off-by-one bounds check | `[[Memory/Knowledge/ue5_fstring_allocation_amplification]]` | [10](tier1-single/off-by-one/c/) | [10](tier1-single/off-by-one/cpp/) | — | — | — |
| Type confusion | `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` | [10](tier1-single/type-confusion/c/) | [10](tier1-single/type-confusion/cpp/) | [10](tier1-single/type-confusion/csharp/) | [10](tier1-single/type-confusion/rust/) | [10](tier1-single/type-confusion/go/) |
| TOCTOU / race | `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` | [10](tier1-single/toctou/c/) | [10](tier1-single/toctou/cpp/) | — | — | — |
| Uninitialised memory disclosure | `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` | [10](tier1-single/uninit-mem-disclosure/c/) | [10](tier1-single/uninit-mem-disclosure/cpp/) | — | — | — |
| PRNG-in-security-path | `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]` | [10](tier1-single/prng-security-path/c/) | [10](tier1-single/prng-security-path/cpp/) | — | — | — |
| Command injection | (legacy baseline) | [10](tier1-single/command-injection/c/) | [10](tier1-single/command-injection/cpp/) | — | — | — |
| Path traversal | (legacy baseline) | [10](tier1-single/path-traversal/c/) | [10](tier1-single/path-traversal/cpp/) | — | — | — |
| LCG / XOR string cipher | `[[Memory/Knowledge/gameguard_research_22_findings]]` | [10](tier1-single/lcg-xor-cipher/c/) | [10](tier1-single/lcg-xor-cipher/cpp/) | — | — | — |
| Insecure deserialisation | (cross-cluster) | — | — | [10](tier1-single/deserialization/csharp/) | [10](tier1-single/deserialization/rust/) | [10](tier1-single/deserialization/go/) |
| Permissive SDDL on named IPC (Win) | `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` | [10](tier1-single/permissive-sddl/c/) | [10](tier1-single/permissive-sddl/cpp/) | — | — | — |
| NULL-DACL on IPC (Win) | `[[Memory/Knowledge/gameguard_research_22_findings]]` | [10](tier1-single/null-dacl/c/) | [10](tier1-single/null-dacl/cpp/) | — | — | — |
| Pre-verification write w/ no cleanup (Win) | `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` | [10](tier1-single/pre-verify-write/c/) | [10](tier1-single/pre-verify-write/cpp/) | — | — | — |
| IV reuse (Win) | `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]` | [10](tier1-single/iv-reuse/c/) | — | — | — | — |
| Direct-syscall stub (Win) | `[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]` | [10](tier1-single/direct-syscall/c/) | [10](tier1-single/direct-syscall/cpp/) | — | — | — |
| TLS-callback first-stage (Win) | `[[Memory/Knowledge/em_covert_execution_tls_seh]]` | [10](tier1-single/tls-callback/c/) | [10](tier1-single/tls-callback/cpp/) | — | — | — |
| SEH/VEH handler abuse (Win) | `[[Memory/Knowledge/em_veh_hwbp_hook_evasion]]` | [10](tier1-single/seh-veh-abuse/c/) | [10](tier1-single/seh-veh-abuse/cpp/) | — | — | — |
| Hidden-from-debugger thread (Win) | `[[Memory/Knowledge/em_covert_execution_tls_seh]]` | [10](tier1-single/hidden-thread/c/) | [10](tier1-single/hidden-thread/cpp/) | — | — | — |
| PEB anti-debug field (Win) | `[[Memory/Knowledge/em_peb_antidebug_fields]]` | [10](tier1-single/peb-antidebug/c/) | [10](tier1-single/peb-antidebug/cpp/) | — | — | — |
| API hash resolution (Win) | `[[Memory/Knowledge/em_hook_evasion_three_approaches]]` | [10](tier1-single/api-hash-resolution/c/) | [10](tier1-single/api-hash-resolution/cpp/) | — | — | — |
| APC injection variant (Win) | `[[Memory/Knowledge/em_advanced_injection_variants]]` | [10](tier1-single/apc-injection/c/) | [10](tier1-single/apc-injection/cpp/) | — | — | — |

Languages beyond the five-column matrix (Swift, Objective-C, JVM,
Pascal/Delphi, D, Zig, Nim, Fortran, Ada) queue for Phase 1+ as
priority demands.

## Tier 2 — Commonly-chained vulnerabilities

| Chain | Components | Reference | Cell |
|---|---|---|---|
| Permissive SDDL → pre-verify-write → missing cleanup → cache poison | named-IPC misconfig + write-then-verify + no rollback + cache trust | `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` | [24](tier2-chains/eac-permissive-prewrite-cleanup-cache/c/) |
| PRNG → cookie-forge → amplification | weak PRNG + signed-token bypass + size amplification | `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]`, `[[Memory/Knowledge/ue5_fstring_allocation_amplification]]` | [23](tier2-chains/ue5-prng-cookie-amplification/cpp/) |
| Info-leak → UAF → ROP | stack/heap address disclosure + lifetime bug + gadget chain | classical | planned (Phase 1) |
| Format-string-leak → stack-OF → ROP | format-string for canary/PIE leak + bounded-OF + ROP | classical | planned (Phase 1) |
| Heap-OF → vtable-hijack → ROP | adjacent-chunk corruption + C++ object overlap + virtual call hijack | C++ classical | planned (Phase 1) |
| TOCTOU race → junction redirect → SYSTEM write | symlink/junction abuse + privileged file op | `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` | planned (Phase 1) |
| Type-confusion → arbitrary-read → deref-anywhere | runtime-type bypass + read primitive + crafted pointer | RCE primitive composition | planned (Phase 1) |
| Deserialisation → gadget chain → RCE | unsafe deserialiser + class-graph gadgets + execution | language-specific | planned (Phase 1) |
| Direct-syscall + TLS-callback + hidden-thread | full evasion stack as a chain (malware) | `[[Memory/Knowledge/em_*]]` | planned (Phase 1) |

## Tier 3 — Obfuscated variants

| Obfuscation | Source cell | Cell |
|---|---|---|
| Symbol stripping | `tier1-single/stack-overflow/c` | [31](tier3-obfuscated/strip-stack-overflow-c/) |
| Name decoration / random-name | (queued) | planned (Phase 1) |
| Control-flow flattening | (queued) | planned (Phase 1) |
| Opaque predicates | (queued) | planned (Phase 1) |
| Dummy-code injection | (queued) | planned (Phase 1) |
| String encryption (LCG-XOR) | (queued, source `lcg-xor-cipher`) | planned (Phase 1) |
| Inlining noise + dead code | (queued) | planned (Phase 1) |
| Compiler-driven (Straylight) | (queued) | planned (Phase 1) |

## Difficulty rating

Difficulty is `(tier × 10) + obfuscation_level + chain_depth`,
where:

- `tier` ∈ {1, 2, 3}
- `obfuscation_level` ∈ {0, 1, 2, 3} (none / single / stacked / extreme)
- `chain_depth` is the number of linked primitives (0 for Tier 1)

Examples:

- Tier-1 stack-overflow (no obfuscation, no chain) = `10`
- Tier-2 EAC chain (4 primitives) with no obfuscation = `24`
- Tier-3 type-confusion under stacked obfuscation = `32`

Operator practice tracks: pick a difficulty band, work through
challenges in that band, compare manual results to toolchain output.

## Phase 0 deliverable summary

- Tier 1: 60 cells (C+C++ baseline + headline-four C#/Rust/Go variants + Win-specific cells with C primary, C++ pass-through)
- Tier 2: 2 chain skeletons (EAC, UE5)
- Tier 3: 1 obfuscation demo (symbol-stripping)

Phase 1 fills out the remaining Tier-2 chains and Tier-3 obfuscation
layers as detector modules mature.
