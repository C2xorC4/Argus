# Argus — current progression list

Authoritative ordering for forward work, established 2026-05-07.
Supersede only by explicit re-prioritisation. Operator's blackbox-
testing posture is the ordering driver — Phase 1 binary-only work
ranks above Phase 2 source-aware work unless impact difference is
large.

## Tier 0 — Cross-cutting (do first; affects every promotion)

| # | Item | Effort | Status |
|---|---|---|---|
| 0.1 | Wider clean-corpus FP sweep (Linux ELF + real-world targets) | half-day | ✅ done 2026-05-07 (15 Windows binaries, results in `dev/corpus_sweep_2026-05-07.json`) |
| 0.2 | Substrate-coherence check — `jm associate` against new findings, optional `--substrate-check` flag in runner | 1-2h | ✅ done 2026-05-07 (`runner.py --substrate-check`; fuzzy token-overlap matching) |
| 0.3 | Per-module `manual_workflows/<module>.md` for the modules touched in the May 7 session | 1 day | ✅ done 2026-05-07 (9 docs: sddl, integrity_check_order, cleanup_dominance, trusted_path, triage, exploit, differ, patch, output-vendor) |

**Pre-existing modules still missing manual_workflow docs** (separate
follow-on, not session-scope): `uninit`, `types`, `race`,
`windows_drivers`, `source_surface`, plus user-authored
`linux_exploit`. Each adds gate-6 readiness for that module
specifically.

## Tier 1 — High-impact binary-only (most blackbox runs benefit)

| # | Phase | Item | Effort | Impact |
|---|---|---|---|---|
| 1.1 | 1 | Process-handle taint chain (`PsLookupProcessByProcessId` / `ObReferenceObjectByPointer`) — raises BYOVD process-killer coverage from 6/13 to ~12/13 | 1-2 days | ✅ done 2026-05-08 (sink-as-propagator entries for ZwOpenProcess, PsLookup*, ObReferenceObjectByPointer; sink hits no longer short-circuit propagation when the call is also a propagator). Empirical 6/13 → 12/13 validation pending BYOVD-corpus access. |
| 1.2 | 1 | Buffer-content taint — tainted-stack-slot bookkeeping in `taint.py` bridges the `&var_N` aliasing gap (snprintf taints rcx#1=&var_N; system reads from rcx_1#2=&var_N — same slot, different SSA var). | 1-2 day build | ✅ done 2026-05-08 (C cell PASS, no regressions across Phase 2 + Tier-2; cpp variant deferred — std::string MLIL shape is a separate gap) |
| 1.3 | 2-blackbox | `cleanup_dominance` v2 — verify-call-presence gate, suppresses notepad-class FP | 0.5 day | ✅ done 2026-05-08 (FPs went 12 → 0 in clean-corpus sweep; Tier-2 EAC PASS preserved) |
| 1.4 | 2-blackbox | `trusted_path` v2 — xref/taint from path-string to load callsite | 1 day | Medium-high |
| 1.5 | 1 | E2 robustness — CcProtect + Viragt64 dispatch-write paths | 0.5-1 day | Medium |

## Tier 2 — Phase 1 lower-impact

| # | Item | Effort |
|---|---|---|
| 2.1 | Architecture-notes Knowledge entry on TTP-altitude design choice | 2-3h |
| 2.2 | Decimal IOCTL constant parsing in `source_surface` | 2-3h |
| 2.3 | K7-style standalone-PoC source parsing | 0.5 day |

## Tier 3 — Phase 2 source-required (lowest blackbox utility)

| # | Item | Effort |
|---|---|---|
| 3.1 | Source-side taint as independent pass | 2-3 days |
| 3.2 | Cross-function structural alignment for zero-callee functions | 1 day |
| 3.3 | DWARF / PDB consumption when debug symbols exist | 1-2 days |
| 3.4 | libclang / tree-sitter parser swap | 1-2 days |
| 3.5 | IOCTL switch enumeration from binary | 1-2 days |

## Sprint plan

**Sprint 1:** Tier 0 — every detector gets gate-2 baseline + manual_workflow.

**Sprint 2:** Tier 1.1, 1.2, 1.3 — real detection deltas on common blackbox cases.

**Sprint 3:** Tier 1.4, 1.5, 2.1 — finish the detector queue + ship the architecture-notes Knowledge entry.

**Defer:** Tier 3 — revisit only when an active engagement requires source-aware analysis.

## Promotion-gate dependencies

- **Gate 2 (No FP):** closed once Tier 0.1 completes for all detectors with results captured per-detector.
- **Gate 3 (PoC validation):** blocked on Phase 4 verification integration; not addressed by this progression list.
- **Gate 6 (Documentation):** closed once Tier 0.3 ships the missing `manual_workflows/<module>.md` files.

After Sprint 1 completes, Phase 1 + Phase 2 detectors that already pass gates 1, 4, 5 will have all-non-PoC gates clean — promotion-ready except for the Phase 4 dependency.
