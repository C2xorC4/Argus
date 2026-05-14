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
`windows_drivers`, `source_surface`, plus user-authored `linux_exploit`.
**NightmareEclipse additions (gate-6 pending):** `rpc_interface`,
`cloud_files`, `composition`, `remote_chain`. Each adds gate-6 readiness
for that module specifically.

## Tier 1 — High-impact binary-only (most blackbox runs benefit)

| # | Phase | Item | Effort | Impact |
|---|---|---|---|---|
| 1.1 | 1 | Process-handle taint chain (`PsLookupProcessByProcessId` / `ObReferenceObjectByPointer`) — raises BYOVD process-killer coverage from 6/13 to ~12/13 | 1-2 days | ✅ done 2026-05-08 (sink-as-propagator entries for ZwOpenProcess, PsLookup*, ObReferenceObjectByPointer; sink hits no longer short-circuit propagation when the call is also a propagator). Empirical 6/13 → 12/13 validation pending BYOVD-corpus access. |
| 1.2 | 1 | Buffer-content taint — tainted-stack-slot bookkeeping in `taint.py` bridges the `&var_N` aliasing gap (snprintf taints rcx#1=&var_N; system reads from rcx_1#2=&var_N — same slot, different SSA var). | 1-2 day build | ✅ done 2026-05-08 (C cell PASS, no regressions across Phase 2 + Tier-2; cpp variant deferred — std::string MLIL shape is a separate gap) |
| 1.3 | 2-blackbox | `cleanup_dominance` v2 — verify-call-presence gate, suppresses notepad-class FP | 0.5 day | ✅ done 2026-05-08 (FPs went 12 → 0 in clean-corpus sweep; Tier-2 EAC PASS preserved) |
| 1.4 | 2-blackbox | `trusted_path` v2 — xref/taint from path-string to load callsite | 1 day | ✅ done 2026-05-11 (per-callsite SSA back-walk; `trusted_path_xref_to_load` HIGH; v1 suppressed when v2 fires; commit `bffceb2`) |
| 1.5 | 1 | E2 robustness — CcProtect + Viragt64 dispatch-write paths | 0.5-1 day | ✅ done 2026-05-11 (commit `bffceb2`) |
| 1.6 | 1 | Gate-6 manual_workflow docs for NE-added modules — `rpc_interface`, `cloud_files`, `composition`, `remote_chain` (four docs) | 0.5 day | ✅ done 2026-05-14 (`analysis-rpc_interface.md`, `analysis-cloud_files.md`, `analysis-composition.md`, `verify-remote_chain.md`) |
| 1.7 | 2 | composition.py v2 — cross-binary reachability: static import table + known service-dispatch table walk so SDDL-protected entry in DLL A can reach TOCTOU in DLL B (currently same-binary only) | 1-2 days | ✅ done 2026-05-14 (`compose_cross_binary` + `_imported_function_names` + `cross_binary_remote_callable_toctou`; `analyze()` accepts `peer_cluster=`; 30 tests; commit `23336c3`) |
| 1.8 | 4 | NightmareEclipse §7–9 — BlueHammer (CONFIRMED-with-patch-mitigation-documented), RedSun (IMPACT_VERIFIED — SYSTEM shell), UnDefend (IMPACT_VERIFIED — Defender update failure) on HMDXIN | 2-4 sessions | High — first Windows multi-process chain IMPACT_VERIFIED transitions |

## Active Operations

| # | Item | Status | Done when |
|---|---|---|---|
| NE.7 | BlueHammer (CVE-2026-33825) on HMDXIN | **Stub** — `_poc/bluehammer_poc.py` ready; needs PROC_IDX from NDR v3 re-run against HMDXIN-specific DLL version | CONFIRMED-with-patch-mitigation-documented (HMDXIN is post-patch) |
| NE.8 | RedSun on HMDXIN | **Stub** — `_poc/redsun_poc.py` ready; needs Cloud Files placeholder step + staging payload | IMPACT_VERIFIED — SYSTEM shell on HMDXIN; payload binary in SYSTEM process list |
| NE.9 | UnDefend on HMDXIN | **Stub** — `_poc/undefend_poc.py` ready | IMPACT_VERIFIED — Defender definition-update failure in Event Log during run; clean resume after exit |
| NE.10 | Comparison — independent PoCs vs public Nightmare-Eclipse reference | ☐ | Diff doc: method choice, sentinel, substitution primitive, reliability, stealth delta |
| NE.11 | Post-mortem — methodology + Argus enhancement backlog | ☐ | Doc committed; Argus issue list filed |

## Tier 2 — Phase 1 lower-impact

| # | Item | Effort |
|---|---|---|
| 2.1 | Architecture-notes Knowledge entry on TTP-altitude design choice | 2-3h |
| 2.4 | `weak_prng_in_security_path` UI/keyboard exclusion filter — "Key" in names like `IsItemKeyFocused`, `IsDeleteKeyInvokedInSearch`, `HandleAccessKeyMessages` triggers the security-path gate; need a denylist of UI/keyboard name tokens | 1-2h | Medium — taskmgr.exe produced 46 FPs on this class (2026-05-13 run) |
| 2.5 | `chains.ue5_prng_cookie_amplification` context discriminator — chain requires game/UE5 binary indicators (e.g. UE5 string markers, module name, high LCG-XOR volume) before firing; currently over-fires on any binary with 46+ weak_prng findings | 1-2h | Medium — taskmgr.exe triggered the chain FP (2026-05-13 run) |
| 2.6 | explorer.exe `rpc_hosted_toctou_cooccurrence` triage — **TRIAGED 2026-05-13**: TOCTOU is in `CLogonTaskFramework::s_WriteOutOOBEDataForOEMApp` (PathFileExistsW→CreateFileW/DeleteFileW on a path var); SDDL findings are KR/GR Read-only grants to World on a registry key and a per-user shared object. Composition BFS hit via Logon/OOBE callgraph proximity, not via an actual low-privilege IPC entry. Finding is **FP at exploitation-grade** — the permissive SDDL does not expose the TOCTOU to a remote low-privilege caller. Relevant follow-ups: SDDL FP class (2.7) + composition module narrative fix (2.8). |
| 2.7 | SDDL detector — Read-only World grant false-positive: registry `KR` to Everyone and object `GR` to Everyone are normal for public resources; detector should gate HIGH on Write/Execute/Create grants, not on Read grants. Currently fires HIGH on any World grant regardless of rights. | 1-2h | Medium — explorer SDDL findings are both benign Read-only |
| 2.8 | composition.py `rpc_hosted_toctou_cooccurrence` description fix | ✅ done 2026-05-13 — replaced Defender-specific "BlueHammer / RedSun" narrative with `_classify_lpe_shape()` (path-race vs token-race discriminator from TOCTOU evidence payload; 6/6 tests pass). `lpe_class` field added to both `remote_callable_toctou` and `rpc_hosted_toctou_cooccurrence` finding details. |
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

**Sprint 1:** Tier 0 — every detector gets gate-2 baseline + manual_workflow. ✅ Done 2026-05-07.

**Sprint 2:** Tier 1.1, 1.2, 1.3 — real detection deltas on common blackbox cases. ✅ Done 2026-05-08.

**Sprint 3 (active):** NightmareEclipse §7–9 (NE.7–NE.9) — first Windows multi-process chain IMPACT_VERIFIED runs against HMDXIN. Run concurrently: Tier 1.4 (trusted_path v2) + Tier 1.6 (gate-6 docs for NE modules).

**Sprint 4:** Tier 1.5 (E2 robustness) + Tier 1.7 (composition.py v2 cross-binary reachability) + Tier 2.1 (architecture-notes Knowledge entry). NE.10–NE.11 (comparison + post-mortem) close out the NightmareEclipse arc.

**Defer:** Tier 3 — revisit only when an active engagement requires source-aware analysis.

## Promotion-gate dependencies

- **Gate 2 (No FP):** closed once Tier 0.1 completes for all detectors with results captured per-detector.
- **Gate 3 (PoC validation):** blocked on Phase 4 verification integration; not addressed by this progression list.
- **Gate 6 (Documentation):** closed once Tier 0.3 ships the missing `manual_workflows/<module>.md` files.

After Sprint 1 completes, Phase 1 + Phase 2 detectors that already pass gates 1, 4, 5 will have all-non-PoC gates clean — promotion-ready except for the Phase 4 dependency.
