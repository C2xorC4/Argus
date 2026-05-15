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
| 0.3 | Per-module `manual_workflows/<module>.md` for the modules touched in the May 7 session | 1 day | ✅ done 2026-05-07 (9 docs: sddl, integrity_check_order, cleanup_dominance, trusted_path, triage, exploit, differ, patch, output-vendor). NE-added modules: ✅ done 2026-05-14 (rpc_interface, cloud_files, composition, remote_chain — commit `bb8a660`) |
| 0.4 | Gate-6 completion — `manual_workflows/` docs for remaining pre-existing modules: `uninit`, `types`, `race`, `windows_drivers`, `source_surface`, `linux_exploit` (6 docs) | 0.5 day | Open |

## Tier 1 — High-impact binary-only (most blackbox runs benefit)

| # | Phase | Item | Effort | Impact |
|---|---|---|---|---|
| 1.1 | 1 | Process-handle taint chain (`PsLookupProcessByProcessId` / `ObReferenceObjectByPointer`) — raises BYOVD process-killer coverage from 6/13 to ~12/13 | 1-2 days | ✅ done 2026-05-08 (sink-as-propagator entries for ZwOpenProcess, PsLookup*, ObReferenceObjectByPointer; sink hits no longer short-circuit propagation when the call is also a propagator). Empirical 6/13 → 12/13 validation pending BYOVD-corpus access. |
| 1.2 | 1 | Buffer-content taint — tainted-stack-slot bookkeeping in `taint.py` bridges the `&var_N` aliasing gap (snprintf taints rcx#1=&var_N; system reads from rcx_1#2=&var_N — same slot, different SSA var). | 1-2 day build | ✅ done 2026-05-08 (C cell PASS, no regressions across Phase 2 + Tier-2; cpp variant deferred — std::string MLIL shape is a separate gap) |
| 1.3 | 2-blackbox | `cleanup_dominance` v2 — verify-call-presence gate, suppresses notepad-class FP | 0.5 day | ✅ done 2026-05-08 (FPs went 12 → 0 in clean-corpus sweep; Tier-2 EAC PASS preserved) |
| 1.4 | 2-blackbox | `trusted_path` v2 — xref/taint from path-string to load callsite | 1 day | ✅ done 2026-05-11 (per-callsite SSA back-walk; `trusted_path_xref_to_load` HIGH; v1 suppressed when v2 fires; commit `bffceb2`) |
| 1.5 | 1 | E2 robustness — CcProtect + Viragt64 dispatch-write paths | 0.5-1 day | ✅ done 2026-05-11 (nested-add offset fold in `_trace_offset_any`; BYOVD-13 dispatch resolution 12/13 → 13/13; commit `bffceb2`) |
| 1.6 | 1 | Gate-6 manual_workflow docs for NE-added modules — `rpc_interface`, `cloud_files`, `composition`, `remote_chain` (four docs) | 0.5 day | ✅ done 2026-05-14 (`analysis-rpc_interface.md`, `analysis-cloud_files.md`, `analysis-composition.md`, `verify-remote_chain.md`; commit `bb8a660`) |
| 1.7 | 2 | composition.py v2 — cross-binary reachability via import-table bridge so SDDL-protected entry in DLL A can reach TOCTOU in DLL B | 1-2 days | ✅ done 2026-05-14 (`compose_cross_binary` + `_imported_function_names` + `cross_binary_remote_callable_toctou`; `analyze()` accepts `peer_cluster=`; 30 tests; commit `23336c3`) |
| 1.8 | 4 | NightmareEclipse §7–9 — BlueHammer, RedSun, UnDefend PoC validation on HMDXIN | 2-4 sessions | ✅ partial 2026-05-13: BlueHammer CONFIRMED (post-patch — race window closed; patch mitigation documented); RedSun CONFIRMED (Cloud Files step absent, §8b deferred); UnDefend **IMPACT_VERIFIED** (Defender update failure in Event Log confirmed). See Active Operations for §8b open thread. |

## Active Operations

| # | Item | Status | Done when |
|---|---|---|---|
| NE.7 | BlueHammer (CVE-2026-33825) on HMDXIN | ✅ **CONFIRMED** 2026-05-13 — post-patch HMDXIN; race window closed by patch. Patch mitigation documented in §10 comparison. | CONFIRMED-with-patch-mitigation-documented ✅ |
| NE.8 | RedSun on HMDXIN | ✅ **CONFIRMED** 2026-05-13 — Cloud Files placeholder step absent from PoC; System32 write blocked. `cloudfiles_primitive.py` built and ready (commit `f6fbe59`). §8b deferred. | IMPACT_VERIFIED — SYSTEM shell on HMDXIN; payload binary in SYSTEM process list |
| NE.8b | RedSun §8b — IMPACT_VERIFIED via Cloud Files placeholder | **Open** — `cloudfiles_primitive.py` (ctypes wrapper for CldApi.dll) ready in `NightmareEclipse/_poc/`. Needs `CfRegisterSyncRoot` + `CfConnectSyncRoot` + placeholder creation + NTFS junction swap wired into `redsun_poc.py` trigger. HMDXIN is the target (unpatched as of 2026-05-14). | IMPACT_VERIFIED — SYSTEM shell; probe file in System32 or SYSTEM process list |
| NE.9 | UnDefend on HMDXIN | ✅ **IMPACT_VERIFIED** 2026-05-13 — Defender definition-update failure confirmed in Event Log during run; clean service resume after exit. | Done ✅ |
| NE.10 | Comparison — independent PoCs vs public Nightmare-Eclipse reference | ✅ **done** 2026-05-14 (session 007) — `section_10_comparison.md` committed; proc_idx=42 row updated; NDR divergence entry marked FIXED. | Done ✅ |
| NE.11 | Post-mortem — methodology + Argus enhancement backlog | ✅ **done** 2026-05-14 (session 007) — `section_11_postmortem.md` committed; three Argus extensions documented (cloud_files detector ✅ done, NDR v3b ✅ done, rpc_callable_cloud_stall ✅ done). | Done ✅ |

## Tier 2 — Phase 1 lower-impact

| # | Item | Effort | Status |
|---|---|---|---|
| 2.1 | Architecture-notes Knowledge entry on TTP-altitude design choice | 2-3h | ✅ done 2026-05-11 (commit `bffceb2`) |
| 2.2 | Decimal IOCTL constant parsing in `source_surface` | 2-3h | ✅ done 2026-05-14 (decimal literal support in `_IOCTL_CMP_RE`/`_IOCTL_DIC_RE`; `switch(IoControlCode){case:}` block scanner `_scan_ioctl_switch_cases`; `CTL_CODE(dev,fn,method,access)` macro decoder `_scan_ctl_code_macros` with 24-entry device-type table; `_parse_ioctl_int` helper handles hex+decimal+signed) |
| 2.3 | K7-style standalone-PoC source parsing | 0.5 day | ✅ done 2026-05-14 (`_scan_py_poc_bindings` + `parse_poc_files` — scans `.py` files for uppercase IOCTL const assignments, `DeviceIoControl(…, literal, …)` calls, and Win32 device path strings in raw/escaped literals; `standalone_poc_ioctl` INFO finding category; 15 smoke-tests pass) |
| 2.4 | `weak_prng_in_security_path` UI/keyboard exclusion filter | 1-2h | ✅ done 2026-05-14 (`_KEY_UI_DENYLIST` in `crypto.py`; suppresses IsItemKeyFocused-class matches; commit `8d4c8b1`) |
| 2.5 | `chains.ue5_prng_cookie_amplification` context discriminator | 1-2h | ✅ done 2026-05-14 (`min_per_primitive={"weak_prng_in_security_path": 3}` + field in `ChainPattern`; commit `8d4c8b1`) |
| 2.6 | explorer.exe `rpc_hosted_toctou_cooccurrence` triage | — | ✅ **TRIAGED 2026-05-13** — FP at exploitation-grade. TOCTOU is in `CLogonTaskFramework::s_WriteOutOOBEDataForOEMApp`; SDDL findings are KR/GR read-only grants (not write-enabling). Root causes closed by 2.7 + 2.8. |
| 2.7 | SDDL detector — read-only World grant false-positive | 1-2h | ✅ done 2026-05-14 (read-only carve-out extended to all overbroad principals; GR/KR grants on WD/BU → neutral; write/create rights still fire; commit `8d4c8b1`) |
| 2.8 | composition.py `rpc_hosted_toctou_cooccurrence` description fix | 1h | ✅ done 2026-05-13 (`_classify_lpe_shape()` discriminator; `lpe_class` field in finding details) |
| 2.9 | `race.py` v2 — SSA path-variable validation; confirm check-then-use on the same MLIL SSA var before emitting `toctou`; eliminates FP class where check and use operate on different vars (different file/handle, coincidentally similar name) | 1-2 days | ✅ done 2026-05-14 (`_ssa_var_str` now includes Variable.identifier alongside name+version; same-named stripped locals at different stack offsets get distinct root keys; existing toctou TP tests preserved) |
| 2.10 | `taint.py` indirect call following — propagate taint through vtable and function-pointer dispatch (currently missed entirely); required for accurate taint chains in C++ services and COM servers | 1-2 days | ✅ done 2026-05-14 (`_resolve_indirect_call_targets` via Binja PossibleValueSet on call dest; `_propagate_into_callee` loops over direct+indirect candidates; silently skips when value analysis can't resolve) |
| 2.11 | `trusted_path.py` v3 — computed/registry/env-var path resolution; current v2 back-walk handles literal `wchar_t*` constants only; registry reads and env-var expansions bypass the check | 1 day | ✅ done 2026-05-14 (`find_trusted_path_computed_load` OUT-param stack-slot tracker; detects RegQueryValueEx/GetEnvironmentVariable/GetTempPath/SHGetFolderPath/PathCombine/etc. filling the same slot as the load-API path arg; new `trusted_path_computed_load` HIGH category; `analyze()` returns v2+v3 combined, v1 suppressed when either fires) |

## Tier 3 — Infrastructure / Phase 5 implementation

| # | Item | Effort | Status |
|---|---|---|---|
| 4.1 | `differ.py` / `patch.py` Phase 5 real implementation — currently dead scaffold (`NotImplementedError` stubs); blocks the Patch-Tuesday diff-then-triage workflow; requires binary diffing integration (BinDiff or Binja's own differ API) and patch-delta taint seeding | 2-3 days | Open |

## Sprint log

**Sprint 1:** Tier 0 — every detector gets gate-2 baseline + manual_workflow. ✅ Done 2026-05-07.

**Sprint 2:** Tier 1.1, 1.2, 1.3 — real detection deltas on common blackbox cases. ✅ Done 2026-05-08.

**Sprint 3:** Tier 1.4 (trusted_path v2) + 1.5 (E2 robustness) + 2.1 (architecture-notes). Also delivered: `dynamic_sink_arg.py` (new format-string/command/path sink detector), Phase-4 `auto_triage` bridge (`phase4_triage` declarative JSON schema), or-of-categories chain slot syntax, C++ stdlib sink registrations in `race.py`/`imports.py`, `uninit.py` stack footprint aggregator, WARN-pass on vulntest runner. vulntest pass-rate 20/6/57 → 33/0/50. ✅ Done 2026-05-11 (commit `bffceb2`).

**Sprint 4:** NightmareEclipse §0–§11 (RPC walker, NDR v2/v3b, cloud_files detector, composition v1+rpc_callable_cloud_stall, Windows-lab harness, BlueHammer/RedSun/UnDefend PoC runs, §10 comparison, §11 post-mortem). Also: FP fixes 2.4/2.5/2.7, composition v2 cross-binary reachability (1.7), gate-6 docs 1.6. 154 tests total. ✅ Done 2026-05-14.

**Sprint 5 (complete):** 2.9/2.10/2.11/2.2/2.3 ✅ done 2026-05-14. known_vulnerable_patterns dedup fix: exact-match (vuln×address) and fuzzy-match (vuln_key across corpus versions) deduplication; _resolve_va/function_name helpers; 39 new tests (205 total). vulntest/validation/ untracked from repo. ✅ Done 2026-05-15. Optional: NE.8b RedSun IMPACT_VERIFIED via Cloud Files. Backlog: 0.4 (Gate-6 doc completion), 4.1 (differ/patch Phase 5). Tier 3 deferred unless engagement requires source-aware analysis.

## Promotion-gate dependencies

- **Gate 2 (No FP):** closed for all Sprint 1–4 detectors. Per-detector results in `dev/corpus_sweep_2026-05-07.json` and `dev/corpus_sweep_2026-05-09.json`. FP fixes 2.4/2.5/2.7 applied 2026-05-14.
- **Gate 3 (PoC validation):** Phase-4 `auto_triage` bridge live; NE chain IMPACT_VERIFIED transitions confirmed (UnDefend). Blocked on per-detector PoC cells for remaining detection gaps (50 FAIL-no-binary or Pass-3 gaps).
- **Gate 6 (Documentation):** closed for all Sprint 1–4 detectors. Remaining gap: `uninit`, `types`, `race`, `windows_drivers`, `source_surface`, `linux_exploit` still missing `manual_workflows/` docs.
