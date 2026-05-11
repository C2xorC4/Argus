# `analysis/trusted_path.py` — Manual-Workflow Companion

## Purpose

Detects when a binary references attacker-writable path strings
(`\Temp\`, `\AppData\`, `\ProgramData\`, `/tmp/`, `/var/tmp/`,
`/dev/shm/`) AND imports load-class APIs (`LoadLibraryEx`,
`CreateFile`-for-read, `ReadFile`, `MapViewOfFile`, `fopen`,
`dlopen`). Together they suggest the binary loads content from a
low-trust location and treats it as authoritative — the canonical
EAC chain's terminal primitive (cache-load of attacker-poisoned
data).

Emits two categories:
- `trusted_path_cache_load` (MEDIUM, v1) — binary-scope co-presence
- `trusted_path_xref_to_load` (HIGH, v2) — per-callsite proven flow
  from an attacker-writable path literal to a specific load API
  call site

When v2 fires for a binary, v1 is suppressed (v2 is strictly more
informative — knowing *which* literal flows to *which* load
callsite supersedes "some such literal exists somewhere").

## Detector character

- **v1 binary-scope heuristic:** the path-string and load-import
  are co-present anywhere in the binary; the detector doesn't
  xref the string to a specific load call site. High-recall
  per-binary, low-precision per-call-site. Useful fallback for
  cases where v2's SSA back-walk doesn't resolve (computed paths,
  obfuscated string assembly).
- **v2 per-callsite SSA xref:** for every load-class call site
  (`LoadLibraryW`, `fopen`, `CreateFileW`, etc.), walks the SSA
  definition chain back from the path argument up to four hops
  to a constant pointer. If that pointer resolves to a string
  in the binary's string table containing an attacker-writable
  token, emits HIGH. Currently handles direct ConstPtr,
  Load-of-ConstPtr, single/multi-hop SSA copies, and
  Phi-node-bounded chains. Does NOT currently handle:
  - Buffer-built paths (`swprintf(buf, ...); LoadLibraryW(buf)`) —
    Tier 1.2 stack-slot taint can extend this in a follow-on
  - Registry-derived paths (`RegQueryValueW` → `LoadLibraryW`)
  - Environment-variable-resolved paths (`GetEnvironmentVariableW`
    → expansion → load)

## Programmatic invocation

```bash
python -m scripts.analysis.trusted_path --binary <path>
```

## Manual workflow (Binary Ninja UI)

1. Open binary; settle analysis.
2. **Strings panel:** filter for `\Temp\`, `\AppData\`,
   `\ProgramData\`, `\Windows\Temp\`, `/tmp/`, `/var/tmp/`. Inspect
   each.
3. For each matched string, **xref the address** (Right click →
   Find references). Walk to each load-class call site and verify:
   - The path string is the file-name argument to the load call.
   - The path is constructed dynamically from a string in
     attacker-writable space (vs hardcoded to a system-protected
     path that happens to share a substring).
4. **Imports panel:** confirm the binary imports at least one load
   API. If the path strings exist but no load API is imported, the
   strings are likely error-message text and the v1 detector
   over-reports.
5. **Stop conditions:**
   - Path string xref'd to a `LoadLibraryEx` / `CreateFile`-for-read
     call site → real `trusted_path_cache_load` candidate.
   - Path string only used in a write call (`CreateFile` for
     write) → not the load-side of the chain; consider whether
     `pre_verification_write` is the right finding instead.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — the
  cache-load is the chain's exploitation step, where the
  attacker-poisoned write becomes a privileged read.

## Divergence policy

- **Manual authoritative for:** v1 per-binary findings until v2
  ships. The string-imports co-presence is suggestive but not
  proof; reviewer chases xrefs.
- **Programmatic authoritative for:** the lexical match. If the
  detector says a `\Temp\` string is present and `LoadLibraryEx`
  is imported, those facts are reliable. The interpretation
  ("therefore the binary loads from temp") is what review
  confirms or refutes.

## Operator-validation checklist

- [ ] `vulntest/tier2-chains/eac-permissive-prewrite-cleanup-cache/c/`
      — fires once (matches `\Windows\Temp\eac_target.bin`).
- [ ] Clean-corpus sweep — 0 findings across 15 Windows binaries
      (gate-2 CLEAN, 2026-05-07).
- [ ] On a real-world binary that's known to load from AppData
      (e.g., a software updater): manual workflow surfaces the
      callsite, programmatic v1 emits but doesn't pinpoint —
      compare and document.
