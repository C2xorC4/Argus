# `analysis/sddl.py` — Manual-Workflow Companion

## Purpose

Detects permissive Discretionary Access Control List declarations
that grant over-broad rights to over-broad principals on Windows
IPC objects (named pipes, file mappings, mutexes, events) and on
the security descriptors of trusted objects. Two emissions:

- `permissive_sddl` — an SDDL string constant in the binary contains
  an Allow-ACE granting GENERIC_ALL or other broad-write rights to
  Anonymous Logon, Guests, Users, or Everyone.
- `null_dacl` — `SetSecurityDescriptorDacl(sd, TRUE, NULL, FALSE)`
  call site detected via MLIL constant inspection. NULL DACL
  semantics are "no access control"; any local user has full access.

Canonical real-world examples: EAC EOS named-IPC SDDL pattern
(`(A;OICI;GA;;;AN)` Anonymous Logon GENERIC_ALL); GameGuard
`SmxNPGG` NULL DACL on named pipe.

## Programmatic invocation

```bash
# from skills/binary-ninja/
python -m scripts.analysis.sddl --binary <path-to-target.exe>
```

Or via `dev/validate.py` (full pipeline) / `vulntest/runner.py`
(cell-validation harness).

## Manual workflow (Binary Ninja UI)

1. Open binary in Binja UI; wait for analysis to settle.
2. **Strings panel:** filter for `D:`, `O:`, `S:` (SDDL section
   markers). Inspect each match for `(A;...;GA;;;WD)`-style ACEs
   granting GENERIC_ALL to over-broad principals (`WD` Everyone,
   `AN` Anonymous, `BG` Guests, `BU` Users).
3. **Imports panel:** check for `ConvertStringSecurityDescriptor-
   ToSecurityDescriptorW`, `CreateNamedPipeW`, `CreateFileMappingW`,
   `SetSecurityDescriptorDacl`. Cross-reference each call site to
   confirm the SDDL flows to a security-sensitive sink.
4. For NULL DACL: navigate to each `SetSecurityDescriptorDacl` call
   site; in HLIL, verify arg2 is constant `1` (TRUE — DaclPresent)
   and arg3 is constant `0` (NULL Dacl pointer).
5. **Stop conditions:**
   - SDDL string with broad-write ACE + IPC-creation import → fire
     `permissive_sddl`.
   - `SetSecurityDescriptorDacl(sd, TRUE, NULL, ...)` → fire
     `null_dacl`.
   - SDDL with read-only rights to AU (Authenticated Users) →
     no finding (acceptable for read-only resources).

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — EAC EOS
  named-IPC SDDL is Component 1 of the chain.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — GameGuard
  `SmxNPGG` NULL DACL.
- `[[Memory/Knowledge/windows_sddl_grammar]]` — full ACE grammar +
  SID abbreviation table + NULL-DACL vs empty-DACL semantics.

### Reference book chapters

- *Windows Internals*, ch. on Security Reference Monitor / DACL
  evaluation — context for why broad-allow ACEs are exploitable.

## Divergence policy

- **Programmatic authoritative for:** SDDL string parsing,
  `SetSecurityDescriptorDacl` direct-NULL detection. Mechanical
  pattern matching outperforms human triage for these.
- **Manual authoritative for:** indirect NULL DACL paths — when
  the security descriptor is constructed dynamically and the NULL
  comes from a `nullptr` / variable rather than a literal `0`. The
  programmatic detector keys on constant-zero MLIL operand and
  misses dynamic-NULL cases. A reviewer can chase the variable's
  data flow.
- **Both must agree for:** novel SDDL forms (custom SID strings
  outside the `_OVERBROAD_PRINCIPALS` deny-list, or new SDDL syntax
  introduced in future Windows revisions). Update the deny-list
  when a new principal class warrants flagging.

## Operator-validation checklist

- [ ] `vulntest/tier1-single/permissive-sddl/c/` — programmatic
      detector emits `permissive_sddl` on the vuln binary, silent
      on remediation.
- [ ] `vulntest/tier1-single/null-dacl/c/` — programmatic detector
      emits `null_dacl` on vuln, silent on remediation.
- [ ] `vulntest/tier2-chains/eac-permissive-prewrite-cleanup-cache/c/`
      — both findings present alongside the chain emission.
- [ ] Substrate-coherence check via `jm associate "permissive_sddl"`
      surfaces the cited Knowledge entries (EAC + GameGuard).
- [ ] Sweep against clean Windows corpus produces zero
      `permissive_sddl` / `null_dacl` findings (gate-2 verified
      2026-05-07: 0 FPs across 15 binaries).
