# Permissive SDDL on named IPC — C / Windows

## Brief

`CreateNamedPipeW` with a SECURITY_DESCRIPTOR derived from
`D:(A;;GA;;;WD)` — the SDDL string for "Everyone (WD) granted
GENERIC_ALL (GA)". Any local user, including unprivileged or
attacker-controlled, can `CreateFileW` against the pipe and invoke
whatever protocol the server implements.

This is exactly one half of the EAC EOS chain. The privileged
service exposed a permissively-protected IPC; an unprivileged
process spoke the protocol; the protocol exposed privileged
operations.

**Difficulty:** `1.0.0`.

## Build

```bash
make    # x86_64-w64-mingw32-gcc by default
```

Adjust `CC` for native MSVC. Output: `build/vuln.exe`.

## Detection

### Programmatic

Detector: `scripts/analysis/surface.py` (recon stage). Pattern:

- Import: `ConvertStringSecurityDescriptorToSecurityDescriptorW` /
  `SetSecurityDescriptorDacl` / `InitializeSecurityDescriptor`
- String constants matching SDDL with `WD` (Everyone) or `AN`
  (Anonymous) ACEs granting non-trivial access
  (`GA`, `GW`, `KA`, `FA`)
- IPC object creation: `CreateNamedPipeW`, `CreateFileMappingW`,
  `CreateMutexW`, `CreateEventW`, `RegCreateKeyExW` follows

The detector flags the SDDL string itself as a strong signal —
parse the string with the same Win32 API; if the resulting DACL
has Everyone with > GENERIC_READ, finding fires.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Imports → `Convert*SecurityDescriptor*` family.** Hits in
   `wmain`.
2. **Look at the wide-string argument.** `.rdata` reference to
   `D:(A;;GA;;;WD)`. Recognise the SDDL.
3. **Cross-ref to IPC creation.** `CreateNamedPipeW` follows.
4. **Decision point.** SDDL grants Everyone, attached to IPC.

### Reference

- LJM: `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` —
  EAC's named-IPC was permissively-ACL'd; first link in the
  arbitrary-write chain.
- LJM: `[[Memory/Knowledge/gameguard_research_22_findings]]` —
  GameGuard exposed multiple IPC objects with permissive SDs.

## Exploitation

**Primitive class:** unauthenticated access to privileged IPC.

**Mitigation considerations.**

- **AppContainer / sandbox** — sandbox can refuse to grant Everyone
  even if the SDDL says so. Defeats the *spawn* of the connection
  but not the underlying ACL.
- **Restricted-token services** — service runs as a low-privilege
  identity; Everyone-GA on the pipe grants only what the service
  itself has.

## Chain potential

- [`Permissive SDDL → pre-verify-write → missing cleanup → cache poison`](../../../tier2-chains/) —
  the EAC chain.

## Remediation

```c
// before
const wchar_t *sddl = L"D:(A;;GA;;;WD)";   // Everyone GENERIC_ALL

// after — Local System + Administrators only
const wchar_t *sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)";
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Architectural fix

Project-wide: every IPC has an explicit, auditable principal list.
Code-review template lists the SDDL alongside the IPC creation;
permissive ACEs (WD, AN, GU) require justification. Use
`ConvertSecurityDescriptorToStringSecurityDescriptor` in monitoring
code to log effective DACLs at startup.

## Operator-validation checklist

- [ ] Build clean (MinGW or MSVC)
- [ ] Detector flags permissive SDDL string + IPC creation
- [ ] PoC confirms permissive SDDL is in the binary
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
