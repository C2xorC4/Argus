# Direct-syscall stub — C / Windows

## Brief

Resolves the syscall service number (SSN) for `NtClose` by reading
NTDLL's user-mode stub bytes (`mov r10, rcx; mov eax, <ssn>;
syscall; ret`), then invokes the syscall directly via a stub
outside NTDLL. Bypasses any user-mode hook EDR/AV may have
installed inline at the NTDLL entry — the syscall instruction
transitions to kernel mode without traversing the hooked code path.

This is the most-prevalent EDR evasion technique in modern
offensive tooling. Hell's Gate (Vrba & Sektor7) is the canonical
implementation; SysWhispers (jthuraisamy) is the prevalent generator;
TartarusGate (trickster0) is a hardened variant that handles
bypass-of-bypass scenarios.

This cell is **not a vulnerability** — it's a malware-detection
target. The toolchain's detection of this pattern is the entire
point of the cell.

**Difficulty:** `1.0.0`.

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py` (with malware-mode), backed by
`scripts/heuristics/syscalls.py`.

Pattern:

- `syscall` instruction in code outside any `.dll` image (i.e., in
  the binary's own text section, not in NTDLL).
- Surrounding instructions match the NTDLL prologue:
  `mov r10, rcx` / `mov eax, imm32` / `syscall` / `ret`.
- The `eax` immediate is computed dynamically (resolve_ssn loads it
  from a captured NTDLL byte, or computes it via Hell's Gate
  signature scanning).
- A nearby `GetProcAddress` / `LdrGetProcedureAddress` / PEB-LDR
  walk resolves NT-prefixed symbol names.

Combined signal is high-confidence.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Search for `syscall` instruction.** Filter to
   `not in module ntdll`. Hits in the binary are the smoking gun.
2. **Inspect the surrounding stub.** Confirm it matches the
   `mov r10, rcx; mov eax, imm32; syscall; ret` shape.
3. **Find the SSN-resolution helper.** Either reads from NTDLL
   stub bytes (Hell's Gate) or scans NTDLL for the prologue
   signature (Hell's Hall variant).

### Reference

- LJM: `[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]` —
  full Hell's Gate / SysWhispers / TartarusGate analysis with
  resolution algorithms and evolution history.
- Book: *Evading the Machine*, syscall-evasion chapter.

## Exploitation

Not a vulnerability. The "exploitation" here is *use of the
technique by malware* to evade EDR.

## Detection-engineering pairing

This cell pairs with a defensive output: when the detector fires,
emit a Sigma / KQL / Splunk-SPL rule the operator can deploy to
detect the *technique* at runtime (e.g., trace direct-syscall
from non-NTDLL pages via Intel PT / ETW Threat Intel provider /
syscall-monitoring driver).

## Remediation

See [`remediation/README.md`](remediation/README.md). Software
developers: don't roll syscall stubs. Defenders: deploy
syscall-monitoring telemetry.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags syscall outside NTDLL + NTDLL-prologue
      signature + GetProcAddress("NtClose")
- [ ] PoC verifies SSN resolves successfully
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
