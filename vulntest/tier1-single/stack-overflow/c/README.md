# Stack buffer overflow — C variant

## Brief

Classical x86_64 stack-based buffer overflow. `greet()` allocates a
64-byte buffer on the stack and copies `argv[1]` into it via
`strcpy()` with no length check. Sufficiently long input overwrites
the saved frame pointer and saved return address, hijacking control
flow on function return.

This is the foundational form taught in *Heavy Wizardry* ch. 4 and
the canonical x86 exploitation primer. Every more sophisticated
variant in the corpus (ROP chain, format-string-leak chain,
heap-OF→vtable chain) builds on this recognition.

**Difficulty:** `1.0.0` (Tier 1, no obfuscation, no chain).

## Build

```bash
make            # produces build/vuln (or build/vuln.exe on Windows)
```

Build flags: `-O0 -g -fno-stack-protector -fno-pie -no-pie`. Stack
canary and PIE are disabled so the bug is reachable without a leak.
NX / DEP at the OS level remain on; the PoC demonstrates *trigger*,
not full RCE — full exploitation comes in Phase 3.

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py` — sources from `argv`, sinks at
import-table calls listed in `scripts/heuristics/imports.py`.

Expected Finding (excerpt):

```json
{
  "category": "stack_buffer_overflow",
  "severity": "high",
  "function": "greet",
  "knowledge_refs": ["[[Memory/Knowledge/hw_stack_overflow_mechanics]]"],
  "cwe": ["CWE-121"],
  "evidence_signatures": [
    {"kind": "import", "name": "strcpy"},
    {"kind": "stack_alloc_size", "function": "greet", "size": 64},
    {"kind": "taint_flow", "source": "argv", "sink": "strcpy:src"}
  ]
}
```

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Open binary in Binja UI.** Wait for analysis to settle.
2. **Symbols → Imports.** Confirm `strcpy` (or `__builtin___strcpy_chk`
   if FORTIFY is enabled — the FORTIFY-stub presence already says
   the developer was warned).
3. **Cross-references on `strcpy`.** Single hit: inside `greet`.
4. **Open `greet` in HLIL.** Note the local variable `buf` with stack
   slot of 64 bytes.
5. **Trace the source argument of `strcpy`.** Walks back to `name`
   parameter → `greet` caller → `argv[1]` in `main`. The full source-
   to-sink chain is: `main:argv → greet:name → strcpy:src`, with
   sink-side length unbounded.
6. **Decision point.** Buffer is 64 bytes; sink is unbounded. Class
   confirmed.

### Reference

- LJM: `[[Memory/Knowledge/hw_stack_overflow_mechanics]]` — the canonical
  taxonomy; saved-RBP / saved-RIP layout, frame-pointer-omission
  variants, canary interaction.
- Book: *Heavy Wizardry*, ch. 4 — the layout diagram and the first
  hand-built exploit.

## Exploitation

**Primitive class:** stack-OF → return-address overwrite.

**Mitigation considerations.**

- `/GS` / `-fstack-protector-strong` — **defeats** the trivial
  trigger; canary check fails before return. Bypass: leak canary via
  format-string or info-leak chain (see Tier 2 `format-string-leak →
  stack-OF → ROP`).
- CFG / `/guard:cf` — irrelevant for return-address overwrite (CFG
  guards indirect calls, not returns). CET shadow stack would.
- ASLR — irrelevant for the trigger; matters for the full ROP chain
  (Phase 3).
- CET shadow stack — **defeats** return-address overwrite outright.
  Drives offense to vtable / typed-call hijack instead.
- NX / DEP — defeats classical shellcode-on-stack; Phase 3 ROP chain
  bypasses by reusing executable code.

**Idiomatic exploit walkthrough.**

```bash
make
python3 poc/trigger.py build/vuln    # exits 0 on crash, 1 on no-crash
```

PoC artefact: [`poc/trigger.py`](poc/trigger.py).

For the C-specific shape:

- **Saved RBP + saved RIP layout.** x86_64 SysV ABI: `[buf:64][saved
  RBP:8][saved RIP:8]`. Padding of 72 bytes lands the next 8 bytes
  in the return address.
- **Frame-pointer omission.** Compiled with `-fomit-frame-pointer`
  the saved RBP disappears and padding is 64 bytes flat. Detector
  must handle both shapes.
- **Win64 ABI.** Different prolog (RBP push optional, shadow space).
  Cross-platform detection treats prolog-shape and saved-return
  position as architecture-specific.

## Chain potential

- [`format-string-leak → stack-OF → ROP`](../../../tier2-chains/) —
  use a separate format-string vulnerability to leak the canary and
  PIE base, then trigger this stack-OF with a calculated ROP payload.
- [`info-leak → UAF → ROP`](../../../tier2-chains/) — substitute the
  UAF for the stack-OF when canary defeats the simpler primitive.

## Remediation

### Idiomatic fix

```c
// before
char buf[64];
strcpy(buf, name);                       // unbounded

// after
char buf[64];
snprintf(buf, sizeof(buf), "%s", name);  // bounded, NUL-terminated
```

`snprintf` is preferred over `strncpy` because `strncpy` does not
guarantee NUL termination when source ≥ destination size — that
introduces a separate read-overrun bug.

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Compiler / linker mitigations

- `-fstack-protector-strong` (GCC/Clang) / `/GS` (MSVC) — adds canary
  check on function epilogue. Bug still present; trigger detected
  at runtime.
- `-D_FORTIFY_SOURCE=2` — `strcpy` becomes `__strcpy_chk` when
  destination size is statically knowable. Compile-time and runtime
  size validation.
- `-fPIE -pie` / `/DYNAMICBASE` — randomises image base; ROP chain
  needs leak primitive.
- `/CETCOMPAT` (MSVC, Windows 10+ on CET-capable CPUs) — shadow
  stack. Return-address overwrite triggers `#CP`.

### Architectural fix

Treat untrusted input as length-bounded before use. Project-wide
guideline: ban `strcpy`, `strcat`, `sprintf`, `gets` from the import
allowlist. Replace with bounded variants (`snprintf`, `strncpy_s`,
`StringCchCopy` on Windows). Audit existing code via
`scripts/heuristics/imports.py` baseline scan.

## Operator-validation checklist

- [ ] Build clean (`make` succeeds)
- [ ] Detector finds the bug at `greet` (not at `main`)
- [ ] Programmatic Finding matches `expected.json`
- [ ] PoC triggers (`python3 poc/trigger.py build/vuln` returns 0)
- [ ] ASan / UBSan run confirms stack-buffer-overflow class
- [ ] Manual reproduction in Binja UI matches programmatic finding
- [ ] Substrate-coherence check: `jm associate "stack buffer overflow strcpy unbounded"`
      surfaces `hw_stack_overflow_mechanics` as top match
