# Uninitialised memory disclosure — C variant

## Brief

`emit_status()` allocates `struct status` on the stack, fills three
fields, then `fwrite`s the entire struct. The `message` field is
never initialised; on output, those 16 bytes carry whatever stack
contents existed before the call — typically previous frame's
locals, including pointers, return addresses, canary fragments.

This is the canonical kernel info-leak class. Combined with a
separate stack-OF, the leak feeds canary / PIE-base recovery,
unlocking the second-stage exploit.

**Difficulty:** `1.0.0`.

## Build

```bash
make
make msan         # MSan-instrumented (requires clang)
```

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py` with stack-struct-partial-init
heuristic. Pattern: stack-allocated struct, only some fields
written, full-size write to output sink (`fwrite`, `write`, `send`,
`sendto`, `WriteFile`, `IoCallDriver`).

Recovering this from IL requires:

- Detecting the struct shape (Binja's type inference).
- Tracking writes to each field within the function.
- Tracking the size argument of the output call vs. the struct size.

When all fields are written before output, the heuristic does not
fire. When fields or padding go unwritten, it does.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Find output sinks.** `fwrite` / `write` / `send` family.
2. **Identify struct argument.** Trace pointer to declaration site.
3. **Inspect declaration.** No `memset`, no `{0}` initialiser.
4. **Inspect fills.** Some fields written, others not.

### Reference

- LJM: `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` —
  reading uninitialised storage is UB.

## Exploitation

**Primitive class:** info-leak → ASLR/canary defeat.

**Mitigation considerations.**

- **`-Wuninitialized` / `-Wmaybe-uninitialized`** — compile-time
  detection; pragma `#pragma pack` confounds some checks.
- **MSan / `-fsanitize=memory`** — runtime detection (clang only).
- **`-ftrivial-auto-var-init=zero`** (gcc/clang) — auto-zero stack
  variables. Strong mitigation; cost is small.

## Chain potential

- [`info-leak → UAF → ROP`](../../../tier2-chains/) — the leak
  primitive feeds a follow-on memory-corruption chain.
- [`format-string-leak → stack-OF → ROP`](../../../tier2-chains/) —
  alternative leak shape.

## Remediation

```c
// before
struct status s;
s.state = state;
fwrite(&s, ...);

// after
struct status s = {0};               // zero, then partial-fill
s.state = state;
fwrite(&s, ...);
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Compiler / linker mitigations

- `-ftrivial-auto-var-init=zero` — auto-zero locals; broadest
  protection.
- `-D_FORTIFY_SOURCE=2` — does not address this class directly.

### Architectural fix

Project-wide: every aggregate output struct is zero-initialised at
declaration. Linter rule: no `struct X s;` followed by partial-fill
followed by output without a memset.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags partial-init followed by full-size output
- [ ] Hex-dump of output shows non-zero bytes in unfilled fields
- [ ] MSan run (`make msan`) reports use-of-uninitialized-value
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
