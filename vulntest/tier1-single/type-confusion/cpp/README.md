# Type confusion — C++ variant

## Brief

`get_radius()` `static_cast`s a `Shape*` to `Circle*` without
checking the runtime type. When the underlying object is a
`Rectangle`, the cast is undefined behaviour — the field offsets
disagree (`Rectangle::w_` lies where `Circle::radius_` would, and
`h_` extends beyond `Circle`'s allocation).

The interesting consequence is the vtable. Even though
`Rectangle` has its own `area()` override, the static_cast does not
change the vtable pointer (vtable lives in the object header). The
`area()` call dispatches through the *actual* vtable, so this
particular case is benign for `area`. But field reads through the
casted pointer are not — and in real exploits, the chain proceeds
to a method that reads casted-type-specific fields, producing
arbitrary-pointer reads / writes.

This is the canonical primitive in browser-RCE chains: V8 / JSC
type-confusion bugs are static-cast equivalents at the engine level.

**Difficulty:** `1.0.0`.

## Build

```bash
make
```

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py` with the
`static_cast_polymorphic_downcast` heuristic. Signal: `static_cast`
from a base type with virtual functions to a derived type, no
preceding `dynamic_cast` or `typeid` check on the same pointer.

This is recoverable from binary IL: the cast itself is a no-op at
the assembly level (just a pointer reinterpretation), but the
*absence* of the dynamic_cast runtime helper call is the signal.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Find polymorphic base classes.** RTTI symbols
   (`_ZTV<class>`, `_ZTI<class>` for Itanium ABI) flag classes with
   virtual functions.
2. **Identify downcast call sites.** A static_cast from a polymorphic
   base appears as a plain pointer assignment in HLIL — no runtime
   helper call. Compare against `__dynamic_cast` (Itanium) /
   `__RTDynamicCast` (MSVC) call sites which represent dynamic_cast.
3. **Decision point.** Static downcast without RTTI check =
   type-confusion candidate.

### Reference

- LJM: `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` — UB
  classes; static_cast violation lands in "type-rules UB".
- LJM: `[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]` — Go's
  `unsafe.Pointer` bypasses the same type system; same class in
  managed-runtime form.

## Exploitation

**Primitive class:** type-confusion → arbitrary-field-read / write.

**Mitigation considerations.**

- **CFI (Control Flow Integrity, e.g., Clang `-fsanitize=cfi`)** —
  flags vtable pointers from non-permitted types at virtual-call
  sites. Defeats the typical follow-on (vtable-hijack via type
  confusion).
- **MSVC `/sdl`** — runtime type-check insertion in some scenarios.
- **PartitionAlloc / scudo** — type-segregated heaps reduce
  exploitability of type-confusion-derived primitives.

## Chain potential

- [`type-confusion → arbitrary-read → deref-anywhere`](../../../tier2-chains/) —
  the canonical RCE composition. Type confusion produces an
  arbitrary-pointer-read primitive; deref-anywhere closes to RCE.

## Remediation

```cpp
// before — UB on type mismatch
Circle* c = static_cast<Circle*>(s);
return c->area();

// after — virtual dispatch, no cast needed
return s->area();

// alternatively — guarded dynamic_cast
Circle* c = dynamic_cast<Circle*>(s);
return c ? c->area() : 0.0;
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

### Compiler / linker mitigations

- `-fsanitize=cfi` (Clang) — runtime vtable validation at virtual
  call.
- `-Wcast-qual` `-Wcast-align` — adjacent-issue warnings; not direct.

### Architectural fix

Prefer virtual dispatch (no cast). When a downcast is genuinely
needed, use `dynamic_cast` and treat `nullptr` as the failure
branch. Project-wide: ban `static_cast` from polymorphic bases.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags static_cast downcast in `get_radius`
- [ ] PoC executes the wrong-type path
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
