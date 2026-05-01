# Stack buffer overflow — C++ variant

## Brief

C++ presents the same primitive as the C variant but in code that
*looks* idiomatic. `std::cin >> buf` where `buf` is `char[N]` invokes
`std::basic_istream::operator>>(char*)`, which has the same unbounded
behaviour as `gets`. Modern guidance (C++ Core Guidelines,
SL.io.50) treats this as an obsolete form, but it remains in the
language and in real codebases.

The detector must surface this even though no `strcpy` import
appears — the unbounded sink is a method on the std streams library,
not a libc symbol.

**Difficulty:** `1.0.0`.

## Build

```bash
make            # produces build/vuln (or build/vuln.exe on Windows)
```

Build flags mirror the C variant (`-fno-stack-protector -fno-pie -no-pie`).

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py` with C++ stream-source augmentation.
The `heuristics/imports.py` table must include the mangled symbol
`_ZNSirsEPc` (gcc Itanium ABI for
`std::basic_istream<char>::operator>>(char*)`) and the MSVC
equivalent.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Open binary.** Wait for analysis.
2. **Symbols → Imports / Functions.** Filter for `operator>>`. The
   demangled name reads
   `std::basic_istream<char,...>::operator>>(char*)`; raw symbol on
   gcc is `_ZNSirsEPc`.
3. **Cross-references on the stream-shift symbol.** Hits inside
   `Greeter::promptAndGreet`.
4. **Trace the destination argument.** Walks back to `name` local
   variable with stack slot 64 bytes.
5. **Decision point.** `operator>>(char*)` is unbounded; buffer is
   fixed-size. Class confirmed.

### Reference

- LJM: `[[Memory/Knowledge/hw_stack_overflow_mechanics]]`
- Book: *Heavy Wizardry*, ch. 4 (mechanics) + C++ Core Guidelines
  SL.io.50 (the obsolete-form rule).

## Exploitation

**Primitive class:** stack-OF → return-address overwrite.

**Mitigation considerations.** Same as the C variant. Note: MSVC
default `/sdl` enables `/GS` and additional checks; an MSVC build
without `/GS` requires `/GS-`.

**Idiomatic exploit walkthrough.**

```bash
make
echo "AAAA...BBBBBBBB" | python3 poc/trigger.py build/vuln
```

PoC artefact: [`poc/trigger.py`](poc/trigger.py).

C++-specific notes:

- **Mangled symbols.** Itanium ABI (gcc/clang) and MSVC ABI mangle
  differently. The detector must demangle or match both.
- **Throw / catch path.** If the surrounding code wraps the read in
  `try { ... } catch(...)`, an exception unwind can become an
  alternate sink (vtable hijack via corrupted exception object —
  Tier 2 territory).
- **Object-on-stack overflow.** When the buffer is a member of a
  stack-allocated object, the vtable pointer of the surrounding
  object is also overwriteable. See Tier 2 heap-OF→vtable-hijack
  for the heap-equivalent.

## Chain potential

- [`heap-OF → vtable-hijack → ROP`](../../../tier2-chains/) — the
  C++ analogue when the buffer is a class member rather than a stack
  local.
- [`format-string-leak → stack-OF → ROP`](../../../tier2-chains/).

## Remediation

```cpp
// before
char name[64];
std::cin >> name;                    // unbounded

// after
std::string name;                    // grows; bounded by allocator
std::cin >> name;
```

Alternative bounded form:

```cpp
char name[64];
std::cin >> std::setw(sizeof(name)) >> name;   // setw bounds the read
```

Stored in [`remediation/vuln.cpp`](remediation/vuln.cpp).

### Compiler / linker mitigations

Same as C variant. Additionally:
- MSVC `/sdl` — strict diagnostic level; flags `operator>>(char*)`
  pattern at compile time when bounds are statically knowable.

### Architectural fix

Project-wide rule against `char[]` interaction with std streams.
`std::string`, `std::array`, or `std::span` instead. Lint via
clang-tidy `cppcoreguidelines-pro-bounds-array-to-pointer-decay`.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector finds the bug at `Greeter::promptAndGreet`
- [ ] Programmatic Finding matches `expected.json`
- [ ] PoC triggers
- [ ] ASan run confirms stack-buffer-overflow
- [ ] Manual reproduction in Binja UI matches programmatic finding
- [ ] Substrate-coherence check via `jm associate`
