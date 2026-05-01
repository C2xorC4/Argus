# Format-string — C++ variant

## Brief

C++ inherits printf from C; calling it with an attacker-controlled
format string reproduces the C-variant primitive verbatim. Idiomatic
C++ (iostreams, `std::format`) does not have this class — this cell
exists to validate detection on mixed-C/C++ code where the printf
call appears in a C++ source file with C++-mangled callers.

**Difficulty:** `1.0.0`.

## Build / Detection / Exploitation / Remediation

Identical to the C variant. See [`../c/README.md`](../c/README.md).

The detection difference is symbol-mangling: the call site appears
in `log_message(std::string const&)` rather than plain `log_message`.

## Architectural fix — C++-specific

Replace printf with `std::cout`, `std::format` (C++20), `fmt::format`
(libfmt). All three are type-safe by construction and do not have a
format-string-injection class.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags non-literal format string
- [ ] PoC leaks stack values
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
