# Format-string — C variant

## Brief

`printf(user)` — the user-controlled string is passed as the format
argument. Format-specifier handling steps the variadic argument
pointer through the stack, leaking values; `%n` writes the count of
bytes printed so far to a pointer argument, providing arbitrary
write.

Modern compilers warn under `-Wformat-security` and refuse under
`-Werror`. The class survives in code paths where the warning is
suppressed (vendor printf-likes, `__attribute__((format))` not
applied, `sprintf` into local buffer that's then passed to a real
printf).

**Difficulty:** `1.0.0`.

## Build

```bash
make
```

`-Wno-format-security` is set explicitly to allow the bug to compile.
In production this warning is a build failure under `-Werror`.

## Detection

### Programmatic

Detector: `scripts/analysis/taint.py`. Pattern: any printf-family
call (`printf`, `fprintf`, `sprintf`, `snprintf`, `vprintf`, `syslog`,
`err`, `warn`) where the format argument is non-constant **and**
tainted by argv / fread / recv / environ.

Full manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

1. **Imports → `printf`.** Cross-ref to `log_message`.
2. **Inspect `log_message`.** First arg to `printf` is the function
   parameter `user`; not a literal.
3. **Trace `user`.** Walks back to `argv[1]`.
4. **Decision point.** Format string is non-literal and tainted.

### Reference

- LJM: `[[Memory/Knowledge/em_advanced_injection_variants]]` —
  format-string as info-leak primitive feeding canary / PIE base
  recovery.

## Exploitation

**Primitive class:** format-string → arbitrary read (%x, %s, %p) +
arbitrary write (%n).

**Mitigation considerations.**

- **FORTIFY_SOURCE level 2** — `__printf_chk` etc. validates that
  format string is not in writable memory and that `%n` is in
  read-only memory. Defeats canonical exploit.
- **`-Wformat-security` + `-Werror`** — compile-time refusal.
- **glibc `_FORTIFY_SOURCE=3`** (recent) — additional checks on
  argument count.

## Chain potential

- [`format-string-leak → stack-OF → ROP`](../../../tier2-chains/) —
  classical chain: leak canary + PIE base, then trigger separate
  stack-OF with calculated payload.

## Remediation

```c
// before
printf(user);

// after
printf("%s", user);              // literal format; user as data
```

Stored in [`remediation/vuln.c`](remediation/vuln.c).

### Compiler / linker mitigations

- `-Wformat=2` `-Wformat-security` `-Werror` — compile-time refusal.
- `-D_FORTIFY_SOURCE=2`.
- `__attribute__((format(printf, n, m)))` on printf-like helpers so
  the compiler validates them too.

### Architectural fix

Project-wide format-string discipline. Lint via clang-tidy
`cert-err34-c` / `bugprone-printf-non-literal`. Code-review rule:
no printf-family call with a non-literal format.

## Operator-validation checklist

- [ ] Build clean (with `-Wno-format-security` — production build
      would refuse)
- [ ] Detector flags non-literal format string in `log_message`
- [ ] PoC leaks stack values
- [ ] Manual Binja UI walkthrough matches
- [ ] Substrate-coherence check via `jm associate`
