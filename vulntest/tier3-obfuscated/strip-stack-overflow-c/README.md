# Tier 3 — symbol-stripped variant of stack-overflow / C

## Source cell

[`tier1-single/stack-overflow/c/`](../../tier1-single/stack-overflow/c/)

This Tier-3 variant takes the same source program and re-emits it
with all debug info, symbol tables, and exported names stripped.
Detection logic that depends on import-table fingerprinting still
works (imports are not removed by `strip`); detection logic that
depends on function names or DWARF entries fails.

The detector's job: produce the same Finding category and severity
*without* the function name `greet` being recoverable. The IL
shape, the alloc size, the strcpy reference must be enough.

**Difficulty:** `3.1.0` (Tier 3, single obfuscation, no chain).

## Layout

This Tier-3 cell does NOT carry its own source. It carries:

- `transform.sh` — script that takes the Tier-1 `build/vuln`
  binary and produces the stripped variant
- `Makefile` — invokes the source cell's `make`, then transforms
- `expected.json` — same structural finding, plus annotation that
  the binary lacks function-name symbols
- `README.md` — this file

## Transform

```bash
# transform.sh
set -euo pipefail
SOURCE="../../tier1-single/stack-overflow/c"
make -C "$SOURCE"
mkdir -p build
cp "$SOURCE/build/vuln" build/vuln
strip --strip-all build/vuln                     # remove all symbol tables
objcopy --strip-debug build/vuln                 # belt-and-suspenders
```

## Expected detection behaviour

Detector: `scripts/analysis/taint.py` + `scripts/analysis/obfuscation.py`.

- `obfuscation.py` annotates: `symbols_stripped: true`,
  `dwarf_present: false`, `pdb_present: false`.
- `taint.py` still finds the bug: import-table has `strcpy`,
  cross-ref to a function (anonymous), HLIL recovers the
  64-byte stack alloc + unbounded copy. Function reported as
  `sub_<addr>` rather than `greet`.

## Operator-validation checklist

- [ ] Source cell builds clean (`make -C ../../tier1-single/stack-overflow/c`)
- [ ] Transform produces symbol-stripped binary
- [ ] Detector still emits stack_buffer_overflow finding
- [ ] Finding cites a reasonable function-anonymous name
      (e.g., `sub_401200`)
- [ ] Substrate-coherence check via `jm associate`
