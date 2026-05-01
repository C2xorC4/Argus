# Tier 1 — Isolated single-vulnerability variants

Cross-product of **vulnerability classes × compiled languages**.
Each cell is a minimal, single-bug program demonstrating the class
in one language, with the language's idiomatic memory/runtime
characteristics.

Layout per cell:

```
<class>/<language>/
├── source/
├── Makefile
├── expected.json
├── poc/
├── README.md          ← challenge brief (see ../_templates/cell_README.md)
└── remediation/
```

See [`../INDEX.md`](../INDEX.md) for the full class × language
matrix and Phase 1 build-out target.

## Phase 0 status

Empty. Phase 0 commits the directory structure + INDEX + template
only. Phase 1 build-out target:

- C / C++ columns: full coverage of every Phase 1 detection category.
- C# / Rust / Go: stack-OF, heap-UAF, type-confusion, deserialisation
  variants (the four classes most likely to surface managed-vs-
  unmanaged distinctions).

Other languages queue for Phase 1+ as priority demands.

## Build conventions

- Default target produces a deterministic binary (no timestamps,
  random seeds, or PIE-randomised offsets baked into the build).
  Use `-frandom-seed=<fixed>` for GCC, equivalent flags for other
  compilers.
- Multi-arch builds where relevant: x86_64 baseline; arm64 for
  cells where ARM-specific patterns surface (`a64_*` Knowledge
  applies).
- Build outputs in `build/`. `make clean` resets.
- The `Makefile` is part of the cell — the toolchain CI builds
  every cell from clean to validate reproducibility.
