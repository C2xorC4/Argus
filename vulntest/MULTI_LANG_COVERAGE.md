# Multi-language coverage — current state + gap analysis

Argus's native-instruction pipeline (taint.py, heap.py, etc.) is
calibrated for MSVC-flavoured C/C++ binaries with classical
import-table sinks and SSA over machine instructions. Three of our
Tier-1 cells exercise the same bug classes in Go, Rust, and C# /
.NET — and the native pipeline is mostly silent on them, because:

- **Go**: no MSVC-style import table; calls go through
  `runtime.cgocall` or are inlined by the Go linker; symbols are
  in `runtime.pclntab` (gopclntab), not in PE exports.
- **Rust**: linked statically against the Rust stdlib; user code
  is monomorphised + inlined; release builds strip symbols; the
  only universal markers are panic-string runtime entries.
- **C# / .NET**: no machine-instruction sinks at the language-
  relevant level. The bytecode is CIL inside the CLI metadata
  table, alongside a type-and-member table that names every
  reference precisely. Argus's MLIL doesn't see it.

`dotnet_managed.py` covers v1 of this — a string-co-presence
heuristic detector that fires when distinctive runtime markers
co-occur. It works for deserialisation (BinaryFormatter,
encoding/gob, serde-stack) because those have unmistakeable
runtime-string fingerprints. It does **not** work for shapes whose
runtime fingerprint is identical across categories — most of the
rest of the multi-language matrix.

## Coverage matrix (Tier-1)

| Class                    | C# / .NET | Go        | Rust          |
|--------------------------|-----------|-----------|---------------|
| deserialization          | ✅ v1 string co-presence | ✅ v1 | ✅ v1 |
| stack-overflow           | ❌        | ❌        | ❌            |
| type-confusion           | ❌        | ❌        | ❌            |
| use-after-free           | partial (`ObjectDisposedException` co-presence) | ❌ | ❌ |

✅ = detector emits the expected category from `expected.json`.
❌ = no detector fires; cell is currently FN.

## Why most cells are FN — string probe results

Probed each built fixture for diagnostic markers:

### Rust (~140 KB stripped release builds)
**Identical** string table across stack-OF / type-confusion / UAF:
both have `panicked at`, `rust_panic`, generic stdlib panic
locations (`library\core\src\panicking.rs` etc.). Specifically
NONE of the cells include:
- `transmute` (would identify type-confusion)
- `copy_nonoverlapping` / `write_bytes` (would identify stack-OF)
- `Box::into_raw` / `Box::from_raw` (would identify UAF)
- User source paths (`src/main.rs`) — release build strips these

Implication: **v1 string-co-presence is fundamentally insufficient
for Rust per-cell classification.** The detector can confirm "this
is a Rust binary" but not "this Rust binary has a transmute UB
candidate". Requires v2: DWARF or PDB symbol walk (Rust on Windows
emits a PDB even in release builds when `debuginfo` is on).

### C# / .NET (~5 KB CLI assemblies)
Stripped of nearly everything — they're just CIL bytecode plus the
metadata table. From the raw string scan:
- `stack-OF`: only `System.Runtime` (generic CLR marker)
- `type-confusion`: only `System.Runtime`
- `UAF`: `System.Runtime` + **`ObjectDisposedException`** (the
  C# UAF-analog signal)

Implication: only UAF is catchable from strings. Stack-OF and
type-confusion need v2: a CLI metadata parser that reads the
type-ref and member-ref tables, identifies `localloc`
(IL stackalloc) and `Unsafe.As<T1, T2>` / `Marshal.PtrToStructure`
references precisely.

### Go (~2.3 MB binaries with gopclntab)
String tables include many runtime markers:
- `unsafe.Pointer` — present in both type-confusion AND UAF cells
  (both use `unsafe.Pointer`; can't distinguish from strings alone)
- `reflect.`, `runtime.cgocall`, `stackalloc` — runtime ubiquity,
  not user-code specific
- `_cgo_runtime_cgocall` — present in cgo-using binaries
  (would distinguish the cgo stack-OF cell from pure-Go cells —
  but the cell isn't currently built, missing toolchain)

Implication: v2 — walk gopclntab to enumerate user-code function
names. `main.main` is reachable; functions it calls reveal whether
the binary calls into cgo, uses `unsafe.Pointer`, etc.

## What each language needs for precision

### Rust v2 — PDB / DWARF symbol walk
- Cargo release builds emit a `.pdb` next to the `.exe` on Windows
  when `[profile.release] debug = "line-tables-only"` (or higher)
  is set in `Cargo.toml`. None of our fixtures currently set it.
- Approach: extend `dotnet_managed.py` (rename to
  `runtime_metadata.py`?) or add `analysis/rust_pdb.py` that:
  1. Looks for a sibling `.pdb` file
  2. Walks the PDB module list / public symbols
  3. Matches well-known Rust intrinsics:
     `core::mem::transmute` → `type_confusion`
     `core::ptr::copy_nonoverlapping` → `stack_buffer_overflow`
       (when callsite function returns to an unsafe block;
       v2.1 refinement)
     `alloc::boxed::Box::into_raw` + `from_raw` co-presence →
       `use_after_free`
- Alternative: rebuild fixtures with debug info enabled (modify
  `Cargo.toml` `[profile.release] debug = 2`); v1 string probe
  then becomes useful (function names land in the binary itself).

### Go v2 — gopclntab walk
Format is documented (`runtime/symtab.go`). At
`runtime.pclntab` magic header, structure is well-known. Steps:
1. Locate `pclntab` magic in the binary (`0xfffffff1` for Go
   1.18+; earlier versions differ slightly)
2. Read the function table — yields (PC range, function name)
3. Enumerate functions whose names contain user-package paths
   (everything not under `runtime.`, `internal/`, `sync.`,
   `os.`, etc. — the heuristic identifies user-defined functions)
4. For each user function, walk MLIL via Binja and check whether
   it references known dangerous-API markers:
   - `unsafe.Pointer` operations (visible in MLIL as untyped
     pointer arithmetic between SSA vars of different inferred
     widths)
   - `runtime.cgocall` invocations
   - `unsafe.Slice` / `unsafe.SliceData` (Go 1.21+)

### C# / .NET v2 — CLI metadata walk
- Open the PE, find the .NET directory (cor20 header) via the data
  directory at offset 14
- Read the CLI metadata heap layout
- Walk the `TypeRef` and `MemberRef` tables — each row names a
  type or member by string
- Match members:
  - `Marshal::PtrToStructure` → `type_confusion`
  - `Unsafe::As<,>` → `type_confusion`
  - Method body localloc IL (opcode 0xFE 0x0F) → `stack_buffer_overflow`
    candidate when in `unsafe` context (assembly's `IsAllowed
    SkipVerification` / `UnverifiableCodeAttribute`)
- This is the heaviest of the three, but C#'s metadata is the
  most precise once parsed. There are existing Python libraries
  (`pythonnet`, `dnfile`) that do this.

## Sensible workload (priority order)

1. **Go gopclntab walk** (smallest cost, highest signal). The
   format is documented and the runtime-string base detection
   already confirms Go origin. With gopclntab we get user-package
   function names — enough to fire `type_confusion` on
   `unsafe.Pointer` reinterpret, `use_after_free` on slice-growth
   patterns, etc. Implementable in ~150 LOC of Python.

2. **C# CLI metadata walk** — once Go is done, this is the next
   step for managed-binary precision. `Marshal::PtrToStructure` /
   `Unsafe::As` references in the MemberRef table are direct hits
   for type-confusion. Implementable in ~250 LOC.

3. **Rust PDB walk** — requires either rebuilding fixtures with
   debug info OR a PDB parser. Lowest priority because the
   precision gain depends on first changing the fixture build
   profile. Alternative: rebuild fixtures with
   `debug = "line-tables-only"` so user code surfaces in the
   panic-string table — then v1 string co-presence becomes useful.

4. **String-rule quick wins** before v2 lands:
   - C# UAF: `ObjectDisposedException` co-presence (cell is a
     direct hit; the build's only distinctive string)
   - Rust origin marker only: emit a Tier-3 info-grade `language_origin`
     finding so the rollup separates Rust binaries cleanly

## Known fixture-build gaps

- `stack-overflow/go/build/` is empty — cgo build needs gcc /
  mingw; toolchain missing on this host. Either install mingw
  toolchain in the build env or rewrite the fixture to use pure-Go
  (e.g. exercise slice-out-of-bounds, which Go's runtime catches
  → produces a runtime crash, lower-severity FN).
- Go fixtures (where built) use Go 1.24.3 (see
  `/c/Users/C2xor/sdk/go1.24.3` in PATH).
- C# fixtures target .NET 9; `dotnet` SDK is on PATH.
- Rust fixtures use `stable-x86_64-pc-windows-msvc`. To get
  precision back: edit `Cargo.toml` `[profile.release]` to add
  `debug = "line-tables-only"`.

## Cross-references

- v1 detector: `skills/binary-ninja/scripts/analysis/dotnet_managed.py`
- Build infra: per-cell `Makefile` in each language sub-directory
- Expected: per-cell `expected.json` (declares the category and
  severity the cell SHOULD surface)
- Runner: `vulntest/runner.py` — currently skips multi-lang cells
  by default in the Phase-4 verify integration (`--c-cpp-only`
  flag bypass) because the C-flavoured detectors FP on Go/Rust
  runtime patterns
