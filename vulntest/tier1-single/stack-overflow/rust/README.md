# Stack buffer overflow — Rust variant

## Brief

Rust safe code cannot stack-overflow — array access is
bounds-checked at compile time (when statically determinable) or
runtime (when dynamic). The vulnerability surface is `unsafe` blocks
where the developer asserts safety the borrow checker / type system
can't verify.

This cell uses `unsafe { ptr::copy_nonoverlapping(src, dst, len) }`
where `len` is `name.len()` — sourced from argv — and `dst` points
to a `[u8; 64]` stack array. The `unsafe` block bypasses the
length check.

The detector's job in Rust binaries: identify `unsafe` blocks (which
are NOT marked at the binary level — Rust compiles unsafe and safe
to identical machine code) by detecting *unguarded raw pointer
writes* — i.e., writes that don't go through Rust's bounds-checked
indexing primitives.

**Difficulty:** `1.0.0`.

## Build / Detection

```bash
make    # cargo build --target-dir ../build_target
```

Detector: `scripts/analysis/taint.py` with Rust-specific extension.
Pattern:

- Stack array allocation (e.g., `[u8; N]` lowers to a fixed stack
  region).
- Call to a non-Rust pointer-API: `core::ptr::copy_nonoverlapping`,
  `core::ptr::write`, `core::slice::from_raw_parts_mut`.
- Length argument tainted by argv / IO / network.

Detection difficulty: Rust safe-code overflow does NOT emit these
calls; the patterns are unique to unsafe regions.

## Reference

- LJM: `[[Memory/Knowledge/hw_stack_overflow_mechanics]]`
- The Rustonomicon — unsafe Rust contract.

## Remediation

```rust
// before
unsafe { ptr::copy_nonoverlapping(name.as_ptr(), buf.as_mut_ptr(), name.len()); }

// after — slice operation, bounds-checked
let n = name.len().min(buf.len());
buf[..n].copy_from_slice(&name[..n]);
```

## Operator-validation checklist

- [ ] Build clean (`cargo build`)
- [ ] Detector flags ptr::copy_nonoverlapping with tainted length
- [ ] Substrate-coherence check via `jm associate`
