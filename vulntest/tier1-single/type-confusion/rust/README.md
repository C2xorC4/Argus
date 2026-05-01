# Type confusion — Rust variant

## Brief

`std::mem::transmute` reinterprets bytes between equal-sized types.
When the target type carries validity invariants the source bytes
don't satisfy (e.g., a non-null pointer requirement, a valid bool,
a trait-object vtable pointer), the transmute is UB.

In safe code, this is impossible. In unsafe blocks, transmute is
the most common type-confusion primitive.

Detector: `scripts/analysis/taint.py`. Pattern: call to
`core::mem::transmute` between types whose size is equal but layout
differs (different field types). Recoverable when both types appear
in the binary's debug info or via heuristic field-pattern recognition.

## Reference

- LJM: `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]`
- The Rustonomicon — transmute soundness.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags transmute between non-equivalent layouts
- [ ] Substrate-coherence check via `jm associate`
