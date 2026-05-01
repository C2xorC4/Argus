# Type confusion — Go / unsafe.Pointer variant

## Brief

`*(*B)(unsafe.Pointer(&a))` reinterprets `a`'s bytes as type `B`.
Go's type system provides no validation — `unsafe.Pointer` is the
intentional escape valve. Field offsets of A and B disagree; the
reinterpretation reads memory under wrong-type assumptions.

Detector: `scripts/analysis/taint.py`. Pattern:
`*(*T)(unsafe.Pointer(&x))` cast between unrelated types. The
binary-level signature is the cgo-style call shape but with
`runtime.Pointer` rather than cgo entry.

## Reference

- LJM: `[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]` — Go
  unsafe.Pointer hazards from *Black Hat Go*.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags unsafe.Pointer cast between unrelated types
- [ ] Substrate-coherence check via `jm associate`
