# Use-after-free — Rust variant

## Brief

Rust's borrow checker forbids UAF in safe code. Unsafe blocks can
construct it: `Box::into_raw` produces a `*mut T`; `Box::from_raw`
on the same pointer transfers ownership into a Box that drops at
end-of-scope; the original `*mut T` is now dangling.

Detector: `scripts/analysis/heap.py`. Pattern: `Box::from_raw`
followed by deref of the original raw pointer; or `core::ptr::drop_in_place`
followed by subsequent access.

## Reference

- LJM: `[[Memory/Knowledge/wnapi_heap_internals]]`

## Remediation

Don't escape ownership through raw pointers. Use `Box<T>`,
`Rc<T>`, `Arc<T>`, references with explicit lifetimes — the safe
abstractions are the remediation.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags into_raw → from_raw → deref pattern
- [ ] Substrate-coherence check via `jm associate`
