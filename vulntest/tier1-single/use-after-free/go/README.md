# Use-after-free — Go / unsafe.Pointer variant

## Brief

Go's GC prevents UAF in safe code; `unsafe.Pointer` escapes the
guarantee. Holding a raw pointer to a slice's backing array across
an `append` that grows past capacity creates a dangling pointer —
the GC may move (or eventually free) the original backing array
while the raw pointer still references it.

Detector: `scripts/analysis/heap.py` (Go-extended). Pattern:
`unsafe.Pointer(&slice[idx])` followed by mutation of slice length
(`append`, slice reslicing) followed by deref of the pointer.

## Reference

- LJM: `[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]`

## Remediation

Don't keep raw pointers across slice mutations. Re-fetch the
pointer after each append, or use `[]byte` directly without going
through `unsafe.Pointer`.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags unsafe.Pointer-across-append pattern
- [ ] Substrate-coherence check via `jm associate`
