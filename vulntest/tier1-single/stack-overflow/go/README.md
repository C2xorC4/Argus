# Stack buffer overflow — Go / cgo variant

## Brief

Pure Go cannot stack-overflow — every slice access is
bounds-checked at runtime. Memory bugs in Go come at the cgo
boundary: Go calls into C code where the C bug is the same as the
plain-C variant.

Detection: same heuristics as the C-variant detector (strcpy +
fixed-size buffer + tainted source) — but the cgo-generated
wrapper functions (`_cgo_<hash>_Cfunc_greet`) need to be recognised
as cgo entry points.

**Difficulty:** `1.0.0`.

## Reference

- LJM: `[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]` — *Black
  Hat Go* on Go's unsafe.Pointer / cgo memory-bug surface.
- See [`../c/README.md`](../c/README.md) for the underlying class.

## Remediation

```c
// in cgo C side
strncpy(buf, name, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = 0;
```

Or move the logic to pure Go using `[]byte` slices with explicit
length.

## Operator-validation checklist

- [ ] Build clean (CGO_ENABLED=1)
- [ ] Detector flags strcpy in cgo C function
- [ ] Substrate-coherence check via `jm associate`
