# Stack buffer overflow — C# / .NET variant

## Brief

`unsafe` block + `stackalloc byte[64]` + raw pointer write loop with
no bound. The CLR does not bounds-check raw pointer arithmetic
inside `unsafe`; the bug is identical to C semantics, just
delimited by the `unsafe` keyword.

The key detection insight: in C# binaries (managed assemblies +
native), `unsafe` regions look very different from safe code at
the IL level — `localloc`, `cpblk`, raw `&` operators are markers.

**Difficulty:** `1.0.0`.

## Build / Detection / Remediation

Detector: `scripts/analysis/taint.py` (extended for managed-runtime
IL). Pattern:

- `localloc` IL instruction (= `stackalloc`)
- `cpblk` / pointer-arithmetic-write loop in same method
- No `Span<T>` / managed-array bounds check on the write

```csharp
// after — Span<T> is bounds-checked even with stackalloc backing
Span<byte> buf = stackalloc byte[64];
buf[i] = (byte)c;          // throws IndexOutOfRangeException on overrun
```

Stored in [`remediation/Vuln.cs`](remediation/Vuln.cs).

## Operator-validation checklist

- [ ] Build clean (csc /unsafe)
- [ ] Detector flags localloc + unsafe-pointer-write loop
- [ ] PoC produces non-zero exit
- [ ] Substrate-coherence check via `jm associate`
