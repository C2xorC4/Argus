# Use-after-free — C# / .NET variant

## Brief

C# / .NET cannot UAF in managed memory (GC tracks all references).
The analog is **use-after-Dispose**: `IDisposable.Dispose()` releases
unmanaged resources (file handles, sockets, native buffers). A
method call on the disposed object operates on freed unmanaged
state — typically caught by `ObjectDisposedException` but not
always (custom IDisposable implementations may not throw).

Detector: `scripts/analysis/heap.py` (managed-IL extended). Pattern:
`callvirt` on a local after a `callvirt Dispose()` on the same local
within the same method.

See [`../c/README.md`](../c/README.md) for the broader UAF class.

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags use-after-Dispose pattern
- [ ] Substrate-coherence check via `jm associate`
