# Type confusion — C# / .NET variant

## Brief

`unsafe { (B*)p; }` reinterprets a byte buffer as struct `B` even
though it was written as struct `A`. CLR does not validate cross-
type reinterpretation in unsafe blocks. The reinterpreted `IntPtr`
can become an arbitrary-pointer when the source data was attacker-
controlled.

Detector: `scripts/analysis/taint.py` (managed-IL extended). Pattern:
`unsafe` block + `(T*)expr` cast between types whose layouts are
not field-by-field equivalent.

See [`../cpp/README.md`](../cpp/README.md) for the broader class.

## Operator-validation checklist

- [ ] Build clean (csc /unsafe)
- [ ] Detector flags cross-type unsafe pointer cast
- [ ] Substrate-coherence check via `jm associate`
