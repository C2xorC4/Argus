# Insecure deserialisation — Go variant

## Brief

`gob.NewDecoder` + `Decode` on attacker-controlled bytes. gob is
Go's native binary format; no length cap by default. Allocation-
amplification DoS is the primary risk; gadget-chain RCE is not
available in pure Go (no reflective constructor invocation).

Detector: `scripts/analysis/taint.py`. Signal: `gob.NewDecoder` /
`json.NewDecoder` / `yaml.NewDecoder` over a reader sourced from
attacker-controlled IO without a `MaxBytesReader` / `LimitReader`.

## Remediation

```go
// before
dec := gob.NewDecoder(bytes.NewReader(data))

// after — capped reader
dec := gob.NewDecoder(io.LimitReader(bytes.NewReader(data), 1024*1024))
```

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags gob/json/yaml decode without LimitReader
- [ ] Substrate-coherence check via `jm associate`
