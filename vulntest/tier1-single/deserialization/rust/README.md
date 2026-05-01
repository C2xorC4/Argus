# Insecure deserialisation — Rust variant

## Brief

`bincode::deserialize::<Message>(&bytes)` on attacker-controlled
bytes. Pure-Rust deserialisers don't have JVM/.NET-style
gadget-chain RCE (no reflective construction), but they have:

- **Allocation amplification** — `Vec<u8>` with attacker-supplied
  length triggers large allocations.
- **Panic-induced DoS** — malformed bytes panic in the deserialiser.
- **Logic compromise** — invariants only enforced via trusted
  constructors are bypassed by deserialisation.

Detector: `scripts/analysis/taint.py`. Signal: any `serde::deserialize`
/ format-specific deserialise call (`bincode::deserialize`,
`postcard::from_bytes`, `rmp_serde::from_slice`) with an attacker-
controlled byte slice and no `with_limit` configuration.

## Remediation

```rust
// before
let msg: Message = bincode::deserialize(&bytes).expect("...");

// after — bounded deserialiser
let cfg = bincode::DefaultOptions::new().with_limit(1024 * 1024);
let msg: Message = cfg.deserialize(&bytes)?;
```

## Operator-validation checklist

- [ ] Build clean (cargo build with serde+bincode)
- [ ] Detector flags unbounded bincode deserialize
- [ ] Substrate-coherence check via `jm associate`
