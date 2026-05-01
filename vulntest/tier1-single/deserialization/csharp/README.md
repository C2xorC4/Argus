# Insecure deserialisation — C# / .NET variant

## Brief

`BinaryFormatter.Deserialize(stream)` on attacker-controlled bytes.
ysoserial.net produces gadget chains that achieve RCE on
deserialise — the standard payload uses
`System.Windows.Data.ObjectDataProvider` to invoke
`Process.Start("cmd", ...)`.

`BinaryFormatter` is formally obsolete since .NET Core 3.0 and
disabled by default in .NET 5+, but legacy usage persists.
Other vulnerable formatters: `LosFormatter`, `NetDataContractSerializer`,
`ObjectStateFormatter`, `SoapFormatter`.

Detector: `scripts/analysis/taint.py`. Signal: any reference to a
deny-listed serialiser type plus a `Deserialize` call with a stream
argument.

## Reference

- Microsoft SYSLIB0011 — BinaryFormatter obsoletion notice.
- ysoserial.net (defensive analysis) — gadget chain catalogue.

## Remediation

```csharp
// before
var obj = new BinaryFormatter().Deserialize(stream);

// after — use System.Text.Json with explicit type bound
var obj = JsonSerializer.Deserialize<MyType>(stream);
```

## Operator-validation checklist

- [ ] Build clean
- [ ] Detector flags BinaryFormatter.Deserialize call
- [ ] Substrate-coherence check via `jm associate`
