# `analysis/attack_surface.py` — Manual-Workflow Companion

## Purpose

Enumerates external-input entry points (network, file, IPC, stdin,
cmdline, env, registry) and walks the callgraph forward to identify
which entries can reach known sinks within `max_depth` hops. Output:
per-entry-point Findings + per-(entry, sink) reachability Findings,
prioritising entries with high sink fan-out as the high-value
ingress.

Entry-source taxonomy in `analysis/attack_surface.py:ENTRY_SOURCES`
(31 entries × 7 channels). Sink table reused from
`analysis/taint.py:SINK_TABLE` for consistency.

## Programmatic invocation

```python
from scripts.analysis import attack_surface
findings = attack_surface.analyze(session, max_depth=4)
```

## Manual workflow (Binary Ninja UI)

1. **Imports → entry sources.** Filter for `recv`, `accept`,
   `ReadFile`, `CreateNamedPipe*`, `ConnectNamedPipe`,
   `GetCommandLine*`, `getenv` family. Cross-ref each.
2. **Map each entry callsite to its enclosing function.** That
   function is your "ingress function."
3. **Walk the call graph forward from each ingress.** `Right-click
   → Show All Outgoing Calls` (or the Call Graph view).
4. **At each downstream callee, check if it reaches a sink.**
   Imports → `strcpy`, `system`, `fopen`, `printf`, `malloc`-class.
   Cross-ref each within the reachable subtree.
5. **Score the entry by fan-out.** An ingress that reaches multiple
   sinks (especially across multiple sink classes) is a high-value
   target — broad attack surface from one entry.
6. **Decision points:**
   - Entry reaches no sinks within `max_depth` → low-priority entry
     (or entry into an inert handler).
   - Entry reaches buffer-overflow + format-string + command-injection
     sinks → very high-priority; likely many bug classes accessible
     from this one channel.
   - Entry-channel mismatch (e.g., `recv` reaches `system` directly,
     no validation in between) → critical priority.

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — IPC entry
  → privileged sink chain pattern.
- `[[Memory/Knowledge/em_advanced_injection_variants]]` — entry
  via process-injection vector.

### Reference book chapters

- *The Art of Software Security Assessment* — attack-surface
  enumeration methodology.
- *The Tangled Web* / *Bug Bounty Bootcamp* — channel-specific
  entry-point patterns.

## Divergence policy

- **Entry-point taxonomy:** programmatic catalog is the source of
  truth; new entry types drive a PR to `ENTRY_SOURCES`.
- **Reachability over indirect calls:** require both. Programmatic
  follows resolved callees only; manual catches RPC dispatchers,
  message-pump-driven calls, function-pointer tables.
- **Multi-hop chains beyond `max_depth`:** manual is authoritative
  for deep chains; programmatic truncates.
- **Sanitisation-on-the-path:** manual is authoritative.
  Programmatic doesn't yet validate that an intermediate function
  sanitises the entry's input.

## Operator-validation checklist

- [ ] Run on a small network server VulnTest cell (Phase 1+ build) —
      expect attack_surface_entry findings for `recv` + chain to
      sink.
- [ ] Run on `notepad.exe` — expect no entry_reaches_sink findings
      (broad attack surface but well-validated paths).
- [ ] Substrate-coherence check.
- [ ] Spot-check a high-fan-out entry: manually walk the chain in
      Binja UI; confirm at least one of the listed sinks is
      genuinely reachable.
