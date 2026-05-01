# `<module-name>` — Manual-Workflow Companion

> Template for per-module companion docs. Copy and rename to
> `analysis-<module>.md` (or `exploit-<module>.md`, etc.) when
> authoring. Replace every `<placeholder>` and remove this blockquote.

## Purpose

<one-paragraph plain-English description of what this module does
and what vulnerability or pattern class it addresses>

## Programmatic invocation

```bash
# from the skill root (D:\Repos\Security\Argus\skills\binary-ninja\)
python -m scripts.<package>.<module> --binary <path-to-target> [options]
```

Output: `Finding[]` written to stdout as JSON, or to `<output-path>`
when `--output` is given.

## Manual workflow (Binary Ninja UI)

Reproducible by a human with no prior knowledge of the binary.

1. **Open binary in Binja UI.** `File → Open` → select target. Wait
   for analysis to settle.
2. <step>
3. <step>
4. <step>
5. **Stop conditions / decision points:**
   - <condition that yields a positive finding>
   - <condition that rules out a finding>
   - <condition that warrants escalation to a different module>

## Reference material

### LJM Knowledge entries

- `[[Memory/Knowledge/<entry>]]` — what it teaches; how the
  programmatic detector uses it.
- `[[Memory/Knowledge/<entry>]]` — ...

### Reference book chapters

- *<Book title>*, ch. <N>: <topic> — <relevance to this module>.

## Divergence policy

When the programmatic module and the manual workflow disagree:

- **For <vulnerability classes A, B, C>:** the manual workflow is
  authoritative. <Reason — typically: semantic / business-logic
  classes where pattern matching misses contextual cues a human
  catches.>
- **For <vulnerability classes D, E, F>:** the programmatic module
  is authoritative. <Reason — typically: instruction-level pattern
  matching or hardening-flag detection where mechanical accuracy
  outranks pattern recognition.>
- **For <vulnerability classes G, H>:** require both to agree.
  <Reason — high-stakes findings or new pattern categories not yet
  validated.>

If the divergence is consistent across multiple targets, file an
update to either the heuristics module or this companion doc and
record the resolution in the module's commit log.

## Operator-validation checklist

- [ ] Build the relevant VulnTest cell(s) and run the programmatic
      detector — confirm expected Finding(s) emitted.
- [ ] Run the manual workflow on the same VulnTest binary —
      confirm reproduction matches the programmatic result.
- [ ] Run the substrate-coherence check (`jm associate` against the
      Finding's category + description) — confirm cited Knowledge
      entries are top matches.
- [ ] On a real-world binary in scope, run programmatic + manual
      and document any divergence under §Divergence policy above.
