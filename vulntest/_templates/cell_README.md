# `<class>` — `<language>` variant

> Template for a Tier-1 single-vulnerability cell. Copy to
> `vulntest/tier1-single/<class>/<language>/README.md` and fill in.
> Tier-2 (chains) and Tier-3 (obfuscated) cells use this same shape
> with extra sections; see [`vulntest/README.md`](../README.md) for
> how the tiers extend it.

## Brief

<one-paragraph plain-English description of the bug as it appears
in this language. Include the idiomatic shape — what does this
class typically look like in `<language>` source?>

**Difficulty:** `<tier>.<obfuscation>.<chain_depth>` (see
[INDEX.md](../../INDEX.md) §Difficulty rating).

## Build

```bash
make            # default target produces the test binary
make all-archs  # multi-arch build where relevant (x86_64, arm64, ...)
```

Outputs land in `build/`. The Makefile must produce a deterministic
binary so `expected.json` references stay valid.

## Detection

### Programmatic

Detector: `<scripts/analysis/<module>.py>` — heuristics from
`<scripts/heuristics/<module>.py>`.

Expected Finding(s):

```json
{
  "category": "<class>",
  "severity": "<severity>",
  "knowledge_refs": ["[[Memory/Knowledge/<entry>]]"],
  "cwe": ["CWE-<n>"],
  "mitre_attack": ["<technique-id>"]
}
```

Full expected manifest: [`expected.json`](expected.json).

### Manual (Binary Ninja UI)

Reproducible by a human with no prior knowledge of the binary.

1. **Open binary in Binja UI.**
2. <step>
3. <step>
4. <decision point — what would a human notice that confirms the
   class>

### Reference

- LJM: `[[Memory/Knowledge/<entry>]]` — what it teaches
- Book: *<Title>*, ch. <N> — what it adds

## Exploitation

**Primitive class:** <stack-OF / heap-UAF / format-string / ...>

**Mitigation considerations.** What `/GS`, CFG, ASLR, CET, PAC, MTE
do to the path:

- `/GS` present → <effect>
- CFG present → <effect>
- ASLR present → <effect>
- ...

**Idiomatic exploit walkthrough.**

```bash
./poc/trigger.sh    # or ./poc/trigger.py
```

PoC artefact: [`poc/`](poc/).

For the language-specific shape:

- **`<language>`-specific exploitation note 1** — <e.g., for C:
  stack canary + frame-pointer-omission interaction>
- **note 2** — <e.g., for Rust: how the `unsafe` block bounds the
  exploitable region>
- **note 3** — <e.g., for C#: unsafe-block + P/Invoke boundary>

## Chain potential

Likely chain partners — links to relevant Tier-2 cells:

- [`<chain-name>`](../../tier2-chains/<chain-name>/) — <how this
  primitive contributes>
- ...

## Remediation

### Idiomatic fix

```<language>
// before
<vulnerable code excerpt>

// after
<idiomatic fix in this language — bounds check, runtime guard,
language feature, etc.>
```

Stored in [`remediation/`](remediation/).

### Compiler / linker mitigations

- `-fstack-protector-strong` / `/GS` — <effect on this bug>
- CFG (`/guard:cf`) — <effect>
- ASLR (`-fPIE -pie`) — <effect>
- ...

### Architectural fix

If remediation goes beyond local code change (re-design of a trust
boundary, removal of an attack surface): describe here.

## Operator-validation checklist

- [ ] Build clean (`make` succeeds)
- [ ] Detector finds the bug at expected location
- [ ] Programmatic Finding matches `expected.json`
- [ ] PoC triggers (`./poc/trigger.sh` succeeds)
- [ ] Sanitizer / debugger confirms primitive
- [ ] Manual reproduction in Binja UI matches programmatic finding
- [ ] Substrate-coherence check: `jm associate "<class>: <description>"`
      surfaces the cited Knowledge entry as a top match
