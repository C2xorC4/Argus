# `output/vendor.py` — Manual-Workflow Companion

## Purpose

Phase 6 (Reporting) sub-stage — vendor-specific report renderers
for HackerOne, MSRC, Bugcrowd, and Epic Games HackerOne. PROVEN-only
emission gate enforced by default; non-reportable disclosure
altitudes are refused without explicit override.

## Public API

```python
from scripts.output import render_vendor, render_vendor_bundle

# Single finding → vendor-specific markdown
report = render_vendor(finding, vendor="hackerone")

# Multi-finding bundle (separated by horizontal rule)
report = render_vendor_bundle(findings, vendor="msrc")

# Override the PROVEN gate for internal drafts
draft = render_vendor(finding, vendor="bugcrowd",
                      enforce_proven_only=False)
```

Recognised vendor identifiers: `hackerone` / `h1`, `msrc`,
`bugcrowd`, `epic` / `epicgames`.

## Manual workflow

Vendor reporting is operator-driven; the renderers produce a
template that the operator fills with PoC artefacts, repro steps,
and impact narrative. Steps:

1. **Confirm finding state.** Only `IMPACT_VERIFIED` (≡ PROVEN)
   findings should reach external submission. The renderer's
   default refuses non-PROVEN.
2. **Confirm disclosure altitude.** Per
   `[[Memory/Feedback/disclosure_altitude_capability_vs_results]]`,
   only `CAPABILITY` and `OBSERVATION` altitudes are externally
   reportable. `RESULT` and `INSTANCE` stay internal.
3. **Render via the appropriate vendor template.**
4. **Fill the template's operator-fill sections:**
   - Steps to reproduce (vendor wants concrete bytes / commands).
   - Impact (program-specific impact criteria).
   - CVSS vector (Bugcrowd template includes this slot).
   - Vendor-program metadata (Epic Games template includes this).
5. **Attach PoC artefacts** per vendor convention (file uploads
   for H1; text for MSRC).
6. **Submit via vendor portal** — never auto-submitted by Argus.

## Reference material

### LJM Knowledge entries

- `[[Memory/Feedback/disclosure_altitude_capability_vs_results]]` —
  altitude-vs-results framework that gates emission.

## Divergence policy

- **Programmatic authoritative for:** template structure, PROVEN
  gate enforcement, altitude refusal.
- **Manual authoritative for:** all template fill content (repro
  steps, impact, CVSS, program-specific fields). The renderers
  produce skeletons; operator drafts the substance.
- **Never auto-submit.** External submission is always operator-
  driven — this module produces strings, doesn't POST them.

## Operator-validation checklist

- [ ] `render_vendor(proven_finding, vendor="h1")` produces a
      non-empty markdown report with `## Steps to reproduce`,
      `## Impact`, and `## Recommended fix` sections.
- [ ] `render_vendor(detected_finding, vendor="h1")` (default
      enforce_proven_only=True) returns a refusal message
      starting with `# Refused`.
- [ ] All four vendor renderers (`hackerone`, `msrc`, `bugcrowd`,
      `epicgames`) return non-empty strings on a sample finding.
- [ ] Bundle render for 3 findings is separated by horizontal
      rules.
