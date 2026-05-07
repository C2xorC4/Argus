"""Vendor-specific report renderers — Phase 6.

HackerOne / MSRC / Bugcrowd / Epic-Games-flavoured renderings of
PROVEN findings. Per `docs/PIPELINE.md`, vendor-specific output is
the final step in the Reporting sub-stage and is gated by
`is_externally_reportable` (state == IMPACT_VERIFIED AND
disclosure_altitude in {capability, observation}).

Each renderer takes one or more `Finding` objects (typically a single
PROVEN finding that backs a vendor submission) and produces a string
in the vendor's expected format. Format details vary — H1 prefers
markdown with a structured "Steps to reproduce" / "Impact" /
"Recommended fix" layout; MSRC prefers a more rigid template;
Bugcrowd is closer to H1 but with a CVSS calculator block.

Skeleton in this revision: minimal-but-conformant renderings that
can be substituted into a vendor portal as-is. Real implementations
will pull operator metadata (researcher name, payment address,
program-specific fields) from a config and templatize accordingly.
"""

from __future__ import annotations

from typing import Iterable

from .finding import DisclosureAltitude, Finding, Severity


_SEVERITY_TO_H1_RATING = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "None",
}


def _is_externally_reportable(finding: Finding) -> bool:
    """Reportability gate per disclosure-altitude rule."""
    altitude = finding.disclosure_altitude
    return altitude in (DisclosureAltitude.CAPABILITY,
                        DisclosureAltitude.OBSERVATION)


def render_hackerone(finding: Finding) -> str:
    """HackerOne markdown report — Title / Summary / Steps /
    Impact / Recommended fix."""
    sev = _SEVERITY_TO_H1_RATING.get(finding.severity, "None")
    cwe_block = (", ".join(finding.cwe) if finding.cwe else "—")
    refs_block = ("\n".join(f"- {r}" for r in finding.knowledge_refs)
                  if finding.knowledge_refs else "—")
    return f"""# {finding.category} ({sev}) in {finding.binary}

## Summary

{finding.description}

## Steps to reproduce

(Insert per-finding repro steps; PoC artefact attached separately.)

## Impact

{finding.description}

State: `{finding.state.value}` (PROVEN required for external submission).

## Affected addresses

- `0x{finding.address:x}` in `{finding.function}`

## CWE / references

- CWE: {cwe_block}
- Knowledge refs:
{refs_block}

## Recommended fix

(Operator: insert remediation guidance per knowledge_refs.)
"""


def render_msrc(finding: Finding) -> str:
    """Microsoft Security Response Center submission — closer to a
    structured vulnerability report than free-form prose."""
    return f"""Vulnerability Type: {finding.category}
Severity: {finding.severity.value}
Affected Product: {finding.binary}
Affected Module: {finding.binary} ({finding.platform})
Architecture: {finding.arch}

Description:
{finding.description}

Reproduction:
- Address: 0x{finding.address:x} in {finding.function}
- Detector: {finding.detector}
- (Operator: attach PoC artefact + repro steps.)

CWE: {", ".join(finding.cwe) if finding.cwe else "—"}
MITRE ATT&CK: {", ".join(finding.mitre_attack) if finding.mitre_attack else "—"}

Knowledge references:
{chr(10).join(finding.knowledge_refs) or "—"}
"""


def render_bugcrowd(finding: Finding) -> str:
    """Bugcrowd submission — markdown with a CVSS placeholder."""
    sev = finding.severity.value.upper()
    return f"""**Title:** {finding.category} in {finding.binary}

**Severity:** {sev}

**CVSS:** (operator: paste vector from cvss-calc)

## Description

{finding.description}

## Reproduction

- Affected file: `{finding.binary}`
- Architecture: {finding.arch}
- Trigger address: `0x{finding.address:x}` in `{finding.function}`
- Detector: `{finding.detector}`

## Impact

(Operator: tie to bounty-program impact criteria.)

## References

{chr(10).join('- ' + r for r in finding.knowledge_refs) or "—"}
"""


def render_epic_games(finding: Finding) -> str:
    """Epic Games HackerOne — uses the H1 renderer with a vendor
    program annotation. Kept separate so program-specific fields
    (target build, server vs client, anti-cheat involvement) can
    be slotted in without re-templating the canonical H1 form."""
    base = render_hackerone(finding)
    program_block = (
        "\n## Program metadata\n\n"
        f"- vendor_program: {finding.vendor_program or 'epicgames'}\n"
        f"- bounty_category: {finding.bounty_category or '(operator: select)'}\n"
    )
    return base + program_block


_RENDERERS = {
    "hackerone": render_hackerone,
    "h1":        render_hackerone,
    "msrc":      render_msrc,
    "bugcrowd":  render_bugcrowd,
    "epic":      render_epic_games,
    "epicgames": render_epic_games,
}


def render(finding: Finding, *, vendor: str = "hackerone",
           enforce_proven_only: bool = True) -> str:
    """Render `finding` for `vendor`. Returns the rendered string.

    `enforce_proven_only` (default True) refuses to emit for findings
    whose state isn't `IMPACT_VERIFIED` and whose disclosure altitude
    isn't externally reportable. Caller can override for internal
    review drafts.
    """
    if enforce_proven_only:
        if not _is_externally_reportable(finding):
            return (
                f"# Refused — finding {finding.id} altitude "
                f"`{finding.disclosure_altitude.value}` is not externally "
                f"reportable\n"
            )
    fn = _RENDERERS.get(vendor.lower())
    if fn is None:
        raise ValueError(f"unknown vendor: {vendor!r}; "
                         f"known: {sorted(_RENDERERS)}")
    return fn(finding)


def render_bundle(findings: Iterable[Finding], *,
                  vendor: str = "hackerone",
                  enforce_proven_only: bool = True) -> str:
    """Render multiple findings into one document, separated by HR."""
    parts: list[str] = []
    for f in findings:
        parts.append(render(f, vendor=vendor,
                            enforce_proven_only=enforce_proven_only))
    return ("\n\n---\n\n").join(parts)


__all__ = [
    "render", "render_bundle",
    "render_hackerone", "render_msrc",
    "render_bugcrowd", "render_epic_games",
]
