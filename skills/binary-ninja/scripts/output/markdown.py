"""Markdown renderer for Argus Findings.

Phase 0: minimal viable renderer for human-readable triage and
internal documentation. The `report-writer` agent in Phase 6
extends with vendor-specific report formats; this module stays as
the lowest-common-denominator output.
"""

from __future__ import annotations

from typing import Iterable

from .finding import Finding, Severity


_SEVERITY_BADGE = {
    Severity.CRITICAL: "**CRITICAL**",
    Severity.HIGH: "**HIGH**",
    Severity.MEDIUM: "**MEDIUM**",
    Severity.LOW: "LOW",
    Severity.INFO: "info",
}


def _finding_block(f: Finding) -> str:
    lines: list[str] = []
    badge = _SEVERITY_BADGE[f.severity]
    lines.append(f"### {badge} — {f.category}")
    lines.append("")
    lines.append(f"**Finding ID:** `{f.id}`")
    lines.append(f"**Detector:** `{f.detector}`")
    lines.append(f"**State:** `{f.state.value}`")
    lines.append(f"**Location:** `{f.binary}` — function `{f.function}` "
                 f"@ `{hex(f.address)}` ({f.arch}/{f.platform})")
    if f.cwe:
        lines.append(f"**CWE:** {', '.join(f.cwe)}")
    if f.mitre_attack:
        lines.append(f"**MITRE ATT&CK:** {', '.join(f.mitre_attack)}")
    if f.knowledge_refs:
        lines.append(f"**Knowledge:** {', '.join(f.knowledge_refs)}")
    lines.append(f"**Mitigation-weighted exploitability:** "
                 f"{f.mitigation_weighted_exploitability:.2f}")
    if f.target_mitigations.to_dict():
        mits = ", ".join(
            f"{k}={'on' if v else 'off'}"
            for k, v in f.target_mitigations.to_dict().items()
        )
        lines.append(f"**Target mitigations:** {mits}")
    lines.append("")
    if f.description:
        lines.append(f.description)
        lines.append("")
    if f.evidence:
        lines.append("**Evidence:**")
        for e in f.evidence:
            addr = f" @ `{hex(e.address)}`" if e.address is not None else ""
            lines.append(f"- _{e.kind}_ from `{e.source}`{addr}: {e.payload}")
        lines.append("")
    if f.state_history:
        lines.append("**State history:**")
        for t in f.state_history:
            lines.append(
                f"- `{t.from_state.value}` → `{t.to_state.value}` "
                f"by `{t.actor}` at {t.timestamp.isoformat()}"
                + (f" — {t.notes}" if t.notes else "")
            )
        lines.append("")
    return "\n".join(lines)


def render(findings: Iterable[Finding], title: str = "Argus Findings") -> str:
    """Return a markdown report for a sequence of Findings."""
    findings_list = list(findings)
    findings_list.sort(key=lambda f: (-f.severity.numeric, f.category, f.address))

    out: list[str] = [f"# {title}", ""]
    out.append(f"_{len(findings_list)} findings_")
    out.append("")

    # Summary table
    out.append("## Summary")
    out.append("")
    out.append("| Severity | Category | State | Detector | ID |")
    out.append("|---|---|---|---|---|")
    for f in findings_list:
        out.append(
            f"| {_SEVERITY_BADGE[f.severity]} | `{f.category}` "
            f"| `{f.state.value}` | `{f.detector}` | `{f.id}` |"
        )
    out.append("")

    # Per-finding detail
    out.append("## Findings")
    out.append("")
    for f in findings_list:
        out.append(_finding_block(f))
        out.append("---")
        out.append("")

    return "\n".join(out)
