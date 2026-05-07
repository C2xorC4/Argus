"""SARIF 2.1.0 renderer for Argus Findings.

Phase 0: thin stub that consumes the Finding v2 schema and emits a
minimal-but-conformant SARIF document. Phase 1 fleshes out the rule
table from the heuristics modules; Phase 6 (report-writer) extends
with the vendor-specific fields.
"""

from __future__ import annotations

import json
from typing import Iterable

from .finding import Finding, Severity


_SEVERITY_TO_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}


def _result_for(finding: Finding) -> dict:
    return {
        "ruleId": finding.category,
        "level": _SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": finding.description or finding.cite()},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.binary},
                    "region": {
                        "startLine": 1,
                        "properties": {
                            "address": hex(finding.address),
                            "function": finding.function,
                        },
                    },
                }
            }
        ],
        "properties": {
            "argus_id": finding.id,
            "argus_state": finding.state.value,
            "argus_detector": finding.detector,
            "argus_knowledge_refs": finding.knowledge_refs,
            "argus_mitigation_weighted_exploitability":
                finding.mitigation_weighted_exploitability,
            "cwe": finding.cwe,
            "mitre_attack": finding.mitre_attack,
            "disclosure_altitude": finding.disclosure_altitude.value,
        },
    }


def _rule_for(finding: Finding) -> dict:
    return {
        "id": finding.category,
        "name": finding.category.replace("_", " ").title(),
        "shortDescription": {"text": finding.category.replace("_", " ")},
        "fullDescription": {
            "text": (
                f"Detector: {finding.detector}. "
                f"Knowledge refs: {', '.join(finding.knowledge_refs) or 'none'}."
            )
        },
        "properties": {
            "cwe": finding.cwe,
            "mitre_attack": finding.mitre_attack,
        },
    }


def render(findings: Iterable[Finding]) -> dict:
    """Return a SARIF 2.1.0-conformant dict for a sequence of Findings."""
    findings_list = list(findings)

    rule_index: dict[str, dict] = {}
    results: list[dict] = []
    for f in findings_list:
        rule_index.setdefault(f.category, _rule_for(f))
        results.append(_result_for(f))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Argus",
                        "version": "0.0.1-phase0",
                        "informationUri": "https://github.com/c2xorc4/argus",
                        "rules": list(rule_index.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render_json(findings: Iterable[Finding], indent: int = 2) -> str:
    return json.dumps(render(findings), indent=indent, default=str)
