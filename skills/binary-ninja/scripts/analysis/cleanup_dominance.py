"""Missing-cleanup-on-failure detector.

Fires `missing_cleanup_on_failure` when a function performs a data
commit AND does not import a matching rollback API. Distinct from
`pre_verification_write` (which adds an order constraint —
commit-before-verify with the verify call AFTER the commit). Both
can co-fire on the canonical EAC pattern; the chain template treats
them as separate primitives.

Coarser than `integrity_check_order.py`'s v3 dominance logic — this
detector intentionally fires on the structural absence of cleanup
imports, without checking whether they'd actually dominate the
failure path. The two detectors layer:

- `missing_cleanup_on_failure` (this module): cheap, structural,
   high recall.
- `pre_verification_write` (integrity_check_order.py): expensive,
   order-aware, high precision.

Together they give the operator both signals: "this function
commits without any cleanup APIs imported" + "this function commits
in a verify-AFTER-commit order with no rollback dominating the
failure return."

Knowledge anchors:
- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]`
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh
from .integrity_check_order import (
    _COMMIT_IMPORTS,
    _ROLLBACK_BY_RESOURCE,
    _function_call_set,
)


CATEGORY_META = {
    "missing_cleanup_on_failure": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-459", "CWE-377"],
        "mitre": [],
        "knowledge_refs": [
            "[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]",
        ],
    },
}


def find_missing_cleanup(bv, *, binary: str, arch: str, platform: str,
                         detector: str = "analysis.cleanup_dominance"
                         ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    commit_imports_present = imports & set(_COMMIT_IMPORTS)
    if not commit_imports_present:
        return findings
    seen_function_keys: set[int] = set()
    for sink_name in commit_imports_present:
        resource = _COMMIT_IMPORTS[sink_name]
        rollback_set = _ROLLBACK_BY_RESOURCE.get(resource, frozenset())
        for addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            func = getattr(mlil, "function", None)
            if func is None:
                continue
            fkey = ilh.function_key(func)
            if fkey in seen_function_keys:
                continue
            seen_function_keys.add(fkey)
            call_set = _function_call_set(bv, func)
            # Coarse signal: function commits but imports no rollback.
            if call_set & rollback_set:
                continue
            sf = getattr(func, "source_function", None) or func
            func_name = getattr(sf, "name", "") or ""
            meta = CATEGORY_META["missing_cleanup_on_failure"]
            findings.append(Finding(
                id="",
                category="missing_cleanup_on_failure",
                severity=meta["severity"],
                address=addr,
                function=func_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre"]),
                description=(
                    f"{sink_name}@0x{addr:x} commits to {resource} in "
                    f"{func_name} without importing any rollback API "
                    f"({sorted(rollback_set)[:3]}...). Failure-path "
                    f"cleanup is structurally absent."
                ),
                evidence=[Evidence(
                    kind="commit_no_rollback_import",
                    source=detector,
                    payload=f"commit={sink_name} resource={resource}",
                    address=addr,
                    function=func_name,
                )],
                details={
                    "commit_name": sink_name,
                    "resource_type": resource,
                    "rollback_set_searched": sorted(rollback_set),
                },
            ))
    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.cleanup_dominance"
            ) -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    return find_missing_cleanup(bv, binary=binary, arch=arch,
                                platform=platform, detector=detector)
