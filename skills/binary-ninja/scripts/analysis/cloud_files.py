"""Cloud Files write-proxy detector.

Detects Windows binaries that use the Cloud Files API
(CfRegisterSyncRoot / CfConnectSyncRoot / CfExecute / CfHydratePlaceholder)
in a context where an attacker-controlled path argument could route a
SYSTEM-privileged write through an NTFS junction or mount point.

Exploitation shape (post-mortem, NightmareEclipse §10):

    BlueHammer uses CfRegisterSyncRoot + CfConnectSyncRoot as a BLOCKING
    CALLBACK to hold Defender's scan thread in the race window between
    GetFileAttributesW and CreateFileW (the MpIsPathSymlink TOCTOU).

    RedSun uses CfRegisterSyncRoot to register a placeholder file that
    Defender's cloud-restore path will write back to disk as SYSTEM. The
    restore write follows NTFS junctions, bypassing System32 ACL enforcement
    because the caller holds SeRestorePrivilege. An attacker-controlled
    junction at the placeholder's parent directory routes the restore write
    to an attacker-chosen destination.

Both roles — stall primitive and write-router — are invisible to
per-binary static analysis because the Cloud Files API registers a
callback into user-mode provider code; the privilege violation happens
in the interaction between Defender (SYSTEM) and the attacker's
sync-root registration.

Detection signals emitted by this module:

    cloud_files_import (INFO)
        The binary imports at least one Cloud Files API function. Weak
        signal alone; becomes HIGH when combined with a toctou or sddl finding.

    cloud_files_write_proxy (HIGH)
        The binary imports Cloud Files AND has either:
        (a) a co-located toctou finding (BlueHammer-class stall shape), OR
        (b) a permissive_sddl finding (attacker can invoke the RPC path that
            triggers Defender's cloud-restore write).
        The combination means a low-privilege attacker can cause a SYSTEM-
        context cloud-restore write via an attacker-controlled sync root.

Knowledge anchors:
    [[Memory/Knowledge/windows_defender_attack_surface]] — BlueHammer/RedSun
    [[Memory/Knowledge/argus_detector_design_principles]] — Phase vocabulary
"""
from __future__ import annotations

from typing import Optional

from ..output.finding import Evidence, Finding, Severity


CATEGORY_META = {
    "cloud_files_import": {
        "severity": Severity.INFO,
        "cwe": [],
        "mitre": ["T1574"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "cloud_files_write_proxy": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-367", "CWE-284"],
        "mitre": ["T1068", "T1574"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
            "[[Memory/Knowledge/windows_defender_attack_surface]]",
        ],
    },
}

# Cloud Files API surface. CfRegisterSyncRoot and CfConnectSyncRoot are the
# registration calls; CfExecute and CfHydratePlaceholder are the runtime
# calls that perform privileged write operations on placeholders.
_CF_IMPORTS = (
    "CfRegisterSyncRoot",
    "CfUnregisterSyncRoot",
    "CfConnectSyncRoot",
    "CfDisconnectSyncRoot",
    "CfExecute",
    "CfHydratePlaceholder",
    "CfCreatePlaceholders",
    "CfUpdatePlaceholder",
    "CfRevertPlaceholder",
    "CfOpenFileWithOplock",
)

# Subset of Cloud Files imports that indicate active write-proxy capability
# (not just querying metadata).
_CF_WRITE_PROXY_IMPORTS = frozenset((
    "CfRegisterSyncRoot",
    "CfConnectSyncRoot",
    "CfExecute",
    "CfHydratePlaceholder",
    "CfCreatePlaceholders",
))


def _imported_symbols(bv) -> set[str]:
    """Return all import names visible to Binary Ninja in this binary."""
    names: set[str] = set()
    try:
        for sym in bv.get_symbols_of_type(
                bv.symbols.__class__.__mro__[0]  # guard against API version
        ):
            names.add(sym.name)
    except Exception:
        pass
    # Fallback: walk all symbols and filter to imports.
    try:
        for sym in bv.symbols.values():
            if hasattr(sym, "__iter__"):
                for s in sym:
                    if hasattr(s, "name"):
                        names.add(s.name)
            elif hasattr(sym, "name"):
                names.add(sym.name)
    except Exception:
        pass
    return names


def _cf_imports_present(bv) -> list[str]:
    """Return sorted list of Cloud Files API names imported by the binary."""
    syms = _imported_symbols(bv)
    return sorted(s for s in _CF_IMPORTS if s in syms)


def _cf_write_proxy_imports(cf_present: list[str]) -> list[str]:
    return [s for s in cf_present if s in _CF_WRITE_PROXY_IMPORTS]


def analyze(
        session,
        findings: Optional[list[Finding]] = None,
        *,
        binary: Optional[str] = None,
        arch: Optional[str] = None,
        platform: Optional[str] = None,
        detector: str = "analysis.cloud_files",
) -> list[Finding]:
    """Emit cloud_files_import and cloud_files_write_proxy findings.

    Requires `findings` from prior detectors (sddl, race/toctou) to
    determine whether the import crosses into HIGH territory.
    When called without prior findings, emits INFO-level import findings only.
    """
    bv = getattr(session, "bv", None)
    if bv is None:
        return []

    cf_present = _cf_imports_present(bv)
    if not cf_present:
        return []

    binary = binary or getattr(session, "binary_path", "") or ""
    arch   = arch   or getattr(session, "arch",        "") or ""
    platform = platform or getattr(session, "platform",    "") or ""

    prior = findings or []
    toctou_findings = [f for f in prior
                       if getattr(f, "category", "") == "toctou"]
    sddl_findings   = [f for f in prior
                       if getattr(f, "category", "") == "permissive_sddl"]

    out: list[Finding] = []
    meta_import = CATEGORY_META["cloud_files_import"]

    # INFO: cloud_files_import — always emitted when CF API is present.
    out.append(Finding(
        id="",
        category="cloud_files_import",
        severity=meta_import["severity"],
        address=0,
        function="<import-table>",
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta_import["knowledge_refs"]),
        cwe=list(meta_import["cwe"]),
        mitre_attack=list(meta_import["mitre"]),
        confidence=1.0,
        description=(
            f"Binary imports Cloud Files API: {', '.join(cf_present)}. "
            f"Presence alone is low signal; elevated to cloud_files_write_proxy "
            f"when co-located with toctou or permissive_sddl findings."
        ),
        evidence=[Evidence(
            kind="import_table",
            source=detector,
            payload=f"cf_imports={','.join(cf_present)}",
            address=0,
            function="<import-table>",
        )],
        details={
            "cf_imports": cf_present,
            "write_proxy_imports": _cf_write_proxy_imports(cf_present),
        },
    ))

    # HIGH: cloud_files_write_proxy — CF write-capable import + TOCTOU or SDDL.
    write_proxy = _cf_write_proxy_imports(cf_present)
    if not write_proxy:
        return out
    if not (toctou_findings or sddl_findings):
        return out

    meta_proxy = CATEGORY_META["cloud_files_write_proxy"]
    has_toctou = bool(toctou_findings)
    has_sddl   = bool(sddl_findings)

    ref_toctou_fn = (
        getattr(toctou_findings[0], "function", "<unknown>")
        if has_toctou else None
    )
    ref_sddl_fn = (
        getattr(sddl_findings[0], "function", "<unknown>")
        if has_sddl else None
    )

    shape_parts = []
    if has_toctou:
        shape_parts.append(
            f"TOCTOU race ({ref_toctou_fn}) can be held open by a Cloud Files "
            f"provider callback registered via {write_proxy[0]} — deterministic "
            f"race window (BlueHammer stall shape)"
        )
    if has_sddl:
        shape_parts.append(
            f"permissive SDDL ({ref_sddl_fn}) allows low-priv caller to invoke "
            f"the RPC path that triggers Defender's cloud-restore write; "
            f"Cloud Files placeholder + NTFS junction routes the SYSTEM-privileged "
            f"write to attacker-chosen destination (RedSun write-proxy shape)"
        )

    out.append(Finding(
        id="",
        category="cloud_files_write_proxy",
        severity=meta_proxy["severity"],
        address=0,
        function="<import-table>",
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta_proxy["knowledge_refs"]),
        cwe=list(meta_proxy["cwe"]),
        mitre_attack=list(meta_proxy["mitre"]),
        confidence=0.80,
        description=(
            f"Cloud Files write-proxy shape detected. Binary imports "
            f"{', '.join(write_proxy)} and has co-located "
            f"{'TOCTOU' if has_toctou else ''}"
            f"{' + ' if has_toctou and has_sddl else ''}"
            f"{'permissive SDDL' if has_sddl else ''} signals. "
            f"Exploitation shapes: {'; '.join(shape_parts)}."
        ),
        evidence=[Evidence(
            kind="cloud_files_write_proxy_composition",
            source=detector,
            payload=(
                f"cf_write_imports={','.join(write_proxy)} "
                f"has_toctou={has_toctou} "
                f"has_sddl={has_sddl} "
                f"toctou_fn={ref_toctou_fn} "
                f"sddl_fn={ref_sddl_fn}"
            ),
            address=0,
            function="<import-table>",
        )],
        details={
            "cf_write_imports": write_proxy,
            "has_toctou": has_toctou,
            "has_sddl": has_sddl,
            "toctou_function": ref_toctou_fn,
            "sddl_function": ref_sddl_fn,
            "exploitation_shapes": (
                ["bluehammer_stall"] * has_toctou
                + ["redsun_write_proxy"] * has_sddl
            ),
        },
    ))

    return out


__all__ = ["analyze", "CATEGORY_META"]
