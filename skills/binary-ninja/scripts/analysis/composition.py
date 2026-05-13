"""Cross-detector composition — exploitation-grade findings.

Individual Argus detectors emit per-shape signals (TOCTOU race,
permissive SDDL, trusted-path load, etc.). Each is information-
grade on its own — the combination is exploitation-grade.

This module reads the full per-binary finding set and emits
new findings that name the COMBINATIONS that have explicit
exploitation pathways in the public-research record.

v1 categories emitted:

  remote_callable_toctou
    Path-check-then-use TOCTOU (`race.py`) reachable from a
    function whose protective SDDL is permissive (`sddl.py`).
    This is the BlueHammer-class shape: a non-privileged
    caller can invoke a privileged service's RPC method which
    eventually races on a caller-supplied path. The most
    distinctive surfacing was Defender's `MpIsPathSymlink`
    helper reachable from `MpComInitializeSecurity`-protected
    COM interface.

Reachability model
------------------

v1 uses **same-binary, callgraph-forward-reachability** with a
configurable depth limit (default 12 hops). For each TOCTOU
finding F and each permissive-SDDL finding S in the same binary:
  - Start BFS from S's containing function in `bv.functions`
  - Walk callees up to `max_depth` hops
  - If F's containing function is reached, emit the composite
    finding

Cross-binary reachability (e.g. SDDL on MpComInitializeSecurity
in MpSvc.dll → TOCTOU on MpIsPathSymlink which is statically
linked into MpClient.dll too) is a v2 enhancement that needs
either an inter-binary call-graph or a knowledge entry mapping
RPC interfaces to dispatching DLLs.

Knowledge anchors:
- `[[Memory/Knowledge/argus_detector_design_principles]]`
- `[[Memory/Knowledge/nightmare_eclipse_attack_surface]]` *(planned;
  to be ingested when the operator buffers the Defender-specific
  notes)*
"""
from __future__ import annotations

from collections import deque
from typing import Optional

from ..output.finding import Evidence, Finding, Severity


CATEGORY_META = {
    "remote_callable_toctou": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-367"],  # TOCTOU
        "mitre": ["T1068"],   # privilege escalation
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "rpc_hosted_toctou_cooccurrence": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-367"],
        "mitre": ["T1068"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
}


# Imports that mark a binary as hosting an RPC / COM server. When
# present alongside a permissive_sddl + a toctou, the binary's
# remotely-callable surface and the race shape co-exist — and the
# RPC dispatch table likely glues them together (Argus's static
# callgraph misses table-driven dispatch).
_RPC_HOST_IMPORTS = (
    "RpcServerRegisterIf",
    "RpcServerRegisterIfEx",
    "RpcServerRegisterIf2",
    "RpcServerRegisterIf3",
    "RpcServerUseProtseq",
    "RpcServerUseProtseqEp",
    "RpcServerUseProtseqIf",
    "RpcServerListen",
    "RpcServerUseAllProtseqs",
    "CoRegisterClassObject",
    "CoRegisterPSClsid",
    "DcomRegisterServer",
)


def _binary_hosts_rpc_or_com(bv) -> tuple[bool, list[str]]:
    """Return (hosts_rpc, matched_imports). Reads `bv.symbols` or
    imports table — caller checks via Binja's imports surface.
    """
    matched = []
    try:
        # Binja exposes imports as Symbols with type
        # SymbolType.ImportedFunctionSymbol. Match by name.
        for sym in (bv.symbols or []):
            try:
                name = getattr(sym, "name", "") or ""
            except Exception:
                continue
            for needle in _RPC_HOST_IMPORTS:
                if needle in name:
                    matched.append(needle)
                    break
    except Exception:
        pass
    matched = sorted(set(matched))
    return (bool(matched), matched)


def _function_at_addr(bv, addr: int):
    """Return the Function containing `addr`, or None."""
    if bv is None or addr is None:
        return None
    try:
        funcs = list(bv.get_functions_containing(int(addr)) or [])
    except Exception:
        return None
    return funcs[0] if funcs else None


def _reachable(start_fn, target_fn, *, max_depth: int = 12) -> int:
    """BFS the callee graph from `start_fn`. Returns the hop count
    if `target_fn` is reached within `max_depth` hops, else -1.
    """
    if start_fn is None or target_fn is None:
        return -1
    if start_fn == target_fn:
        return 0
    target_start = int(getattr(target_fn, "start", 0) or 0)
    seen = {int(getattr(start_fn, "start", 0) or 0)}
    frontier = deque([(start_fn, 0)])
    while frontier:
        fn, depth = frontier.popleft()
        if depth >= max_depth:
            continue
        try:
            callees = list(getattr(fn, "callees", None) or [])
        except Exception:
            callees = []
        for c in callees:
            c_addr = int(getattr(c, "start", 0) or 0)
            if c_addr in seen:
                continue
            seen.add(c_addr)
            if c_addr == target_start:
                return depth + 1
            frontier.append((c, depth + 1))
    return -1


def _finding_addr(f: Finding) -> int:
    """Return the address of a Finding regardless of source variant."""
    a = getattr(f, "address", None)
    if isinstance(a, int):
        return a
    if isinstance(a, str):
        try:
            return int(a, 16) if a.startswith("0x") else int(a)
        except ValueError:
            return 0
    return 0


def compose(bv, findings: list[Finding], *, binary: str, arch: str,
            platform: str,
            detector: str = "analysis.composition",
            max_reachability_hops: int = 12) -> list[Finding]:
    """Compose existing findings into exploitation-grade
    combinations. Returns the new findings; the caller appends
    them to the master list.
    """
    out: list[Finding] = []
    if bv is None or not findings:
        return out

    toctou_findings = [f for f in findings
                       if getattr(f, "category", "") == "toctou"]
    sddl_findings = [f for f in findings
                     if getattr(f, "category", "") == "permissive_sddl"]
    if not toctou_findings or not sddl_findings:
        return out

    # Pre-resolve each finding's containing function. The Finding's
    # `function` field carries a name; we need the actual Function
    # object to walk the call graph. Use the `address` field which
    # always carries the IL anchor address.
    def _func_of(finding):
        return _function_at_addr(bv, _finding_addr(finding))

    # Build (sddl_finding, sddl_function) and (toctou_finding,
    # toctou_function) lists.
    sddl_entries = []
    for sf in sddl_findings:
        fn = _func_of(sf)
        if fn is not None:
            sddl_entries.append((sf, fn))
    toctou_entries = []
    for tf in toctou_findings:
        fn = _func_of(tf)
        if fn is not None:
            toctou_entries.append((tf, fn))

    if not sddl_entries or not toctou_entries:
        return out

    rpc_hosted, rpc_imports = _binary_hosts_rpc_or_com(bv)

    # For each TOCTOU, check reachability from each SDDL. Emit one
    # composite per (toctou, sddl) pair that's reachable. Cap at
    # the closest SDDL for each TOCTOU to avoid combinatorial blow-up.
    emitted_keys: set[tuple[int, int]] = set()
    matched_toctou_addrs: set[int] = set()
    for tf, tfunc in toctou_entries:
        best: Optional[tuple[int, object, object]] = None
        for sf, sfunc in sddl_entries:
            hops = _reachable(sfunc, tfunc, max_depth=max_reachability_hops)
            if hops < 0:
                continue
            if best is None or hops < best[0]:
                best = (hops, sf, sfunc)
        if best is None:
            continue
        hops, sf, sfunc = best
        t_addr = _finding_addr(tf)
        s_addr = _finding_addr(sf)
        key = (t_addr, s_addr)
        if key in emitted_keys:
            continue
        emitted_keys.add(key)

        t_fn_name = getattr(tf, "function", "<unknown>")
        s_fn_name = getattr(sf, "function", "<unknown>")
        sddl_text = ""
        try:
            sddl_text = (sf.details or {}).get("sddl_text") \
                or (sf.details or {}).get("content") \
                or ""
        except Exception:
            pass
        check_addr = ""
        use_addr = ""
        try:
            d = tf.details or {}
            check_addr = str(d.get("check_addr") or d.get("comparison_addr") or "")
            use_addr = str(d.get("use_addr") or d.get("store_addr") or "")
        except Exception:
            pass

        meta = CATEGORY_META["remote_callable_toctou"]
        matched_toctou_addrs.add(t_addr)
        out.append(Finding(
            id="",
            category="remote_callable_toctou",
            severity=meta["severity"],
            address=t_addr,
            function=t_fn_name,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre"]),
            confidence=0.8,
            description=(
                f"Remote-callable TOCTOU. The race {t_fn_name} at "
                f"0x{t_addr:x} is reachable in {hops} callee-hop(s) "
                f"from {s_fn_name} at 0x{s_addr:x}, whose DACL grants "
                f"permissive rights. A non-privileged caller can "
                f"invoke this binary's IPC entry and reach the "
                f"check-then-use race window. Pattern shape: see "
                f"BlueHammer / RedSun (Chaotic Eclipse, April 2026) — "
                f"the same combination of permissive RPC SDDL and a "
                f"path-resolution TOCTOU is the structural anchor "
                f"the public PoCs exploit."
            ),
            evidence=[Evidence(
                kind="cross_detector_composition",
                source=detector,
                payload=(f"toctou_addr=0x{t_addr:x} "
                         f"toctou_fn={t_fn_name} "
                         f"sddl_addr=0x{s_addr:x} "
                         f"sddl_fn={s_fn_name} "
                         f"reachability_hops={hops}"),
                address=t_addr,
                function=t_fn_name,
            )],
            details={
                "race_function": t_fn_name,
                "race_addr": hex(t_addr),
                "race_check_addr": check_addr,
                "race_use_addr": use_addr,
                "sddl_function": s_fn_name,
                "sddl_addr": hex(s_addr),
                "sddl_text": sddl_text,
                "reachability_hops": hops,
                "source_findings": [
                    {"category": "toctou", "id": getattr(tf, "id", "")},
                    {"category": "permissive_sddl", "id": getattr(sf, "id", "")},
                ],
            },
        ))

    # Relaxed-cooccurrence track. The presence of permissive_sddl
    # findings means this binary has SDDL-protected IPC objects;
    # the additional `_RPC_HOST_IMPORTS` check is informational only
    # (Defender resolves these dynamically and they may not appear
    # as static imports). For TOCTOUs we couldn't prove callgraph-
    # reachable from any SDDL — RPC/COM dispatch is table-driven
    # and bypasses Argus's static callgraph — emit MEDIUM cooccurrence.
    # This is the BlueHammer MpSvc.dll case structurally:
    # `MpComInitializeSecurity` sets SDDL on the COM interface, the
    # dispatch table maps methods to `MpIsPathSymlink`, only the
    # runtime dispatch connects them.
    if True:  # Cooccurrence track is unconditional when both shapes present
        meta = CATEGORY_META["rpc_hosted_toctou_cooccurrence"]
        for tf, _tfunc in toctou_entries:
            t_addr = _finding_addr(tf)
            if t_addr in matched_toctou_addrs:
                continue
            t_fn_name = getattr(tf, "function", "<unknown>")
            # Pick the most permissive SDDL as the reference anchor.
            ref_sf = sddl_entries[0][0]
            ref_s_addr = _finding_addr(ref_sf)
            ref_s_fn = getattr(ref_sf, "function", "<unknown>")
            out.append(Finding(
                id="",
                category="rpc_hosted_toctou_cooccurrence",
                severity=meta["severity"],
                address=t_addr,
                function=t_fn_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre"]),
                confidence=0.5,
                description=(
                    f"Co-occurrence: binary has permissive_sddl "
                    f"(e.g. {ref_s_fn} at 0x{ref_s_addr:x}, granting "
                    f"broad rights to non-admin SIDs) AND TOCTOU race "
                    f"({t_fn_name} at 0x{t_addr:x}). Static callgraph "
                    f"reachability from the SDDL-protected function to "
                    f"the race function was NOT proven within depth "
                    f"limit — table-driven RPC/COM dispatch bypasses "
                    f"Argus's static callgraph. Manual reachability "
                    f"verification required."
                    + (f" (Binary imports RPC host APIs: "
                       f"{', '.join(rpc_imports[:5])})"
                       if rpc_hosted else "")
                    + " This is the structural shape exploited by "
                    f"the public BlueHammer / RedSun (Chaotic Eclipse, "
                    f"April 2026) chains."
                ),
                evidence=[Evidence(
                    kind="cross_detector_cooccurrence",
                    source=detector,
                    payload=(f"toctou_addr=0x{t_addr:x} "
                             f"toctou_fn={t_fn_name} "
                             f"sddl_addr=0x{ref_s_addr:x} "
                             f"sddl_fn={ref_s_fn} "
                             f"rpc_imports={rpc_imports[:5]}"),
                    address=t_addr,
                    function=t_fn_name,
                )],
                details={
                    "race_function": t_fn_name,
                    "race_addr": hex(t_addr),
                    "sddl_function": ref_s_fn,
                    "sddl_addr": hex(ref_s_addr),
                    "rpc_host_imports": rpc_imports,
                    "reachability_proven": False,
                },
            ))
    return out


def analyze(session, findings: Optional[list[Finding]] = None, *,
            binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.composition",
            ) -> list[Finding]:
    """Composition entry-point. UNLIKE other Argus analyzers, this
    one requires the existing finding set as input — it operates on
    the per-binary aggregate, not on the binary directly.

    Callers that don't pass `findings` get an empty list back —
    composition is post-detection, not standalone.
    """
    if session is None or not findings:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    return compose(bv, findings, binary=binary, arch=arch, platform=platform,
                   detector=detector)


__all__ = ["analyze", "compose", "CATEGORY_META"]
