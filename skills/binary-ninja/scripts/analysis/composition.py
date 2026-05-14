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
    # NDR v3 composition: RPC path-method + Cloud Files write-proxy import.
    # When a procnum that takes wchar_t* co-exists with CfRegisterSyncRoot /
    # CfConnectSyncRoot etc., the attacker can both (a) call the method with
    # an attacker-controlled path AND (b) register a sync-root callback to
    # hold Defender's scan thread in the TOCTOU window deterministically.
    # Full BlueHammer stall chain without requiring TOCTOU to be co-located
    # in the same binary (Cloud Files callback is the stall primitive).
    "rpc_callable_cloud_stall": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-367", "CWE-284"],
        "mitre": ["T1068", "T1574"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
            "[[Memory/Knowledge/windows_defender_attack_surface]]",
        ],
    },
    # Cross-binary composition: SDDL in binary A + TOCTOU in binary B,
    # bridged by A's import table containing the specific TOCTOU function
    # from B. Multi-DLL service clusters are the primary consumer.
    "cross_binary_remote_callable_toctou": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-367", "CWE-284"],
        "mitre": ["T1068", "T1574"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    # NDR v2 composition: a specific procnum that takes a wchar_t*
    # argument (identified via NDR format-string walk) combined with
    # permissive SDDL on the interface and a co-located TOCTOU shape.
    # This is the named-procnum BlueHammer-class primitive: call
    # procnum N with an attacker-controlled path, race the TOCTOU.
    "rpc_callable_path_toctou": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-367", "CWE-284"],
        "mitre": ["T1068", "T1574"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
            "[[Memory/Knowledge/windows_defender_attack_surface]]",
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


_PATH_RACE_TOKENS = frozenset([
    "pathfileexists", "getfileattributes", "createfile", "deletefile",
    "movefile", "copyfile", "findfirstfile", "findnextfile", "removedirectory",
    "createdirectory", "setfileinformation", "ntcreatefile", "ntopenfile",
    "zwcreatefile", "zwopenfile", "pathisrelative", "pathcanonicalize",
])
_TOKEN_RACE_TOKENS = frozenset([
    "impersonate", "rpcimpersonate", "setthreadtoken", "openthreadtoken",
    "duplicatetoken", "createtoken", "logonuser", "reverttoself",
    "adjusttokenprivileges",
])


def _toctou_payload(finding) -> str:
    """Extract the concatenated evidence payload string from a TOCTOU finding.
    The payload typically contains API names like 'PathFileExistsW -> CreateFileW'.
    """
    evs = getattr(finding, "evidence", None) or []
    return " ".join(getattr(e, "payload", "") for e in evs)


def _imported_function_names(bv) -> frozenset:
    """Return frozenset of imported function names visible in bv.

    In production Binja, uses get_symbols_of_type for the ImportedFunctionSymbol
    kind. Falls back to iterating bv.symbols.values() (MockBV path — only
    import names are populated there, so all names are treated as imports).
    """
    names: set[str] = set()
    if bv is None:
        return frozenset()
    try:
        from binaryninja import SymbolType
        for sym in bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol):
            n = getattr(sym, "name", "") or ""
            if n:
                names.add(n)
        return frozenset(names)
    except (ImportError, TypeError, AttributeError, Exception):
        pass
    try:
        items = (bv.symbols.values()
                 if hasattr(bv.symbols, "values") else bv.symbols)
        for sym in items:
            if hasattr(sym, "__iter__") and not isinstance(sym, str):
                for s in sym:
                    n = getattr(s, "name", "") or ""
                    if n:
                        names.add(n)
            else:
                n = getattr(sym, "name", "") or ""
                if n:
                    names.add(n)
    except Exception:
        pass
    return frozenset(names)


def _classify_lpe_shape(fn_name: str, toctou_evidence_payload: str = "") -> str:
    """Classify the LPE shape from a TOCTOU function name and/or evidence.

    Returns 'path-race' (BlueHammer/file-symlink class),
    'token-race' (FakePotato/impersonation class), or 'unknown'.

    Checks the evidence payload first (contains actual API names like
    PathFileExistsW@0x... -> CreateFileW@0x...) before falling back to
    the containing function name. Mangled C++ names rarely spell out the
    API token directly so the payload check is the higher-signal path.
    """
    combined = (fn_name + " " + toctou_evidence_payload).lower()
    if any(tok in combined for tok in _PATH_RACE_TOKENS):
        return "path-race (file/symlink class)"
    if any(tok in combined for tok in _TOKEN_RACE_TOKENS):
        return "token-race (impersonation/FakePotato class)"
    return "unknown — check TOCTOU function name and evidence payload manually"


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
    rpc_path_findings = [f for f in findings
                         if getattr(f, "category", "") == "remote_callable_path_method"]

    # Require at least sddl + one of (toctou, rpc_path) to have
    # anything to compose. Pure toctou-without-sddl is uninteresting;
    # pure rpc_path-without-sddl means the interface isn't accessible.
    if not sddl_findings:
        return out
    if not toctou_findings and not rpc_path_findings:
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

    rpc_hosted, rpc_imports = _binary_hosts_rpc_or_com(bv)

    # Gate the callgraph-reachability track on both shapes being present.
    # NDR-path composition runs separately below regardless.
    _do_toctou_track = bool(sddl_entries and toctou_entries)

    # For each TOCTOU, check reachability from each SDDL. Emit one
    # composite per (toctou, sddl) pair that's reachable. Cap at
    # the closest SDDL for each TOCTOU to avoid combinatorial blow-up.
    emitted_keys: set[tuple[int, int]] = set()
    matched_toctou_addrs: set[int] = set()
    for tf, tfunc in (toctou_entries if _do_toctou_track else []):
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
                "lpe_class": _classify_lpe_shape(t_fn_name, _toctou_payload(tf)),
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
    if _do_toctou_track:  # Cooccurrence track requires both shapes
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
                    + f" Triage: verify (1) SDDL rights grant write/exec "
                    f"(not read-only) to low-privilege callers; "
                    f"(2) TOCTOU function is reachable via a low-privilege "
                    f"IPC call path; (3) classify race shape: "
                    f"{_classify_lpe_shape(t_fn_name, _toctou_payload(tf))}."
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
                    "lpe_class": _classify_lpe_shape(t_fn_name, _toctou_payload(tf)),
                    "reachability_proven": False,
                },
            ))

    # Cloud Files composition track: cloud_files_write_proxy is already
    # emitted by cloud_files.py with its own TOCTOU/SDDL co-location logic.
    # Add a composition-level finding when a cloud_files_write_proxy finding
    # AND an rpc_path_finding exist in the same binary: this names the specific
    # procnum that triggers the cloud-restore flow (BlueHammer stall + path).
    cf_proxy_findings = [f for f in findings
                         if getattr(f, "category", "") == "cloud_files_write_proxy"]
    if cf_proxy_findings and rpc_path_findings:
        meta_cf = CATEGORY_META.get("rpc_callable_cloud_stall")
        if meta_cf:
            for rpf in rpc_path_findings:
                proc_idx = 0
                interface_uuid = ""
                transfer_syntax = "unknown"
                try:
                    d = rpf.details or {}
                    proc_idx = d.get("proc_idx", 0)
                    interface_uuid = d.get("interface_uuid", "")
                    transfer_syntax = d.get("transfer_syntax", "unknown")
                except Exception:
                    pass
                rp_addr = _finding_addr(rpf)
                rp_fn = getattr(rpf, "function", "<unknown>")
                cf_imports = []
                try:
                    cf_imports = (cf_proxy_findings[0].details or {}).get(
                        "cf_write_imports", [])
                except Exception:
                    pass
                out.append(Finding(
                    id="",
                    category="rpc_callable_cloud_stall",
                    severity=meta_cf["severity"],
                    address=rp_addr,
                    function=rp_fn,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta_cf["knowledge_refs"]),
                    cwe=list(meta_cf["cwe"]),
                    mitre_attack=list(meta_cf["mitre"]),
                    confidence=0.85,
                    description=(
                        f"RPC method {interface_uuid} procnum {proc_idx} "
                        f"({rp_fn}) takes a wchar_t* path parameter AND the "
                        f"binary imports Cloud Files write-proxy API "
                        f"({', '.join(cf_imports)}). "
                        f"BlueHammer stall shape: attacker calls this procnum, "
                        f"registers a Cloud Files sync root to block Defender's "
                        f"scan thread in the TOCTOU window, then redirects the "
                        f"path via NtCreateSymbolicLinkObject."
                    ),
                    evidence=[Evidence(
                        kind="rpc_path_cloud_files_composition",
                        source=detector,
                        payload=(
                            f"interface_uuid={interface_uuid} "
                            f"proc_idx={proc_idx} "
                            f"transfer_syntax={transfer_syntax} "
                            f"cf_imports={','.join(cf_imports)}"
                        ),
                        address=rp_addr,
                        function=rp_fn,
                    )],
                    details={
                        "interface_uuid": interface_uuid,
                        "proc_idx": proc_idx,
                        "handler_function": rp_fn,
                        "handler_addr": hex(rp_addr),
                        "transfer_syntax": transfer_syntax,
                        "cf_write_imports": cf_imports,
                        "exploitation_shape": (
                            "bind → call_procnum_with_attacker_path → "
                            "cloud_files_stall → race_toctou_symlink"
                        ),
                    },
                ))

    # NDR-path composition track: rpc_path_findings + sddl (+ toctou).
    # When NDR v2 has identified specific procnums that take wchar_t*
    # path parameters (remote_callable_path_method), combine them with
    # permissive_sddl to name the exact PoC entry point. If toctou is
    # also present in the same binary, the full BlueHammer-class chain
    # is structural: call procnum N, supply attacker path, race TOCTOU.
    if rpc_path_findings and sddl_findings:
        meta_ndr = CATEGORY_META["rpc_callable_path_toctou"]
        has_toctou = bool(toctou_findings)
        ref_sddl = sddl_findings[0]
        ref_sddl_fn = getattr(ref_sddl, "function", "<unknown>")
        ref_sddl_addr = _finding_addr(ref_sddl)
        try:
            ref_sddl_text = (ref_sddl.details or {}).get("sddl_text", "") or ""
        except Exception:
            ref_sddl_text = ""

        for rpf in rpc_path_findings:
            proc_idx = 0
            interface_uuid = ""
            transfer_syntax = "unknown"
            try:
                d = rpf.details or {}
                proc_idx = d.get("proc_idx", 0)
                interface_uuid = d.get("interface_uuid", "")
                transfer_syntax = d.get("transfer_syntax", "unknown")
            except Exception:
                pass
            rp_addr = _finding_addr(rpf)
            rp_fn = getattr(rpf, "function", "<unknown>")
            chain_desc = (
                f"NDR-confirmed path-taking RPC method: interface "
                f"{interface_uuid} procnum {proc_idx} ({rp_fn}) "
                f"accepts wchar_t* parameter (transfer syntax: "
                f"{transfer_syntax}); interface has permissive SDDL "
                f"({ref_sddl_fn} at 0x{ref_sddl_addr:x}"
                + (f", SDDL: {ref_sddl_text[:80]}" if ref_sddl_text else "")
                + f"). "
                + (
                    "TOCTOU race shape also present in binary — "
                    "full BlueHammer-class chain: bind to interface, "
                    f"call procnum {proc_idx} with attacker-controlled "
                    "path, race symlink swap between check and use."
                    if has_toctou else
                    "No TOCTOU detected in same binary — path exposure "
                    "confirmed but race primitive not co-located."
                )
            )
            out.append(Finding(
                id="",
                category="rpc_callable_path_toctou",
                severity=meta_ndr["severity"],
                address=rp_addr,
                function=rp_fn,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta_ndr["knowledge_refs"]),
                cwe=list(meta_ndr["cwe"]),
                mitre_attack=list(meta_ndr["mitre"]),
                confidence=0.85 if has_toctou else 0.65,
                description=chain_desc,
                evidence=[Evidence(
                    kind="ndr_path_sddl_toctou_composition",
                    source=detector,
                    payload=(
                        f"interface_uuid={interface_uuid} "
                        f"proc_idx={proc_idx} "
                        f"transfer_syntax={transfer_syntax} "
                        f"sddl_fn={ref_sddl_fn} "
                        f"has_toctou={has_toctou}"
                    ),
                    address=rp_addr,
                    function=rp_fn,
                )],
                details={
                    "interface_uuid": interface_uuid,
                    "proc_idx": proc_idx,
                    "handler_function": rp_fn,
                    "handler_addr": hex(rp_addr),
                    "transfer_syntax": transfer_syntax,
                    "sddl_function": ref_sddl_fn,
                    "sddl_addr": hex(ref_sddl_addr),
                    "sddl_text": ref_sddl_text,
                    "has_toctou_colocated": has_toctou,
                    "exploitation_shape": (
                        "bind → call_procnum_with_attacker_path → race_toctou"
                        if has_toctou else
                        "bind → call_procnum_with_attacker_path"
                    ),
                },
            ))

    return out


def compose_cross_binary(
    cluster: list[dict],
    *,
    detector: str = "analysis.composition",
) -> list[Finding]:
    """Cross-binary composition via import-table bridge.

    `cluster` is a list of dicts, one per binary in the service cluster:
        {
            "bv":       <BinaryView or None>,
            "binary":   "MpSvc.dll",
            "arch":     "x86_64",
            "platform": "windows-x86_64",
            "findings": [<Finding>, ...],
        }

    For each pair (A, B) where A ≠ B:
      - A has at least one permissive_sddl finding
      - B has at least one toctou finding
      - A's import table contains the name of B's TOCTOU-containing function

    When all three conditions hold, emit `cross_binary_remote_callable_toctou`
    (HIGH, confidence 0.75) naming the specific cross-module reachability path.

    Confidence is 0.75 rather than the same-binary 0.8 because the import-
    table match proves A can call B's function, but does not prove that the
    specific SDDL entry point's callgraph reaches that import site (only that
    A imports it somewhere). Use in conjunction with same-binary `compose()`.
    """
    out: list[Finding] = []
    if not cluster or len(cluster) < 2:
        return out

    meta = CATEGORY_META.get("cross_binary_remote_callable_toctou")
    if not meta:
        return out

    # Build per-binary index: binary_name → {bv, arch, platform, findings}
    entries: dict[str, dict] = {}
    for entry in cluster:
        b = entry.get("binary", "")
        if b:
            entries[b] = entry

    # Cache imported function names per binary to avoid redundant extraction.
    import_cache: dict[str, frozenset] = {
        b: _imported_function_names(e.get("bv"))
        for b, e in entries.items()
    }

    emitted: set[tuple[str, str, int]] = set()  # (bin_a, bin_b, toctou_addr)

    for bin_a, entry_a in entries.items():
        sddl_findings = [f for f in entry_a.get("findings", [])
                         if getattr(f, "category", "") == "permissive_sddl"]
        if not sddl_findings:
            continue
        imports_a = import_cache.get(bin_a, frozenset())

        for bin_b, entry_b in entries.items():
            if bin_b == bin_a:
                continue
            toctou_findings = [f for f in entry_b.get("findings", [])
                                if getattr(f, "category", "") == "toctou"]
            if not toctou_findings:
                continue

            for tf in toctou_findings:
                toctou_fn = getattr(tf, "function", "") or ""
                if toctou_fn not in imports_a:
                    continue  # no import-table match

                t_addr = _finding_addr(tf)
                key = (bin_a, bin_b, t_addr)
                if key in emitted:
                    continue
                emitted.add(key)

                ref_sf = sddl_findings[0]
                s_addr = _finding_addr(ref_sf)
                s_fn = getattr(ref_sf, "function", "<unknown>")
                lpe_cls = _classify_lpe_shape(toctou_fn, _toctou_payload(tf))

                out.append(Finding(
                    id="",
                    category="cross_binary_remote_callable_toctou",
                    severity=meta["severity"],
                    address=t_addr,
                    function=toctou_fn,
                    binary=bin_a,
                    arch=entry_a.get("arch", "unknown"),
                    platform=entry_a.get("platform", "unknown"),
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    confidence=0.75,
                    description=(
                        f"Cross-binary remote-callable TOCTOU. "
                        f"{bin_a} has permissive SDDL on {s_fn} "
                        f"(0x{s_addr:x}) and its import table contains "
                        f"{toctou_fn}, which holds a TOCTOU race at "
                        f"0x{t_addr:x} in {bin_b}. "
                        f"A low-privilege caller can invoke {bin_a}'s "
                        f"IPC entry and reach the race via the "
                        f"cross-module import. LPE shape: {lpe_cls}."
                    ),
                    evidence=[Evidence(
                        kind="cross_binary_import_composition",
                        source=detector,
                        payload=(
                            f"sddl_binary={bin_a} sddl_fn={s_fn} "
                            f"sddl_addr=0x{s_addr:x} "
                            f"toctou_binary={bin_b} "
                            f"toctou_fn={toctou_fn} "
                            f"toctou_addr=0x{t_addr:x} "
                            f"bridge=import_table"
                        ),
                        address=t_addr,
                        function=toctou_fn,
                    )],
                    details={
                        "sddl_binary": bin_a,
                        "sddl_function": s_fn,
                        "sddl_addr": hex(s_addr),
                        "toctou_binary": bin_b,
                        "toctou_function": toctou_fn,
                        "toctou_addr": hex(t_addr),
                        "cross_binary_bridge": "import_table_function_match",
                        "lpe_class": lpe_cls,
                    },
                ))
    return out


def analyze(session, findings: Optional[list[Finding]] = None, *,
            binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            peer_cluster: Optional[list[dict]] = None,
            detector: str = "analysis.composition",
            ) -> list[Finding]:
    """Composition entry-point. UNLIKE other Argus analyzers, this
    one requires the existing finding set as input — it operates on
    the per-binary aggregate, not on the binary directly.

    Callers that don't pass `findings` get an empty list back —
    composition is post-detection, not standalone.

    `peer_cluster` enables cross-binary composition. Pass a list of
    dicts (one per binary in the service cluster, including this one):
        [{"bv": bv, "binary": name, "arch": a, "platform": p,
          "findings": [...]}]
    When provided, `compose_cross_binary` runs in addition to the
    same-binary `compose` track.
    """
    if session is None or not findings:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    out = compose(bv, findings, binary=binary, arch=arch, platform=platform,
                  detector=detector)
    if peer_cluster:
        out.extend(compose_cross_binary(peer_cluster, detector=detector))
    return out


__all__ = ["analyze", "compose", "compose_cross_binary", "CATEGORY_META"]  # noqa: F401
