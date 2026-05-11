"""Trusted-path cache-load detector.

v1 — binary-scope co-presence: fires `trusted_path_cache_load`
(MEDIUM) when the binary contains an attacker-writable path
literal AND imports a load-class API. High-recall, low-precision
fast-path.

v2 — per-callsite xref: fires `trusted_path_xref_to_load` (HIGH)
when a specific attacker-writable path literal flows to a
specific load-API call site. The detector walks SSA definitions
back from the load callsite's path argument to a constant
pointer; if that pointer resolves to a string in the binary's
string table containing an attacker-writable token, emit.

When v2 fires for a binary, v1 is suppressed for that binary
(v2 is strictly more informative for the proven cases — v1 only
adds value when no specific flow could be resolved).

Knowledge anchors:
- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]`
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in, strings_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh


CATEGORY_META = {
    "trusted_path_cache_load": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-345", "CWE-426"],
        "mitre": ["T1574"],
        "knowledge_refs": [
            "[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]",
        ],
    },
    "trusted_path_xref_to_load": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-345", "CWE-426"],
        "mitre": ["T1574"],
        "knowledge_refs": [
            "[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]",
        ],
    },
}


# Path substrings that mark "attacker-writable / low-trust"
# directories on Windows + POSIX systems. Lowercase comparisons.
_ATTACKER_WRITABLE_TOKENS: tuple[str, ...] = (
    "\\temp\\", "\\appdata\\", "\\programdata\\",
    "\\users\\public\\", "\\windows\\temp\\",
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/var/lib/", "/home/",
)


# Load-class APIs whose presence makes the trusted-path signal
# meaningful. CreateFile is dual-use (read or write) — its presence
# is a weak signal alone but combined with an attacker-writable
# string is suspicious.
_LOAD_IMPORTS: frozenset[str] = frozenset({
    "LoadLibraryA", "LoadLibraryW",
    "LoadLibraryExA", "LoadLibraryExW",
    "GetModuleHandleA", "GetModuleHandleW",
    "ReadFile", "ReadFileEx",
    "MapViewOfFile",
    "fopen", "freopen", "open", "openat",
    "dlopen", "dlmopen",
    "CreateFileA", "CreateFileW", "CreateFile2",
})


# Subset of load APIs where a specific argument is the path/filename
# string. Maps API name → 0-indexed parameter position.
_LOAD_PATH_ARG_INDEX: dict[str, int] = {
    "LoadLibraryA": 0, "LoadLibraryW": 0,
    "LoadLibraryExA": 0, "LoadLibraryExW": 0,
    "GetModuleHandleA": 0, "GetModuleHandleW": 0,
    "CreateFileA": 0, "CreateFileW": 0, "CreateFile2": 0,
    "fopen": 0, "freopen": 0,
    "open": 0,
    "openat": 1,            # int dirfd, const char *pathname
    "dlopen": 0,
    "dlmopen": 1,           # Lmid_t lmid, const char *filename
}


def _build_string_addr_index(bv) -> dict[int, str]:
    """Build {address → string_value} from the binary's strings table.

    Used for O(1) lookup when xref-resolving a load callsite's path
    argument back to its string literal.
    """
    out: dict[int, str] = {}
    for s, addr in (strings_in(bv) or []):
        out[int(addr)] = s
    return out


def _expr_to_const_addr(expr) -> Optional[int]:
    """Resolve an MLIL expression to a constant pointer address, if it
    is one. Handles: ConstPtr operations, Load-of-ConstPtr (reading a
    global ptr), and PossibleValueSet-resolved ConstantPointerValue.
    Returns None when the expression is not a constant pointer.
    """
    if expr is None:
        return None
    # Direct constant.
    cval = getattr(expr, "constant", None)
    if cval is not None:
        try:
            return int(cval)
        except Exception:
            pass
    op_name = type(expr).__name__
    if "ConstantPtr" in op_name or "ConstPtr" in op_name:
        v = getattr(expr, "value", None) or getattr(expr, "constant", None)
        try:
            if v is not None:
                return int(v)
        except Exception:
            pass
    # Load-of-ConstPtr — `*global_ptr_field`.
    if "Load" in op_name:
        src = getattr(expr, "src", None)
        cv = getattr(src, "constant", None) if src is not None else None
        if cv is not None:
            try:
                return int(cv)
            except Exception:
                pass
    # PossibleValueSet-tracked constant pointer.
    val = getattr(expr, "value", None)
    if val is not None:
        vtype = getattr(val, "type", None)
        type_name = (getattr(vtype, "name", "") or str(vtype) or "").lower()
        if "constantpointer" in type_name or "constant_pointer" in type_name:
            v = getattr(val, "value", None)
            try:
                if v is not None:
                    return int(v)
            except Exception:
                pass
    return None


def _resolve_path_arg_to_addr(function, expr, max_hops: int = 4,
                              seen: Optional[set] = None) -> Optional[int]:
    """Walk SSA def chain back from `expr` to a constant-pointer
    address. Returns the address or None.

    Handles common shapes:
      - direct ConstPtr / ConstantPointerValue
      - VarSsa whose def's src is a ConstPtr
      - VarSsa whose def's src is another VarSsa (chain through
        intermediate copies)
      - Phi nodes — try the first definition; conservative.
    """
    if seen is None:
        seen = set()
    if max_hops <= 0 or expr is None:
        return None
    addr = _expr_to_const_addr(expr)
    if addr is not None:
        return addr

    ssa_var = ilh.expr_to_ssa_var(expr)
    if ssa_var is None:
        return None
    key = str(ssa_var)
    if key in seen:
        return None
    seen.add(key)
    defn = ilh.ssa_def_of(function, ssa_var)
    if defn is None:
        return None
    src_expr = getattr(defn, "src", None)
    if src_expr is not None:
        a = _resolve_path_arg_to_addr(function, src_expr,
                                      max_hops - 1, seen)
        if a is not None:
            return a
    # Phi: try each predecessor def.
    op_name = type(defn).__name__
    if "Phi" in op_name:
        for v in (getattr(defn, "src", None) or []):
            a = _resolve_path_arg_to_addr(function, v,
                                          max_hops - 1, seen)
            if a is not None:
                return a
    return None


def _attacker_writable_token(s: str) -> Optional[str]:
    """Return the matching token if `s` contains an attacker-writable
    path substring (case-insensitive), else None."""
    if not s:
        return None
    sl = s.lower()
    for tok in _ATTACKER_WRITABLE_TOKENS:
        if tok in sl:
            return tok
    return None


def find_trusted_path_xref_to_load(
        bv, *, binary: str, arch: str, platform: str,
        detector: str = "analysis.trusted_path",
) -> list[Finding]:
    """v2 per-callsite detector.

    For every load-class call site, resolve its path argument back to
    a constant string address. If that string contains an attacker-
    writable token, emit `trusted_path_xref_to_load` HIGH.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    relevant_apis = [a for a in _LOAD_PATH_ARG_INDEX if a in imports]
    if not relevant_apis:
        return findings

    string_idx = _build_string_addr_index(bv)
    if not string_idx:
        return findings

    seen_keys: set[tuple[str, str, int]] = set()  # (function, api, addr)

    for api in relevant_apis:
        path_idx = _LOAD_PATH_ARG_INDEX[api]
        for call_addr, mlil in ilh.call_sites_of_import(bv, api):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if len(params) <= path_idx:
                continue
            func = getattr(mlil, "function", None)
            if func is None:
                continue
            sf = getattr(func, "source_function", None) or func
            fname = getattr(sf, "name", "") or f"sub_{getattr(sf, 'start', 0):x}"

            string_addr = _resolve_path_arg_to_addr(func, params[path_idx])
            if string_addr is None:
                continue
            string_value = string_idx.get(int(string_addr))
            if string_value is None:
                continue
            tok = _attacker_writable_token(string_value)
            if tok is None:
                continue

            key = (fname, api, int(call_addr))
            if key in seen_keys:
                continue
            seen_keys.add(key)

            meta = CATEGORY_META["trusted_path_xref_to_load"]
            display = string_value if len(string_value) <= 96 else (string_value[:96] + "...")
            findings.append(Finding(
                id="",
                category="trusted_path_xref_to_load",
                severity=meta["severity"],
                address=int(call_addr),
                function=fname,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre"]),
                description=(
                    f"{fname}: load API {api}@0x{call_addr:x} consumes "
                    f"attacker-writable path literal {display!r} "
                    f"(token {tok!r}). Static flow from the string "
                    f"literal at 0x{string_addr:x} reaches this load "
                    f"call site without intermediate validation — "
                    f"trusted-path-cache-load proven by xref."
                ),
                evidence=[Evidence(
                    kind="path_literal_xref_to_load_callsite",
                    source=detector,
                    payload=(f"api={api} call_addr=0x{call_addr:x} "
                             f"string_addr=0x{string_addr:x} "
                             f"string={display!r} token={tok!r}"),
                    address=int(call_addr),
                    function=fname,
                )],
                details={
                    "load_api": api,
                    "call_addr": hex(int(call_addr)),
                    "string_addr": hex(int(string_addr)),
                    "string": string_value,
                    "matched_token": tok,
                },
            ))

    return findings


def find_trusted_path_loads(bv, *, binary: str, arch: str, platform: str,
                            detector: str = "analysis.trusted_path"
                            ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    load_imports_present = imports & _LOAD_IMPORTS
    if not load_imports_present:
        return findings

    # Collect attacker-writable path strings in the binary.
    matched_paths: list[tuple[str, int]] = []
    for s, addr in (strings_in(bv) or []):
        sl = s.lower()
        for tok in _ATTACKER_WRITABLE_TOKENS:
            if tok in sl:
                matched_paths.append((s, addr))
                break

    if not matched_paths:
        return findings

    meta = CATEGORY_META["trusted_path_cache_load"]
    # Anchor at the first matched string; v2 will resolve per-callsite.
    sample_path, sample_addr = matched_paths[0]
    findings.append(Finding(
        id="",
        category="trusted_path_cache_load",
        severity=meta["severity"],
        address=sample_addr,
        function="<binary>",
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta["knowledge_refs"]),
        cwe=list(meta["cwe"]),
        mitre_attack=list(meta["mitre"]),
        description=(
            f"binary references {len(matched_paths)} attacker-writable "
            f"path string(s) (e.g. {sample_path[:64]!r}) and imports "
            f"load-class APIs ({sorted(load_imports_present)[:3]}...). "
            f"Plausibly loads content from a low-trust location and "
            f"treats it as authoritative — confirm with xref / taint."
        ),
        evidence=[Evidence(
            kind="attacker_writable_path_in_binary",
            source=detector,
            payload=(f"sample={sample_path[:80]!r} "
                     f"loads={sorted(load_imports_present)[:8]}"),
            address=sample_addr,
            function="<binary>",
        )],
        details={
            "matched_path_count": len(matched_paths),
            "sample_paths": [p for p, _ in matched_paths[:8]],
            "load_imports_present": sorted(load_imports_present),
        },
    ))
    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.trusted_path"
            ) -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    # v2 first — proven flows beat binary-scope co-presence.
    v2 = find_trusted_path_xref_to_load(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
    if v2:
        # When v2 has fired at all, v1 adds no information (any
        # remaining unresolved paths are either unreachable or
        # tracked via patterns v2 doesn't model yet — emitting v1
        # alongside v2 would just duplicate the binary-level signal).
        return v2

    return find_trusted_path_loads(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
