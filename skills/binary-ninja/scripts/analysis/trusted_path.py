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

v3 — computed/registry/env-var path: fires
`trusted_path_computed_load` (HIGH) when the load-API's path
argument is a stack buffer populated by a registry read
(RegQueryValueEx, RegGetValue, SHGetValue), an environment
variable expansion (GetEnvironmentVariable,
ExpandEnvironmentStrings), or a computed path function
(GetTempPath, SHGetFolderPath, SHGetKnownFolderPath,
PathCombine). v2 back-walk handles only literal wchar_t*
constants; these sources produce runtime values that bypass the
constant-pointer check. Detection uses OUT-parameter tracking:
locates calls to the above APIs in the same function whose OUT
buffer arg resolves to the same stack slot as the load callsite's
path argument.

v1 is suppressed when either v2 or v3 fires (both are more
informative than binary-scope co-presence).

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
    "trusted_path_computed_load": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-345", "CWE-426", "CWE-427"],
        "mitre": ["T1574", "T1574.001"],
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


# ── v3: computed/registry/env-var path sources ───────────────────────────────

# APIs that read a path from the registry into a caller-supplied OUT buffer.
_REGISTRY_READ_APIS: frozenset[str] = frozenset({
    "RegQueryValueExA", "RegQueryValueExW",
    "RegGetValueA", "RegGetValueW",
    "SHGetValueA", "SHGetValueW",
})

# APIs that expand or retrieve environment-variable paths into a buffer.
_ENVVAR_READ_APIS: frozenset[str] = frozenset({
    "GetEnvironmentVariableA", "GetEnvironmentVariableW",
    "ExpandEnvironmentStringsA", "ExpandEnvironmentStringsW",
})

# APIs that compute a path (temp dir, known folder, module path, combination)
# and write the result into a caller-supplied OUT buffer.
_COMPUTED_PATH_APIS: frozenset[str] = frozenset({
    "GetTempPathA", "GetTempPathW",
    "GetTempPath2A", "GetTempPath2W",
    "SHGetFolderPathA", "SHGetFolderPathW",
    "SHGetKnownFolderPath",
    "PathCombineA", "PathCombineW",
    "GetModuleFileNameA", "GetModuleFileNameW",
})

_ALL_COMPUTED_PATH_SOURCES: frozenset[str] = (
    _REGISTRY_READ_APIS | _ENVVAR_READ_APIS | _COMPUTED_PATH_APIS
)

# OUT-parameter index (0-based) for each computed-path source API.
# This is the argument that receives the path bytes.
_COMPUTED_PATH_OUT_ARG_IDX: dict[str, int] = {
    # RegQueryValueEx(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData)
    "RegQueryValueExA": 4, "RegQueryValueExW": 4,
    # RegGetValue(hKey, lpSubKey, lpValue, dwFlags, pvData, pcbData)
    "RegGetValueA": 5, "RegGetValueW": 5,
    # SHGetValue(hKey, pszSubKey, pszValue, pdwType, pvData, pcbData)
    "SHGetValueA": 4, "SHGetValueW": 4,
    # GetEnvironmentVariable(lpName, lpBuffer, nSize)
    "GetEnvironmentVariableA": 1, "GetEnvironmentVariableW": 1,
    # ExpandEnvironmentStrings(lpSrc, lpDst, nSize)
    "ExpandEnvironmentStringsA": 1, "ExpandEnvironmentStringsW": 1,
    # GetTempPath(nBufferLength, lpBuffer)
    "GetTempPathA": 1, "GetTempPathW": 1,
    "GetTempPath2A": 1, "GetTempPath2W": 1,
    # SHGetFolderPath(hwnd, csidl, hToken, dwFlags, pszPath)
    "SHGetFolderPathA": 4, "SHGetFolderPathW": 4,
    # SHGetKnownFolderPath(rfid, dwFlags, hToken, ppszPath) — arg3 is PWSTR*
    "SHGetKnownFolderPath": 3,
    # PathCombine(pszDest, pszDir, pszFile) — dest is arg 0
    "PathCombineA": 0, "PathCombineW": 0,
    # GetModuleFileName(hModule, lpFilename, nSize)
    "GetModuleFileNameA": 1, "GetModuleFileNameW": 1,
}


def _extract_addr_of_slot(func, expr) -> Optional[str]:
    """If `expr` is `&local_var` or an SSA var defined as `&local_var`,
    return str(local_var). Used to identify stack buffers passed as OUT
    params to computed-path APIs and then consumed by load-class APIs.
    """
    if expr is None:
        return None
    op_name = type(expr).__name__
    if "AddressOf" in op_name or "Addr" in op_name:
        slot = getattr(expr, "src", None) or getattr(expr, "var", None)
        if slot is not None:
            return str(slot)
    ssa = ilh.expr_to_ssa_var(expr)
    if ssa is None or func is None:
        return None
    defn = ilh.ssa_def_of(func, ssa)
    if defn is None:
        return None
    src = getattr(defn, "src", None)
    if src is None:
        return None
    src_op = type(src).__name__
    if "AddressOf" in src_op or "Addr" in src_op:
        slot = getattr(src, "src", None) or getattr(src, "var", None)
        if slot is not None:
            return str(slot)
    return None


def _scan_function_for_computed_path_writes(
        bv, func, imports: frozenset) -> dict[str, str]:
    """Scan a function's call instructions for computed-path API calls
    that write a path into a stack buffer via an OUT parameter.

    Returns {str(stack_var): api_name} so that later code can check
    whether a load-API's path arg points to the same stack slot.
    """
    result: dict[str, str] = {}
    ssa_form = ilh._to_ssa_form(func)
    if ssa_form is None:
        return result
    bv_syms = getattr(bv, "get_symbol_at", None)
    if not callable(bv_syms):
        return result
    for inst in (getattr(ssa_form, "instructions", None) or []):
        op_name = type(inst).__name__
        if "Call" not in op_name:
            continue
        dest = getattr(inst, "dest", None)
        if dest is None:
            continue
        cval = getattr(dest, "constant", None)
        if cval is None:
            continue
        try:
            sym = bv_syms(int(cval))
        except Exception:
            continue
        if sym is None:
            continue
        api_name = getattr(sym, "short_name", None) or getattr(sym, "name", "")
        if api_name not in _COMPUTED_PATH_OUT_ARG_IDX or api_name not in imports:
            continue
        out_idx = _COMPUTED_PATH_OUT_ARG_IDX[api_name]
        params = ilh.call_params(inst)
        if out_idx >= len(params):
            continue
        slot = _extract_addr_of_slot(func, params[out_idx])
        if slot is not None:
            result[slot] = api_name
    return result


def find_trusted_path_computed_load(
        bv, *, binary: str, arch: str, platform: str,
        detector: str = "analysis.trusted_path",
) -> list[Finding]:
    """v3 — computed/registry/env-var path detector.

    For every load-class call site, check whether the path argument is a
    stack buffer that was populated by a registry read, env-var expansion,
    or computed-path API in the same function. If so, emit
    `trusted_path_computed_load` HIGH — the path is attacker-influenceable
    via registry writes, environment variables, or other external state.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    relevant_load_apis = [a for a in _LOAD_PATH_ARG_INDEX if a in imports]
    if not relevant_load_apis:
        return findings
    if not (_ALL_COMPUTED_PATH_SOURCES & imports):
        return findings

    meta = CATEGORY_META["trusted_path_computed_load"]
    # Per-function cache: avoid re-scanning the same function multiple times
    # when several load-API call sites live in the same function.
    func_key_to_writes: dict[int, dict[str, str]] = {}
    seen_keys: set[tuple[str, str, int]] = set()

    for api in relevant_load_apis:
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
            fname = (getattr(sf, "name", "")
                     or f"sub_{getattr(sf, 'start', 0):x}")

            # Get or build the computed-path-writes map for this function.
            fstart = int(getattr(sf, "start", 0) or 0)
            if fstart not in func_key_to_writes:
                func_key_to_writes[fstart] = _scan_function_for_computed_path_writes(
                    bv, func, imports,
                )
            writes = func_key_to_writes[fstart]
            if not writes:
                continue

            # Check whether the path arg resolves to a written stack slot.
            path_slot = _extract_addr_of_slot(func, params[path_idx])
            if path_slot is None:
                continue
            source_api = writes.get(path_slot)
            if source_api is None:
                continue

            key = (fname, api, int(call_addr))
            if key in seen_keys:
                continue
            seen_keys.add(key)

            if source_api in _REGISTRY_READ_APIS:
                source_label = "registry read"
            elif source_api in _ENVVAR_READ_APIS:
                source_label = "environment variable"
            else:
                source_label = "computed path function"

            findings.append(Finding(
                id="",
                category="trusted_path_computed_load",
                severity=meta["severity"],
                address=int(call_addr),
                function=fname,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre"]),
                description=(
                    f"{fname}: load API {api}@0x{call_addr:x} consumes a "
                    f"path sourced from {source_label} ({source_api}). "
                    f"The buffer at stack slot '{path_slot}' is populated "
                    f"by {source_api} before being passed to {api} — "
                    f"registry writes / environment manipulation can redirect "
                    f"this load to an attacker-controlled path."
                ),
                evidence=[Evidence(
                    kind="computed_path_to_load_callsite",
                    source=detector,
                    payload=(f"source={source_api} ({source_label}) "
                             f"slot={path_slot!r} "
                             f"load_api={api} call_addr=0x{call_addr:x}"),
                    address=int(call_addr),
                    function=fname,
                )],
                details={
                    "load_api": api,
                    "call_addr": hex(int(call_addr)),
                    "source_api": source_api,
                    "source_type": source_label,
                    "stack_slot": path_slot,
                },
            ))

    return findings


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

    # v2 — literal constant path → load callsite (SSA back-walk).
    v2 = find_trusted_path_xref_to_load(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
    # v3 — computed/registry/env-var path → load callsite (OUT-param scan).
    # Complements v2: fires on runtime-determined paths that have no
    # constant-pointer literal in the SSA def chain.
    v3 = find_trusted_path_computed_load(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
    if v2 or v3:
        # v1 (binary-scope co-presence) adds no information when either
        # per-callsite detector has fired; suppress to avoid duplicate signal.
        return v2 + v3

    return find_trusted_path_loads(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
