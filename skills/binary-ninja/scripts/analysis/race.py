"""TOCTOU / race-condition detection.

Detects the canonical check-then-use pattern across file-system
operations: a check call (`access`, `stat`, `GetFileAttributes`)
verifies a property of a path, then a later use call (`fopen`,
`open`, `CreateFile`, `unlink`, `chmod`) operates on the same path
without re-checking. An attacker swaps the path's target between
the two calls (via symlink, junction, or filesystem race) and the
use operates on a different file than the check approved.

Detection shape (v1):

1. Enumerate check-class call sites (table `_CHECK_SINKS`).
2. Enumerate use-class call sites (table `_USE_SINKS`).
3. For each (check, use) pair in the same function whose path
   arguments resolve to the same SSA value (with up to 3-hop
   def-chasing through register-transfer / SetVar shapes), and
   where the check site precedes the use site in program order,
   emit a `toctou` Finding.

Visited-key state-completeness (per `_DETECTOR_CHECKLIST.md`):

The visited key must encode "has check been seen on this path." For
v1 — which doesn't do CFG-aware path discovery — the implicit key is
"same SSA path-var between check and use sites." A v2 enhancement
would add CFG-path-sensitive analysis: the check might be in one
branch and the use in another that doesn't pass through the check.

Knowledge anchors:
- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — the
  junction-redirect race in the admin → SYSTEM scenario uses this
  primitive class.
- General CWE-367.
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in
from ..lib.scoring import apply_signals_to_finding
from ..output.finding import Evidence, Finding, Severity
from . import _cfg_primitives as cfg
from . import _il_helpers as ilh


# (sink_name, path_arg_idx)
_CHECK_SINKS: dict[str, int] = {
    # POSIX
    "access":            0,
    "stat":              0,
    "lstat":             0,
    "faccessat":         1,        # (dirfd, pathname, mode, flags)
    "fstatat":           1,
    "newfstatat":        1,
    # Windows
    "GetFileAttributesA":   0,
    "GetFileAttributesW":   0,
    "GetFileAttributesExA": 0,
    "GetFileAttributesExW": 0,
    "PathFileExistsA":      0,
    "PathFileExistsW":      0,
    # MSVC libc
    "_access":              0,
    "_waccess":             0,
    "_stat":                0,
    "_wstat":               0,
    # C++ stdlib — std::filesystem::exists is defined in terms of
    # status(); status() is what's actually imported. The path arg
    # is `this`'s sibling reference, MLIL surfaces it as arg 0 of
    # the call.
    "std::filesystem::status":             0,
    "std::filesystem::__cxx11::status":    0,
    "std::filesystem::exists":             0,
}


# (sink_name, path_arg_idx, use_label)
_USE_SINKS: dict[str, tuple[int, str]] = {
    # POSIX file open / file ops
    "fopen":      (0, "fopen"),
    "freopen":    (0, "freopen"),
    "open":       (0, "open"),
    "openat":     (1, "openat"),
    "creat":      (0, "creat"),
    "unlink":     (0, "unlink"),
    "remove":     (0, "remove"),
    "rename":     (0, "rename"),     # path1 — also path2 at idx 1
    "chmod":      (0, "chmod"),
    "chown":      (0, "chown"),
    "lchown":     (0, "lchown"),
    "truncate":   (0, "truncate"),
    "symlink":    (1, "symlink"),    # (target, linkpath)
    "link":       (1, "link"),
    "mkdir":      (0, "mkdir"),
    "rmdir":      (0, "rmdir"),
    # Windows
    "CreateFileA":         (0, "CreateFileA"),
    "CreateFileW":         (0, "CreateFileW"),
    "CreateFile2":         (0, "CreateFile2"),
    "DeleteFileA":         (0, "DeleteFileA"),
    "DeleteFileW":         (0, "DeleteFileW"),
    "MoveFileA":           (0, "MoveFileA"),
    "MoveFileW":           (0, "MoveFileW"),
    "MoveFileExA":         (0, "MoveFileExA"),
    "MoveFileExW":         (0, "MoveFileExW"),
    "CopyFileA":           (1, "CopyFileA"),     # (existing, new) — flag both?
    "CopyFileW":           (1, "CopyFileW"),
    "SetFileAttributesA":  (0, "SetFileAttributesA"),
    "SetFileAttributesW":  (0, "SetFileAttributesW"),
    # C++ stdlib file streams — constructor opens the path.
    # `this` is arg 0, path is arg 1.
    "std::ifstream::ifstream":  (1, "std::ifstream::ifstream"),
    "std::ofstream::ofstream":  (1, "std::ofstream::ofstream"),
    "std::fstream::fstream":    (1, "std::fstream::fstream"),
    "std::ifstream::open":      (1, "std::ifstream::open"),
    "std::ofstream::open":      (1, "std::ofstream::open"),
    "std::fstream::open":       (1, "std::fstream::open"),
}


CATEGORY_META = {
    "toctou": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-367"],
        "mitre": ["T1547"],
        "knowledge_refs": ["[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]"],
    },
}


def _ssa_var_str(v) -> str:
    if v is None:
        return ""
    var_obj = getattr(v, "var", None)
    name = getattr(var_obj, "name", None)
    version = getattr(v, "version", None)
    if name is not None and version is not None:
        # Include the variable's identifier so that two stripped locals
        # with the same Binja-assigned display name (e.g. both named
        # "var_8" at different stack offsets) produce different root
        # keys and do not false-positive match as the same path.
        ident = (getattr(var_obj, "identifier", None)
                 or getattr(var_obj, "index", None))
        if ident is not None:
            return f"{name}${ident}#{version}"
        return f"{name}#{version}"
    return str(v)


def _resolve_path_origin(function, ssa_var, *, max_hops: int = 4) -> Optional[str]:
    """Resolve `ssa_var` to a stable identifier for the path it carries.

    The two SSA vars at a check site and a use site rarely share the
    same SSA version — they're typically separate register copies of
    the same incoming function-argument or local pointer. Walk SSA
    defs back to a "root" form (typically the function-argument SSA
    var or the def site of a `SetVar` from a constant address).
    Return the root SSA var's str, or None.

    Two sites with matching root strs are passing the same logical
    pointer, even if their immediate SSA vars differ.
    """
    if ssa_var is None:
        return None
    cur = ssa_var
    seen: set = set()
    for _ in range(max_hops):
        if cur is None:
            return None
        key = _ssa_var_str(cur)
        if key in seen:
            return key       # cycle — stop and return current root
        seen.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            return key       # no def — likely function param; this is the root
        src = getattr(defn, "src", None)
        if src is None:
            return key
        nested = ilh.expr_to_ssa_var(src)
        if nested is None:
            return key
        cur = nested
    return _ssa_var_str(cur)


def _is_stl_thunk_function(func) -> bool:
    """True iff `func`'s demangled name belongs to the STL / library
    (a function whose body is just `JMP <real_impl>` or a template
    instantiation that delegates). MSVC + libstdc++ both emit these.

    Uses the SYMBOL'S SHORT_NAME (demangled) — checking the raw
    mangled `name` would treat every user C++ function (also
    `_Z`-prefixed under Itanium) as STL.
    """
    sf = getattr(func, "source_function", None) or func
    sym = getattr(sf, "symbol", None)
    sn = (getattr(sym, "short_name", None) if sym else None) or getattr(sf, "name", "") or ""
    return sn.startswith("std::") or sn.startswith("__cxxabi")


def _walk_thunk_to_user_callsites(bv, func, *, max_depth: int = 2):
    """If `func` is an STL thunk, return a list of (caller_func,
    callsite_mlil_inst, ref_addr) for callers of `func`. Walks up
    to `max_depth` levels, stopping when a non-STL caller is reached.
    Used to bridge sink emissions that anchor inside library code
    back to the user-code call site that triggered them.
    """
    out: list = []
    if func is None:
        return out

    def _fn_start(fn):
        # Accept either Function or MediumLevelILFunction; the latter
        # has start via .source_function.
        s = getattr(fn, "start", None)
        if s is not None:
            try:
                return int(s)
            except Exception:
                pass
        src = getattr(fn, "source_function", None)
        return int(getattr(src, "start", 0) or 0) if src is not None else 0

    seen: set = set()
    frontier = [(func, max_depth)]
    while frontier:
        cur_fn, depth = frontier.pop()
        if depth <= 0:
            continue
        start = _fn_start(cur_fn)
        if start == 0:
            continue
        try:
            refs = list(bv.get_code_refs(start) or [])
        except Exception:
            refs = []
        for ref in refs:
            caller = getattr(ref, "function", None)
            if caller is None:
                continue
            fkey = int(getattr(caller, "start", 0) or 0)
            if fkey in seen:
                continue
            seen.add(fkey)
            # Resolve MLIL instruction at the call site.
            ref_addr = int(getattr(ref, "address", 0) or 0)
            mlil = None
            try:
                inst = caller.get_low_level_il_at(ref_addr)
                if inst is not None and hasattr(inst, "mlil"):
                    m = inst.mlil
                    if m is not None:
                        ssa = getattr(m, "ssa_form", None)
                        mlil = ssa if ssa is not None else m
            except Exception:
                mlil = None
            if mlil is not None:
                # Non-STL caller → terminal; STL caller → keep walking
                if _is_stl_thunk_function(caller):
                    frontier.append((caller, depth - 1))
                else:
                    out.append((caller, mlil, ref_addr))
            else:
                # Couldn't resolve MLIL — still recurse if STL caller.
                if _is_stl_thunk_function(caller):
                    frontier.append((caller, depth - 1))
    return out


def _record_check_or_use_site(bv, mlil_inst, *, path_idx, sink_name,
                              sink_label=None, results, kind):
    """Helper: extract path_var + path_root + enclosing function and
    append to the result list. When the enclosing function is an STL
    thunk, also walks up to user-code callers and records synthesized
    sites there (so race-pairing can match across thunk boundaries).
    """
    if mlil_inst is None:
        return
    params = ilh.call_params(mlil_inst)
    if path_idx >= len(params):
        return
    path_var = ilh.expr_to_ssa_var(params[path_idx])
    if path_var is None:
        return
    func = getattr(mlil_inst, "function", None)
    fkey = ilh.function_key(func)
    addr = int(getattr(mlil_inst, "address", 0) or 0)
    root = _resolve_path_origin(func, path_var)
    if root:
        if kind == "check":
            results.setdefault(fkey, []).append((addr, root, sink_name))
        else:  # "use"
            results.setdefault(fkey, []).append(
                (addr, root, sink_name, sink_label, func))
    # If the enclosing function is an STL thunk, walk callers and
    # add synthesized sites at user-code call sites. The root path
    # at the user-code site is derived from THAT call site's args.
    if _is_stl_thunk_function(func):
        for caller, caller_mlil, caller_addr in (
                _walk_thunk_to_user_callsites(bv, func) or []):
            caller_params = ilh.call_params(caller_mlil)
            if path_idx >= len(caller_params):
                continue
            caller_pv = ilh.expr_to_ssa_var(caller_params[path_idx])
            if caller_pv is None:
                continue
            caller_fkey = ilh.function_key(caller)
            caller_root = _resolve_path_origin(caller, caller_pv)
            if not caller_root:
                continue
            if kind == "check":
                results.setdefault(caller_fkey, []).append(
                    (caller_addr, caller_root, sink_name))
            else:
                results.setdefault(caller_fkey, []).append(
                    (caller_addr, caller_root, sink_name, sink_label, caller))


def find_toctou(bv, *, binary: str, arch: str, platform: str,
                detector: str = "analysis.race") -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)

    # Index check sites by function: {func_key: [(addr, path_root, sink_name)]}
    check_sites: dict[int, list[tuple[int, str, str]]] = {}
    for sink_name, path_idx in _CHECK_SINKS.items():
        if sink_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            _record_check_or_use_site(
                bv, mlil, path_idx=path_idx, sink_name=sink_name,
                results=check_sites, kind="check",
            )

    if not check_sites:
        return findings

    # Index use sites by function — same structure as check_sites but
    # the entries also carry the use_label and resolved function.
    # When the use-site call is inside an STL thunk, also walk callers
    # to record synthesized use sites in user code.
    use_sites: dict[int, list] = {}
    for sink_name, (path_idx, use_label) in _USE_SINKS.items():
        if sink_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            _record_check_or_use_site(
                bv, mlil, path_idx=path_idx, sink_name=sink_name,
                sink_label=use_label, results=use_sites, kind="use",
            )

    # Pair check and use sites in the same function.
    for fkey, uses in use_sites.items():
        checks_in_func = check_sites.get(fkey, [])
        if not checks_in_func:
            continue
        for (addr, root, sink_name, use_label, func) in uses:
            # Match: same path-root + check dominates use in CFG.
            # v1 used linear program order (check_addr < use_addr).
            # v2 (Run 19) requires CFG dominance: the check's basic
            # block must dominate the use's basic block, otherwise a
            # check in branch A and a use in branch B that doesn't
            # pass through A would FP. Linear-program-order is
            # sufficient for the common case (same-block check-then-
            # use); CFG dominance generalises to multi-branch
            # functions like utilman.exe's `StartList::HandleFirstTime`.
            for check_addr, check_root, check_name in checks_in_func:
                if check_root != root:
                    continue
                if check_addr >= addr:
                    continue       # use must come after check (program order)
                try:
                    if not cfg.instruction_dominates(func, check_addr, addr):
                        continue   # CFG-disjoint paths — not a TOCTOU pair
                except Exception:
                    pass            # CFG query failed; fall through (be inclusive)
                func_name = ilh.function_display_name(func)
                meta = CATEGORY_META["toctou"]
                finding = Finding(
                    id="",
                    category="toctou",
                    severity=meta["severity"],
                    address=addr,
                    function=func_name,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=(
                        f"check ({check_name}@0x{check_addr:x}) followed by use "
                        f"({use_label}@0x{addr:x}) on the same path — symlink / "
                        f"junction race window between check and use lets an "
                        f"attacker redirect the use to a different target than "
                        f"the check approved"
                    ),
                    evidence=[Evidence(
                        kind="check_then_use_pair",
                        source=detector,
                        payload=(f"{check_name}@0x{check_addr:x} -> "
                                 f"{use_label}@0x{addr:x} path_root={root}"),
                        address=addr,
                        function=func_name,
                    )],
                    details={
                        "check_name": check_name,
                        "check_addr": hex(check_addr),
                        "use_name": use_label,
                        "use_addr": hex(addr),
                        "path_root": root,
                    },
                )
                apply_signals_to_finding(finding, [
                    "check_then_use_split_by_attacker_window",  # SPECIFIC
                ])
                findings.append(finding)

    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.race") -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    return find_toctou(bv, binary=binary, arch=arch, platform=platform, detector=detector)
