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
    name = getattr(getattr(v, "var", None), "name", None)
    version = getattr(v, "version", None)
    if name is not None and version is not None:
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
            params = ilh.call_params(mlil)
            if path_idx >= len(params):
                continue
            path_var = ilh.expr_to_ssa_var(params[path_idx])
            if path_var is None:
                continue
            func = getattr(mlil, "function", None)
            fkey = ilh.function_key(func)
            root = _resolve_path_origin(func, path_var)
            if not root:
                continue
            check_sites.setdefault(fkey, []).append((addr, root, sink_name))

    if not check_sites:
        return findings

    # Walk use sites; for each, look up matching check in same function
    for sink_name, (path_idx, use_label) in _USE_SINKS.items():
        if sink_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if path_idx >= len(params):
                continue
            path_var = ilh.expr_to_ssa_var(params[path_idx])
            if path_var is None:
                continue
            func = getattr(mlil, "function", None)
            fkey = ilh.function_key(func)
            checks_in_func = check_sites.get(fkey, [])
            if not checks_in_func:
                continue
            root = _resolve_path_origin(func, path_var)
            if not root:
                continue
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
