"""Heap-pattern analysis — UAF, double-free, heap-OF, unchecked alloc.

Replaces the legacy `heap_analysis.py` baseline. Detection sources:

- Allocator import set from `heuristics/imports.py:SINKS` filtered by
  `sink_class == "alloc_size"` (malloc / calloc / realloc /
  HeapAlloc / VirtualAlloc / operator new).
- Free import set: `free`, `HeapFree`, `RtlFreeHeap`,
  `operator delete`, `operator delete[]`, `delete`.

Algorithm (per pattern):

- **UAF**: For each free callsite, take the SSA variable of the freed
  pointer. Enumerate all uses of that exact SSA var. Any use whose
  address differs from the free site is a UAF candidate (same SSA
  version means no intervening reassignment).

- **Double-free**: If an SSA variable appears as the freed-pointer
  argument in ≥ 2 free callsites, flag double-free.

- **Heap-OF**: For each malloc-class callsite, the SSA output is the
  alloc handle. If a subsequent memcpy/memmove/strcpy uses that
  handle (or downstream version) as `dst` AND the length argument
  is not the same SSA var as the alloc-size argument, flag heap-OF.
  Phase-1 caveat: not all allocations carry a constant size; the
  alloc-vs-copy mismatch heuristic produces FPs we'll filter in 1+.

- **Unchecked alloc**: For each alloc callsite, if the immediate next
  use of the returned pointer is *not* a comparison against zero,
  flag null-deref candidate.

Limitations (Phase 1):
- Pointer aliasing handled only via SSA versioning (q = p; free(p);
  use(q) — q is a different SSA version and is not detected).
- Loops can produce FPs / FNs around back-edges.
- v1 does not yet consume `heuristics/injection.py:HEAP_GROOMING`
  for chain-candidate annotation; Phase 1+ will.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..heuristics import imports as heur_imports
from ..heuristics._base import imports_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh
from . import mitigations as mitigations_mod


# ─────────────────────────────────────────────────────────────────
# Symbol tables — driven by heuristics/imports.py
# ─────────────────────────────────────────────────────────────────


ALLOC_FUNCTIONS: dict[str, int] = {
    name: idx for (name, idx, klass) in heur_imports.SINKS
    if klass == "alloc_size"
}

FREE_FUNCTIONS: set[str] = {
    "free", "HeapFree", "RtlFreeHeap", "VirtualFree",
    "operator delete", "operator delete[]",
    "_free_dbg",
}

COPY_FUNCTIONS: dict[str, tuple[int, int, Optional[int]]] = {
    # name → (dst_arg, src_arg, len_arg or None)
    "memcpy":      (0, 1, 2),
    "memmove":     (0, 1, 2),
    "memset":      (0, 1, 2),
    "strcpy":      (0, 1, None),
    "strncpy":     (0, 1, 2),
    "strcat":      (0, 1, None),
    "strncat":     (0, 1, 2),
    "wcscpy":      (0, 1, None),
    "wcsncpy":     (0, 1, 2),
}


# ─────────────────────────────────────────────────────────────────
# Knowledge anchors per finding category
# ─────────────────────────────────────────────────────────────────


CATEGORY_META: dict[str, dict] = {
    "use_after_free": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-416"],
        "mitre": ["T1203"],
        "knowledge_refs": ["[[Memory/Knowledge/wnapi_heap_internals]]"],
    },
    "double_free": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-415"],
        "mitre": ["T1203"],
        "knowledge_refs": ["[[Memory/Knowledge/wnapi_heap_internals]]"],
    },
    "heap_buffer_overflow": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-122"],
        "mitre": ["T1203"],
        "knowledge_refs": ["[[Memory/Knowledge/wnapi_heap_internals]]"],
    },
    "unchecked_allocation": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-690"],
        "mitre": [],
        "knowledge_refs": [],
    },
}


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────


def _emit(category: str, *, addr: int, function: str, binary: str,
          arch: str, platform: str, detector: str,
          description: str, evidence: list[Evidence] = None,
          details: dict = None) -> Finding:
    meta = CATEGORY_META[category]
    return Finding(
        id="",
        category=category,
        severity=meta["severity"],
        address=addr,
        function=function,
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta["knowledge_refs"]),
        cwe=list(meta["cwe"]),
        mitre_attack=list(meta["mitre"]),
        description=description,
        evidence=evidence or [],
        details=details or {},
    )


def _ssa_var_str(v) -> str:
    if v is None:
        return ""
    name = getattr(getattr(v, "var", None), "name", None)
    version = getattr(v, "version", None)
    if name is not None and version is not None:
        return f"{name}#{version}"
    return str(v)


# ─────────────────────────────────────────────────────────────────
# Pattern detectors
# ─────────────────────────────────────────────────────────────────


def find_uaf_and_double_free(bv, *, binary: str, arch: str, platform: str,
                             detector: str) -> list[Finding]:
    findings: list[Finding] = []
    imports = imports_in(bv)

    # Map SSA-var-key → list of (free_site_addr, function)
    free_sites: dict[tuple[int, str], list[tuple[int, object]]] = {}

    for free_name in FREE_FUNCTIONS:
        if free_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, free_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if not params:
                continue
            ssa_var = ilh.expr_to_ssa_var(params[0])
            if ssa_var is None:
                continue
            func = getattr(mlil, "function", None)
            key = (id(func), _ssa_var_str(ssa_var))
            free_sites.setdefault(key, []).append((addr, mlil))

    for key, sites in free_sites.items():
        if not sites:
            continue
        first_addr, first_inst = sites[0]
        func = getattr(first_inst, "function", None)
        func_name = getattr(func, "name", "") if func else ""

        # Re-derive the SSA var to look up uses
        params = ilh.call_params(first_inst)
        if not params:
            continue
        ssa_var = ilh.expr_to_ssa_var(params[0])
        if ssa_var is None:
            continue

        # Double-free: more than one free site for the same SSA var
        if len(sites) >= 2:
            findings.append(_emit(
                "double_free",
                addr=sites[1][0], function=func_name, binary=binary,
                arch=arch, platform=platform, detector=detector,
                description=(
                    f"two free sites on same SSA variable "
                    f"{_ssa_var_str(ssa_var)}: 0x{sites[0][0]:x} and 0x{sites[1][0]:x}"
                ),
                details={
                    "ssa_var": _ssa_var_str(ssa_var),
                    "free_sites": [hex(a) for a, _ in sites],
                },
            ))

        # UAF: any use of the same SSA var that isn't one of the free
        # sites is a use-after-free candidate.
        free_addrs = {a for a, _ in sites}
        all_uses = ilh.ssa_uses_of(func, ssa_var)
        for use in all_uses:
            use_addr = int(getattr(use, "address", 0))
            if use_addr in free_addrs:
                continue
            findings.append(_emit(
                "use_after_free",
                addr=use_addr, function=func_name, binary=binary,
                arch=arch, platform=platform, detector=detector,
                description=(
                    f"use of {_ssa_var_str(ssa_var)} at 0x{use_addr:x} "
                    f"after free at 0x{first_addr:x}"
                ),
                details={
                    "ssa_var": _ssa_var_str(ssa_var),
                    "free_addr": hex(first_addr),
                    "use_addr": hex(use_addr),
                },
            ))

    return findings


def find_heap_overflow(bv, *, binary: str, arch: str, platform: str,
                      detector: str) -> list[Finding]:
    findings: list[Finding] = []
    imports = imports_in(bv)

    # Build alloc-handle SSA-var registry: key (function_id, ssa_var_str) → alloc info
    alloc_handles: dict[tuple[int, str], dict] = {}

    for alloc_name in ALLOC_FUNCTIONS:
        if alloc_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, alloc_name):
            if mlil is None:
                continue
            output_var = ilh.call_output_ssa(mlil)
            if output_var is None:
                continue
            func = getattr(mlil, "function", None)
            params = ilh.call_params(mlil)
            size_arg_idx = ALLOC_FUNCTIONS[alloc_name]
            size_var = None
            if params and size_arg_idx < len(params):
                size_var = ilh.expr_to_ssa_var(params[size_arg_idx])

            key = (id(func), _ssa_var_str(output_var))
            alloc_handles[key] = {
                "alloc_name": alloc_name,
                "alloc_addr": addr,
                "size_var": size_var,
                "size_var_str": _ssa_var_str(size_var) if size_var else "",
                "function": func,
            }

    # For each copy callsite, see if the dst SSA var is an alloc handle
    for copy_name, (dst_idx, _src_idx, len_idx) in COPY_FUNCTIONS.items():
        if copy_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, copy_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if dst_idx >= len(params):
                continue
            dst_var = ilh.expr_to_ssa_var(params[dst_idx])
            if dst_var is None:
                continue
            func = getattr(mlil, "function", None)
            key = (id(func), _ssa_var_str(dst_var))
            alloc = alloc_handles.get(key)
            if alloc is None:
                continue

            # Length-argument check
            mismatch_reason = "no length argument (unbounded copy)"
            if len_idx is not None and len_idx < len(params):
                len_var = ilh.expr_to_ssa_var(params[len_idx])
                len_str = _ssa_var_str(len_var) if len_var else ""
                if len_str and len_str == alloc["size_var_str"]:
                    # length and alloc size are the same SSA var → safe-ish
                    continue
                mismatch_reason = (
                    f"length var {len_str or '<unknown>'} != alloc-size var "
                    f"{alloc['size_var_str'] or '<unknown>'}"
                )

            func_name = getattr(func, "name", "") if func else ""
            findings.append(_emit(
                "heap_buffer_overflow",
                addr=addr, function=func_name, binary=binary,
                arch=arch, platform=platform, detector=detector,
                description=(
                    f"{copy_name} into allocation from {alloc['alloc_name']} "
                    f"at 0x{alloc['alloc_addr']:x} — {mismatch_reason}"
                ),
                details={
                    "alloc_name": alloc["alloc_name"],
                    "alloc_addr": hex(alloc["alloc_addr"]),
                    "alloc_size_var": alloc["size_var_str"],
                    "copy_name": copy_name,
                    "copy_addr": hex(addr),
                },
            ))

    return findings


def find_unchecked_alloc(bv, *, binary: str, arch: str, platform: str,
                        detector: str) -> list[Finding]:
    findings: list[Finding] = []
    imports = imports_in(bv)

    for alloc_name in ALLOC_FUNCTIONS:
        if alloc_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, alloc_name):
            if mlil is None:
                continue
            output_var = ilh.call_output_ssa(mlil)
            if output_var is None:
                continue
            func = getattr(mlil, "function", None)
            uses = ilh.ssa_uses_of(func, output_var)
            if not uses:
                continue
            # If any use is a comparison against constant 0, treat as
            # checked. Otherwise flag the first non-comparison use.
            checked = False
            for use in uses:
                op_name = getattr(getattr(use, "operation", None), "name", "")
                if "CMP" in op_name or "CONST" in op_name:
                    checked = True
                    break
                # Also: equality test with 0 in HLIL appears as MLIL_IF
                # branching on a comparison; harder to detect tersely.
            if checked:
                continue
            first_use_addr = int(getattr(uses[0], "address", 0)) if uses else 0
            func_name = getattr(func, "name", "") if func else ""
            findings.append(_emit(
                "unchecked_allocation",
                addr=first_use_addr, function=func_name, binary=binary,
                arch=arch, platform=platform, detector=detector,
                description=(
                    f"{alloc_name} return at 0x{addr:x} used at 0x{first_use_addr:x} "
                    f"with no apparent null-check"
                ),
                details={
                    "alloc_name": alloc_name,
                    "alloc_addr": hex(addr),
                    "first_use_addr": hex(first_use_addr),
                },
            ))

    return findings


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            score_against_mitigations: bool = True,
            detector: str = "analysis.heap") -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    findings: list[Finding] = []
    findings.extend(find_uaf_and_double_free(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    findings.extend(find_heap_overflow(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    findings.extend(find_unchecked_alloc(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))

    if score_against_mitigations and findings and binary:
        try:
            profile = mitigations_mod.extract_mitigations(binary, bv=bv)
            mitigations_mod.score_findings(findings, profile)
        except Exception:
            pass

    return findings
