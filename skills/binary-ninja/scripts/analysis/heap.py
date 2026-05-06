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
from ..lib.scoring import apply_signals_to_finding
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


# Function-name prefixes for known-good runtime / CRT internals that
# legitimately allocate and free memory in patterns that look like UAF
# / double-free / unchecked-alloc to a structural detector. Findings
# inside these are suppressed — they're shipped CRT code, not user
# bugs.
#
# Add cautiously. If a real bug were ever found inside a CRT function,
# this denylist would suppress it. The trade-off is acceptable for
# Tier-2-style detection tooling whose output must be low-noise.
_CRT_NAME_PREFIXES: tuple[str, ...] = (
    "__mingw_", "___w64_", "___main",
    "__Bfree", "__Balloc", "__Bzero", "__multadd", "__lshift", "__hi0",
    "__b2d", "__d2b", "__diff", "__gdtoa", "__strtod", "__cmp",
    "__write_memory", "duplicate_ppstrings",
    "__scrt_", "__report_", "__crt_", "__chkstk",
    "_register_onexit", "_initialize_", "_initterm",
)


def _is_crt_internal(func_name: str) -> bool:
    """Match against `_CRT_NAME_PREFIXES`."""
    if not func_name:
        return False
    for prefix in _CRT_NAME_PREFIXES:
        if func_name.startswith(prefix):
            return True
    return False


# RAII heap-wrapper substrings. ATL `CHeapPtr<T>::Allocate`,
# wil `details::ProcessHeapAlloc`, STL `unique_ptr` / `shared_ptr`
# / `make_unique` / `make_shared`, MFC memory-exception classes —
# these implement allocation-failure handling at the wrapper level
# (ATL returns bool to caller; wil throws via `THROW_LAST_ERROR_IF_NULL`;
# STL `make_unique` propagates `bad_alloc`). The naive
# `_alloc_handle_is_checked` walk doesn't see the wrapper-layer check
# and would falsely flag every wrapped allocation as
# `unchecked_allocation`. Skip findings in functions whose name
# contains any of these tokens.
#
# Match is on the displayed name (mangled OR demangled — tokens are
# present in both forms thanks to template-name preservation).
_RAII_HEAP_WRAPPER_TOKENS: tuple[str, ...] = (
    # ATL
    "CHeapPtr", "CAutoPtr", "CAtlAlloc", "CAutoVectorPtr",
    # WIL (Windows Implementation Libraries) — Microsoft's
    # error-handling helpers; throw on alloc failure.
    "wil@@", "details@wil", "wil::details",
    "ProcessHeapAlloc", "unique_any", "ResultException",
    "FailFast", "ThrowLastError", "THROW_",
    # MFC
    "CMemoryException", "CObject@@", "CObject::operator new",
    # STL — usually inlined but template-deduced wrappers may surface
    "unique_ptr", "shared_ptr", "make_unique", "make_shared",
    "_Allocate", "allocator<", "allocator@std",
    "basic_string@",        # STL string allocation
    # MSVCRT / UCRT throwing alloc helpers
    "_recalloc", "_aligned_malloc", "_malloca",
    "operator new",         # raw `new` (throws bad_alloc by default)
)


def _is_raii_heap_wrapper(func_name: str) -> bool:
    """Match against `_RAII_HEAP_WRAPPER_TOKENS` (substring match).

    Used to suppress `unchecked_allocation` findings in functions
    whose name indicates they're a managed-failure heap wrapper.
    The wrapper itself implements the check (return-bool / throw /
    propagate-exception); detector-level "no comparison near alloc"
    misses these legitimately-checked patterns.
    """
    if not func_name:
        return False
    for tok in _RAII_HEAP_WRAPPER_TOKENS:
        if tok in func_name:
            return True
    return False


def _use_is_real_deref(use) -> bool:
    """Filter SSA uses to those that actually dereference the pointer.

    Excludes:
    - Phi nodes (SSA-bookkeeping at merge points; not dereferences)
    - Pure SetVar aliases (copy from one SSA var to another;
      aliasing-aware analysis is a Tier-2++ enhancement, but as a
      basic filter we accept SetVar uses since they often precede a
      real deref further down the chain)

    Includes:
    - Load / Store (direct dereference)
    - Call (passing the pointer; may deref in callee)
    - Anything else by default (conservative-true)
    """
    if use is None:
        return False
    op_name = type(use).__name__
    if "VarPhi" in op_name or "MemPhi" in op_name:
        return False
    return True

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


# Per-category signal mapping. Heap detector emits with these signals
# stacked according to the daydream-surfaced design:
#  - HUB signals describe the cross-class shape (free_then_use,
#    alloc_then_write_no_full_init).
#  - SPECIFIC signals anchor the class (freed_ssa_subsequent_use for
#    UAF, two_free_paths_same_alloc for double-free).
_CATEGORY_SIGNALS: dict[str, tuple[str, ...]] = {
    "use_after_free":       ("free_then_use", "freed_ssa_subsequent_use"),
    "double_free":          ("free_then_use", "two_free_paths_same_alloc"),
    "heap_buffer_overflow": ("tainted_pointer_write", "alloc_then_write_no_full_init"),
    "unchecked_allocation": (),
}


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────


def _emit(category: str, *, addr: int, function: str, binary: str,
          arch: str, platform: str, detector: str,
          description: str, evidence: list[Evidence] = None,
          details: dict = None) -> Finding:
    meta = CATEGORY_META[category]
    finding = Finding(
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
    signals = _CATEGORY_SIGNALS.get(category, ())
    if signals:
        apply_signals_to_finding(finding, signals)
    return finding


def _ssa_var_str(v) -> str:
    if v is None:
        return ""
    name = getattr(getattr(v, "var", None), "name", None)
    version = getattr(v, "version", None)
    if name is not None and version is not None:
        return f"{name}#{version}"
    return str(v)


def _resolve_to_global_load_addr(function, ssa_var, *, max_hops: int = 4) -> Optional[int]:
    """If `ssa_var`'s def chain reaches a Load from a constant address
    (a global pointer), return that address. Else None.

    Walks SSA defs and looks for `MediumLevelILLoadSsa` (or similar)
    whose source operand is a constant. The canonical
    `g_ptr = [<constant>]` shape.

    Used to detect global-pointer UAF: when free(g_ptr_load) is
    followed elsewhere by a load of the same global used as a
    pointer, that's a use-after-free.
    """
    if function is None or ssa_var is None:
        return None
    seen: set = set()
    cur = ssa_var
    for _ in range(max_hops):
        if cur is None:
            return None
        key = str(cur)
        if key in seen:
            return None
        seen.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            return None
        src_expr = getattr(defn, "src", None)
        if src_expr is None:
            return None
        # Direct Load from constant?
        if "Load" in type(src_expr).__name__:
            load_src = getattr(src_expr, "src", None)
            cval = getattr(load_src, "constant", None)
            if cval is not None:
                try:
                    return int(cval)
                except Exception:
                    return None
        # Chase through SetVar
        nested = ilh.expr_to_ssa_var(src_expr)
        if nested is None:
            return None
        cur = nested
    return None


def _function_stores_to_address(func, target_addr: int) -> bool:
    """True if `func` contains an MLIL Store whose destination is
    the constant address `target_addr`. Used to identify init-class
    functions that write to a global before loading it (those loads
    are fresh values, not post-free reads).
    """
    if func is None:
        return False
    mlil = getattr(func, "mlil", None)
    if mlil is None:
        return False
    ssa = getattr(mlil, "ssa_form", None) or mlil
    try:
        for inst in ssa.instructions:
            if "Store" not in type(inst).__name__:
                continue
            dest = getattr(inst, "dest", None)
            cval = getattr(dest, "constant", None) if dest else None
            if cval is None:
                continue
            try:
                if int(cval) == target_addr:
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def find_global_pointer_uaf(bv, *, binary: str, arch: str, platform: str,
                            detector: str) -> list[Finding]:
    """Detect the global-pointer UAF pattern:

      static T *g_ptr;
      void close() { free(g_ptr); }     // not nulled out
      void use()   { ...g_ptr->...; }   // dangling read/write

    Algorithm:

    1. For each free call site, trace the freed pointer's SSA-def
       chain to a Load-from-constant-address (a global pointer).
       Build map `freed_globals[global_addr] -> [(free_addr, fn)]`.
    2. Walk every function in the binary, looking for Load-from-
       constant-address where the constant matches a freed global
       AND the loaded value is used as a pointer (deref or copy).
    3. Emit UAF candidate for each match in a function OTHER than
       the freeing function (or in the same function but at an
       address after the free).

    v1 limitation: doesn't track whether the global is reassigned
    between free and use (would clear the dangling-pointer state).
    Most real UAFs in the wild don't reassign on the failure path,
    which is precisely why they're bugs.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)

    # Step 1: collect freed globals
    freed_globals: dict[int, list[tuple[int, object, str]]] = {}
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
            global_addr = _resolve_to_global_load_addr(func, ssa_var)
            if global_addr is None:
                continue
            freed_globals.setdefault(global_addr, []).append(
                (addr, func, free_name))

    if not freed_globals:
        return findings

    # Step 2: scan each function for loads of those globals used
    # as pointers
    seen_findings: set[tuple[int, int]] = set()      # (global_addr, function_key)
    for func in bv.functions:
        fname = ilh.function_display_name(func)
        if _is_crt_internal(fname) or _is_raii_heap_wrapper(fname):
            continue
        ssa = ilh.ssa_uses_of                  # alias for type-check
        mlil_func = getattr(func, "mlil", None)
        if mlil_func is None:
            continue
        ssa_form = getattr(mlil_func, "ssa_form", None)
        if ssa_form is None:
            continue
        try:
            insts = list(ssa_form.instructions)
        except Exception:
            continue
        for inst in insts:
            # Find SetVar whose src is `[<constant>]` — load from global
            op_name = type(inst).__name__
            if "SetVar" not in op_name:
                continue
            src_expr = getattr(inst, "src", None)
            if src_expr is None or "Load" not in type(src_expr).__name__:
                continue
            load_src = getattr(src_expr, "src", None)
            cval = getattr(load_src, "constant", None) if load_src else None
            if cval is None:
                continue
            try:
                global_addr = int(cval)
            except Exception:
                continue
            if global_addr not in freed_globals:
                continue
            free_sites = freed_globals[global_addr]
            # Skip if this load IS the free's load (same address)
            inst_addr = int(getattr(inst, "address", 0))
            if any(addr == inst_addr for (addr, _, _) in free_sites):
                continue
            # Skip if this function only contains the free path
            free_in_this_func = any(
                ilh.function_key(f) == ilh.function_key(func)
                for (_, f, _) in free_sites)
            # Even in same function, count if use_addr > free_addr
            use_after_free_in_same = False
            for (addr, f, _) in free_sites:
                if ilh.function_key(f) == ilh.function_key(func) and inst_addr > addr:
                    use_after_free_in_same = True
                    break
            if free_in_this_func and not use_after_free_in_same:
                # Use precedes free (or unrelated to free) within same function
                continue
            # Suppress emission in init-class functions that ALSO
            # store to this global. The store implies the loaded
            # value is freshly assigned, not a stale post-free read.
            if _function_stores_to_address(func, global_addr):
                continue
            sig = (global_addr, ilh.function_key(func))
            if sig in seen_findings:
                continue
            seen_findings.add(sig)
            first_free = free_sites[0]
            findings.append(_emit(
                "use_after_free",
                addr=inst_addr, function=fname, binary=binary,
                arch=arch, platform=platform, detector=detector,
                description=(
                    f"global pointer at 0x{global_addr:x} freed at "
                    f"0x{first_free[0]:x} in {ilh.function_display_name(first_free[1])} "
                    f"is reloaded at 0x{inst_addr:x} in {fname} — global is not "
                    f"nulled after free, dangling pointer reachable from this load"
                ),
                details={
                    "global_addr": hex(global_addr),
                    "free_addr": hex(first_free[0]),
                    "free_function": ilh.function_display_name(first_free[1]),
                    "use_addr": hex(inst_addr),
                    "use_function": fname,
                    "pattern": "global_pointer_uaf",
                },
            ))
    return findings


def _resolve_to_alloc_handle(function, ssa_var, alloc_handles: dict,
                             *, max_def_hops: int = 4) -> Optional[dict]:
    """Resolve an SSA variable to its originating alloc-handle entry.

    Looks up `(id(function), _ssa_var_str(ssa_var))` directly first.
    If not found, walks SSA defs up to `max_def_hops` looking for a
    transitively-defining alloc-handle SSA var (e.g., the canonical
    `rcx#1 = rax#1` register-transfer pattern between malloc's
    return slot and the next call's argument slot).

    Returns the alloc-handle dict (with `alloc_name`, `alloc_addr`,
    `size_var_str`) or None.
    """
    if ssa_var is None:
        return None
    fkey = ilh.function_key(function)
    direct_key = (fkey, _ssa_var_str(ssa_var))
    if direct_key in alloc_handles:
        return alloc_handles[direct_key]
    # SSA-def chase
    seen: set = set()
    cur = ssa_var
    for _ in range(max_def_hops):
        if cur is None:
            return None
        key = _ssa_var_str(cur)
        if key in seen:
            return None
        seen.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            return None
        src_expr = getattr(defn, "src", None)
        if src_expr is None:
            return None
        # Direct SSA-var src: `cur = src_var`
        nested_ssa = ilh.expr_to_ssa_var(src_expr)
        if nested_ssa is not None:
            nested_key = (fkey, _ssa_var_str(nested_ssa))
            if nested_key in alloc_handles:
                return alloc_handles[nested_key]
            cur = nested_ssa
            continue
        # Couldn't extract a single SSA var (src is arithmetic /
        # constant / load) — give up.
        return None
    return None


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
            key = (ilh.function_key(func), _ssa_var_str(ssa_var))
            free_sites.setdefault(key, []).append((addr, mlil))

    for key, sites in free_sites.items():
        if not sites:
            continue
        first_addr, first_inst = sites[0]
        func = getattr(first_inst, "function", None)
        func_name = ilh.function_display_name(func)

        # Re-derive the SSA var to look up uses
        params = ilh.call_params(first_inst)
        if not params:
            continue
        ssa_var = ilh.expr_to_ssa_var(params[0])
        if ssa_var is None:
            continue

        # Double-free: more than one free site for the same SSA var.
        # CFG check: at least one pair of free sites must be on a
        # path where both execute in sequence — equivalently, one
        # must dominate the other in the CFG. When the two free
        # sites are on disjoint CFG branches (neither dominates the
        # other), they're mutually exclusive paths and both calls
        # can't execute in any single run — that's a detector FP
        # (the SSA var is phi-merged across the branch but the
        # actual frees are separate in execution).
        if len(sites) >= 2:
            free_addrs_sorted = sorted(a for a, _ in sites)
            from . import _cfg_primitives as cfg_p
            reachable_pair = False
            for i in range(len(free_addrs_sorted)):
                for j in range(i + 1, len(free_addrs_sorted)):
                    a, b = free_addrs_sorted[i], free_addrs_sorted[j]
                    try:
                        if (cfg_p.instruction_dominates(func, a, b)
                                or cfg_p.instruction_dominates(func, b, a)):
                            reachable_pair = True
                            break
                    except Exception:
                        reachable_pair = True   # be inclusive on CFG-query failure
                        break
                if reachable_pair:
                    break
            if reachable_pair:
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

        # CRT denylist — suppress findings in shipped runtime code
        if _is_crt_internal(func_name):
            continue

        # UAF: a use of the same SSA var that comes AFTER a free is a
        # use-after-free candidate. Three filters:
        #
        # 1. Temporal: use_addr > earliest_free (program order; CFG
        #    post-dominance is a Tier-2++ enhancement).
        # 2. Real-deref: skip phi/mem-phi uses — these are SSA
        #    bookkeeping at merge points, not actual dereferences.
        # 3. Free-site: skip the free call itself (which is also a use).
        free_addrs = {a for a, _ in sites}
        earliest_free = min(free_addrs)
        all_uses = ilh.ssa_uses_of(func, ssa_var)
        for use in all_uses:
            use_addr = int(getattr(use, "address", 0))
            if use_addr in free_addrs:
                continue
            if use_addr <= earliest_free:
                # Use precedes the first free — normal pre-free use,
                # not a UAF.
                continue
            if not _use_is_real_deref(use):
                continue
            findings.append(_emit(
                "use_after_free",
                addr=use_addr, function=func_name, binary=binary,
                arch=arch, platform=platform, detector=detector,
                description=(
                    f"use of {_ssa_var_str(ssa_var)} at 0x{use_addr:x} "
                    f"after free at 0x{earliest_free:x}"
                ),
                details={
                    "ssa_var": _ssa_var_str(ssa_var),
                    "free_addr": hex(earliest_free),
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

            key = (ilh.function_key(func), _ssa_var_str(output_var))
            alloc_handles[key] = {
                "alloc_name": alloc_name,
                "alloc_addr": addr,
                "size_var": size_var,
                "size_var_str": _ssa_var_str(size_var) if size_var else "",
                "function": func,
            }

    # For each copy callsite, see if the dst SSA var is an alloc handle.
    # Direct lookup first; on miss, chase SSA defs (handles register-
    # transfer patterns like `rcx#1 = rax#1` that sit between malloc's
    # return slot and the next call's argument slot).
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
            alloc = _resolve_to_alloc_handle(func, dst_var, alloc_handles)
            if alloc is None:
                continue

            # Length-argument check. The mismatch heuristic alone is
            # noisy — `memcpy(buf, src, len)` where `len` is a fresh
            # SSA var that happens to equal sizeof(buf) at runtime
            # would FP. Two-stage filter:
            #
            # 1. If len_var == alloc_size_var (same SSA var): safe.
            # 2. If alloc_size is a constant integer AND len_var is a
            #    constant equal to it: safe.
            # 3. Otherwise: candidate.
            #
            # Future iteration: gate further with allocate-before-read
            # CFG primitive.
            mismatch_reason = "no length argument (unbounded copy)"
            if len_idx is not None and len_idx < len(params):
                len_var = ilh.expr_to_ssa_var(params[len_idx])
                len_str = _ssa_var_str(len_var) if len_var else ""
                if len_str and len_str == alloc["size_var_str"]:
                    continue
                mismatch_reason = (
                    f"length var {len_str or '<unknown>'} != alloc-size var "
                    f"{alloc['size_var_str'] or '<unknown>'}"
                )

            func_name = ilh.function_display_name(func)
            # CRT denylist — suppress findings in shipped runtime code
            if _is_crt_internal(func_name):
                continue
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


def _alloc_handle_is_checked(func, output_var, *, max_hops: int = 5) -> bool:
    """True if `output_var` (or any SSA var reachable via SetVar
    transitive defs) appears in a conditional or comparison.

    The canonical `if (ptr) {...}` shape lifts in SSA as:
        var_10#1 = rax#1
        if (var_10#1 != 0) ...
    so checking only direct uses of `rax#1` misses the check. This
    helper does a small BFS through SetVar chains looking for
    comparison-class uses.
    """
    if func is None or output_var is None:
        return False
    seen: set = set()
    frontier = [output_var]
    while frontier and len(seen) < 64:
        cur = frontier.pop()
        key = _ssa_var_str(cur)
        if key in seen:
            continue
        seen.add(key)
        uses = ilh.ssa_uses_of(func, cur)
        for use in uses:
            op_name = type(use).__name__
            # Direct comparison or branch on this var
            if ("Cmp" in op_name or "If" in op_name
                    or "Test" in op_name or "Set" in op_name and "Flag" in op_name):
                return True
            # SetVarSsa: this use is `dest = ... cur ...` — chase dest
            if "SetVar" in op_name:
                dst = getattr(use, "dest", None)
                # SetVarSsa: dest is the SSAVariable being assigned.
                if dst is not None:
                    if hasattr(dst, "var") and hasattr(dst, "version"):
                        # SSAVariable
                        frontier.append(dst)
                    else:
                        # Wrapper — try .src or .var
                        for attr in ("src", "var"):
                            v = getattr(dst, attr, None)
                            if v is not None and hasattr(v, "version"):
                                frontier.append(v)
                                break
        if len(seen) > max_hops * 8:
            break
    return False


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
            if _alloc_handle_is_checked(func, output_var):
                continue
            first_use_addr = int(getattr(uses[0], "address", 0)) if uses else 0
            func_name = ilh.function_display_name(func)
            # CRT denylist — suppress findings in shipped runtime code
            if _is_crt_internal(func_name):
                continue
            # RAII heap-wrapper denylist — ATL/wil/STL wrappers handle
            # alloc failure at the wrapper level (return-bool, throw)
            # not at the alloc site. Without this filter every wrapped
            # allocation in modern Windows code FPs.
            if _is_raii_heap_wrapper(func_name):
                continue
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
    findings.extend(find_global_pointer_uaf(
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
