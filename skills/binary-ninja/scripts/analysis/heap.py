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
  argument in ≥ 2 free callsites, flag double-free.  Also detects
  cross-function struct-field aliasing: callee frees (*param).field;
  caller also frees the same field — a classic cleanup-path double-free.

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
    - Return / Ret / TailCall — when a function returns the freed
      pointer, that IS technically "use after free" but it's the
      MSVC C++ ABI for the scalar-deleting destructor
      (`??_E*` mangled functions): `delete this; return this;`.
      The caller is contractually responsible for not touching the
      returned pointer, so emitting a UAF here is FP noise.
      (Empirically: combase.dll produced 660 UAF findings, all in
      this shape, with free-to-use deltas of exactly 19 or 32 bytes
      — function epilogue territory.)

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
    # Return-value uses: the function returns the freed pointer.
    # Matches MSVC `Ret`, `TailCall`, `Jump`-to-thunk patterns plus
    # the generic IL `Return` instruction.
    if "Ret" in op_name or "TailCall" in op_name:
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


def _load_to_base_offset(load_expr):
    """Decompose a Load MLIL expression into (base_ssa_var, field_offset).

    Handles Load(var), Load(var + const), Load(var - const).
    Returns None if the expression doesn't match these shapes.
    """
    src = getattr(load_expr, "src", None)
    if src is None:
        return None
    src_op = type(src).__name__
    direct = ilh.expr_to_ssa_var(src)
    if direct is not None:
        return (direct, 0)
    if "Add" in src_op or "Sub" in src_op:
        left = getattr(src, "left", None)
        right = getattr(src, "right", None)
        sign = -1 if "Sub" in src_op else 1
        left_ssa = ilh.expr_to_ssa_var(left)
        if left_ssa is not None:
            cval = getattr(right, "constant", None)
            if cval is not None:
                return (left_ssa, sign * int(cval))
        if "Add" in src_op:
            right_ssa = ilh.expr_to_ssa_var(right)
            if right_ssa is not None:
                cval = getattr(left, "constant", None)
                if cval is not None:
                    return (right_ssa, int(cval))
    return None


def _extract_load_base_offset(expr, func=None, max_hops: int = 2):
    """Extract (base_ssa, field_offset) from a free()-argument expression.

    Path 1 — direct Load:  free(Load(ptr + offset))
    Path 2 — named field:  free(field_var) where field_var is defined as
              Load(ptr + offset).  Binary Ninja lifts struct fields to named
              MLIL variables when type information is available; walking SSA
              defs up to max_hops steps finds the backing Load.
    """
    if expr is None:
        return None
    if "Load" in type(expr).__name__:
        return _load_to_base_offset(expr)
    if func is None:
        return None
    ssa_var = ilh.expr_to_ssa_var(expr)
    if ssa_var is None:
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
        defn = ilh.ssa_def_of(func, cur)
        if defn is None:
            return None
        src = getattr(defn, "src", None)
        if src is None:
            return None
        if "Load" in type(src).__name__:
            return _load_to_base_offset(src)
        nested = ilh.expr_to_ssa_var(src)
        if nested is not None:
            cur = nested
            continue
        return None
    return None


def _resolve_to_param_idx(func, ssa_var, param_vars: list, max_hops: int = 3) -> int:
    """Return 0-based parameter index if ssa_var (or its SSA-def chain) came
    from a function parameter.  Returns -1 on no match.
    """
    if ssa_var is None or not param_vars:
        return -1

    def _direct(sv):
        underlying = getattr(sv, "var", None)
        if underlying is None:
            return -1
        ident = getattr(underlying, "identifier", None)
        for i, pv in enumerate(param_vars):
            if ident is not None and ident == getattr(pv, "identifier", None):
                return i
        return -1

    idx = _direct(ssa_var)
    if idx >= 0:
        return idx
    seen: set = set()
    cur = ssa_var
    for _ in range(max_hops):
        if cur is None:
            return -1
        key = str(cur)
        if key in seen:
            return -1
        seen.add(key)
        defn = ilh.ssa_def_of(func, cur)
        if defn is None:
            return -1
        src = getattr(defn, "src", None)
        if src is None:
            return -1
        nested = ilh.expr_to_ssa_var(src)
        if nested is None:
            return -1
        idx = _direct(nested)
        if idx >= 0:
            return idx
        cur = nested
    return -1


def _ptr_root(func, ssa_var, max_hops: int = 4) -> Optional[tuple]:
    """Return a stable (kind, identity) pair representing the root of a
    pointer expression — used to correlate a callee arg with a subsequent
    free in the caller even when SSA versions differ.

    Returns:
      ('stack', stack_var_id)  — pointer came from AddressOf(stack_var)
      ('reg',   var_id)        — pointer is a register/local var (fallback)
    """
    if ssa_var is None:
        return None
    var = getattr(ssa_var, "var", None)
    if var is not None:
        ident = getattr(var, "identifier", None)
        if ident is not None and ilh._is_stack_var(var):
            return ("stack", int(ident))
    # Walk SSA def chain for AddressOf(stack_var)
    seen: set = set()
    cur = ssa_var
    for _ in range(max_hops):
        if cur is None:
            break
        key = str(cur)
        if key in seen:
            break
        seen.add(key)
        defn = ilh.ssa_def_of(func, cur)
        if defn is None:
            break
        src = getattr(defn, "src", None)
        if src is None:
            break
        op = type(src).__name__
        if "AddressOf" in op or ("Addr" in op and "Load" not in op):
            sv = getattr(src, "src", None) or getattr(src, "var", None)
            if sv is not None and ilh._is_stack_var(sv):
                stack_ident = getattr(sv, "identifier", None)
                if stack_ident is not None:
                    return ("stack", int(stack_ident))
        nested = ilh.expr_to_ssa_var(src)
        if nested is None:
            break
        cur = nested
    # Fallback: use var identifier (handles same-register, different-version)
    if var is not None:
        ident = getattr(var, "identifier", None)
        if ident is not None:
            return ("reg", int(ident))
    return None


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
    # as pointers. Aggregate emissions per (global, free_site) pair —
    # a single freed global loaded from N other functions is ONE
    # binary-level fact ("this global is freed and re-loaded"), not
    # N separate UAFs. Empirically, smart-pointer Release patterns
    # (?InternalRelease, ?Release, ??_E*) free a singleton's value
    # that's then loaded from hundreds of methods; each load is
    # protected by the singleton's own re-init guard, not a true UAF.
    # Aggregated emission keeps the signal while collapsing the volume.
    aggregated: dict[tuple[int, int], dict] = {}     # (global_addr, free_addr) -> dict
    seen_findings: set[tuple[int, int]] = set()      # (global_addr, function_key)

    # Smart-pointer Release patterns that almost always free a
    # singleton/cache slot, never a UAF in the caller. These are
    # binary-scope `freeing functions`; if the only free site for a
    # global is in one of these, the global_pointer_uaf detector is
    # likely producing pattern-noise. We still emit ONE aggregated
    # finding so the operator can see the binary-level fact, just
    # not 645 of them.
    SMART_PTR_RELEASE_PREFIXES = (
        "?InternalRelease", "?Release", "??_E", "??_G", "??1",
        "?ResetMember", "?Detach", "?Cleanup",
    )

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
            agg_key = (global_addr, first_free[0])
            entry = aggregated.setdefault(agg_key, {
                "global_addr": global_addr,
                "free_addr": first_free[0],
                "free_function": ilh.function_display_name(first_free[1]),
                "use_sites": [],
            })
            entry["use_sites"].append({
                "address": hex(inst_addr),
                "function": fname,
            })

    # Emit one finding per (global, free_site) pair.
    for (global_addr, free_addr), entry in aggregated.items():
        free_fn_name = entry["free_function"]
        # Detect smart-pointer-Release-style freers; severity goes
        # MEDIUM instead of HIGH because these are almost never real
        # UAFs (they're singleton/cache re-init patterns).
        is_smart_release = any(
            free_fn_name.startswith(p) for p in SMART_PTR_RELEASE_PREFIXES
        )
        use_count = len(entry["use_sites"])
        # Anchor at the first use site for address localisation.
        anchor = entry["use_sites"][0]
        try:
            anchor_addr = int(anchor["address"], 16)
        except Exception:
            anchor_addr = 0
        findings.append(_emit(
            "use_after_free",
            addr=anchor_addr,
            function=anchor["function"],
            binary=binary, arch=arch, platform=platform, detector=detector,
            description=(
                f"global pointer at 0x{global_addr:x} freed at "
                f"0x{free_addr:x} in {free_fn_name} is loaded from "
                f"{use_count} other function(s)"
                + (" — freer matches smart-pointer Release shape "
                   "(singleton re-init likely, not exploitable UAF)"
                   if is_smart_release else
                   " — global is not nulled after free, dangling "
                   "pointer reachable from these loads")
            ),
            details={
                "global_addr": hex(global_addr),
                "free_addr": hex(free_addr),
                "free_function": free_fn_name,
                "use_site_count": use_count,
                "use_sites_sample": entry["use_sites"][:8],
                "pattern": "global_pointer_uaf",
                "smart_pointer_release_pattern": is_smart_release,
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
        # use-after-free candidate. Four filters:
        #
        # 1. Temporal: use_addr > earliest_free (program order; CFG
        #    post-dominance is a Tier-2++ enhancement).
        # 2. Real-deref: skip phi/mem-phi uses — these are SSA
        #    bookkeeping at merge points, not actual dereferences.
        # 3. Free-site: skip the free call itself (which is also a use).
        # 4. Function-epilogue: skip uses within ~64 bytes of the free
        #    AND located in the function's tail third. Empirically
        #    these are register-shuffle / return-value-pass-through
        #    instructions (`mov rax, rcx; ret` after `delete this`).
        #    This is the MSVC C++ ABI for the deleting-destructor
        #    family (??_E*, ??_G*) and for any cleanup method that
        #    frees and then returns. The "use" the detector sees is
        #    the epilogue moving the now-freed pointer to the return
        #    register; the caller's contract is that they don't
        #    dereference the returned value.
        free_addrs = {a for a, _ in sites}
        earliest_free = min(free_addrs)
        all_uses = ilh.ssa_uses_of(func, ssa_var)
        # Function bounds for the epilogue filter.
        try:
            sf = getattr(func, "source_function", None) or func
            fn_start = int(getattr(sf, "start", 0) or 0)
            # Use the highest basic-block end as the function end —
            # cheap approximation.
            fn_end = max(
                (int(getattr(b, "end", 0) or 0)
                 for b in (getattr(sf, "basic_blocks", []) or [])),
                default=fn_start
            )
        except Exception:
            fn_start, fn_end = 0, 0
        fn_size = max(0, fn_end - fn_start)
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
            # Epilogue gate: very close to free AND in the tail third
            # of the function.
            if fn_size > 0 and (use_addr - earliest_free) <= 64:
                position_in_fn = use_addr - fn_start
                if position_in_fn >= int(fn_size * 0.66):
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


def find_struct_field_double_free(bv, *, binary: str, arch: str, platform: str,
                                   detector: str) -> list[Finding]:
    """Detect double-free via struct-field aliasing across function boundaries.

    Pattern:
      void callee(struct *p) { free(p->field); }
      void caller()          {
          struct s; ...
          callee(&s);
          free(s.field);   // ← double-free
      }

    Algorithm:
      Phase 1 — collect every free(Load(param_N + offset)) site across all
                functions; build callee_frees map.
                Also build fn_free_sites per-function for Phase 3.
      Phase 2 — for each tracked callee, enumerate its code refs (call sites);
                extract the Nth argument from the call instruction and resolve
                it to a 'root' (stack-var identity via AddressOf walk or var id).
      Phase 3 — check caller's free sites for matching (root, field_offset);
                if found, emit double_free.
    """
    findings: list[Finding] = []
    imports = imports_in(bv)
    if not any(fn in imports for fn in FREE_FUNCTIONS):
        return findings

    # callee_frees[callee_start] = [(param_idx, field_offset, callee_free_addr, callee_name)]
    callee_frees: dict[int, list] = {}
    # fn_free_sites[fn_start] = [(base_ssa, field_offset, free_addr, func_ref)]
    fn_free_sites: dict[int, list] = {}

    for free_name in FREE_FUNCTIONS:
        if free_name not in imports:
            continue
        for free_addr, mlil_inst in ilh.call_sites_of_import(bv, free_name):
            if mlil_inst is None:
                continue
            params_list = ilh.call_params(mlil_inst)
            if not params_list:
                continue
            func = getattr(mlil_inst, "function", None)
            if func is None:
                continue
            fn_start = ilh.function_key(func)
            fn_name = ilh.function_display_name(func)
            if _is_crt_internal(fn_name):
                continue
            freed_arg = params_list[0]
            field = _extract_load_base_offset(freed_arg, func)
            if field is None:
                continue
            (base_ssa, fld_offset) = field
            fn_free_sites.setdefault(fn_start, []).append(
                (base_ssa, fld_offset, free_addr, func)
            )
            # Check if base_ssa traces to a function parameter
            fn_src = getattr(func, "source_function", None) or func
            param_vars = list(getattr(fn_src, "parameter_vars", None) or [])
            param_idx = _resolve_to_param_idx(func, base_ssa, param_vars)
            if param_idx < 0:
                continue
            callee_frees.setdefault(fn_start, []).append(
                (param_idx, fld_offset, free_addr, fn_name)
            )

    if not callee_frees:
        return findings

    seen_sigs: set = set()

    for callee_start, param_free_list in callee_frees.items():
        try:
            refs = list(bv.get_code_refs(callee_start))
        except Exception:
            continue

        for ref in refs:
            caller_addr = int(getattr(ref, "address", 0))
            if caller_addr == 0:
                continue
            caller_fns = bv.get_functions_containing(caller_addr)
            if not caller_fns:
                continue
            caller_fn = caller_fns[0]
            caller_start = ilh.function_key(caller_fn)
            caller_name = ilh.function_display_name(caller_fn)
            if _is_crt_internal(caller_name):
                continue
            # Skip if caller has no free sites to correlate
            caller_free_sites = fn_free_sites.get(caller_start)
            if not caller_free_sites:
                continue

            # Locate the MLIL call instruction at caller_addr
            caller_mlil = getattr(caller_fn, "mlil", None)
            if caller_mlil is None:
                continue
            caller_ssa = getattr(caller_mlil, "ssa_form", None) or caller_mlil
            call_inst = None
            try:
                gi = getattr(caller_ssa, "get_instruction_at", None)
                if callable(gi):
                    call_inst = gi(caller_addr)
            except Exception:
                pass
            if call_inst is None:
                try:
                    for inst in caller_ssa.instructions:
                        if int(getattr(inst, "address", -1)) == caller_addr:
                            call_inst = inst
                            break
                except Exception:
                    pass
            if call_inst is None:
                continue

            call_params_list = ilh.call_params(call_inst)
            call_func_ref = getattr(call_inst, "function", None) or caller_ssa

            for (param_idx, field_offset, callee_free_addr, callee_fn_name) in param_free_list:
                if param_idx >= len(call_params_list):
                    continue
                arg_expr = call_params_list[param_idx]
                arg_ssa = ilh.expr_to_ssa_var(arg_expr)
                if arg_ssa is None:
                    continue
                arg_root = _ptr_root(call_func_ref, arg_ssa)
                if arg_root is None:
                    continue

                for (free_base_ssa, free_offset, local_free_addr, free_func_ref) in caller_free_sites:
                    if free_offset != field_offset:
                        continue
                    free_root = _ptr_root(free_func_ref, free_base_ssa)
                    if free_root is None or free_root != arg_root:
                        continue
                    sig = (caller_start, callee_start, field_offset, local_free_addr)
                    if sig in seen_sigs:
                        continue
                    seen_sigs.add(sig)
                    findings.append(_emit(
                        "double_free",
                        addr=local_free_addr,
                        function=caller_name,
                        binary=binary, arch=arch, platform=platform,
                        detector=detector,
                        description=(
                            f"{callee_fn_name}() frees struct field at offset "
                            f"{field_offset} through its parameter; "
                            f"{caller_name}() also frees the same field at "
                            f"0x{local_free_addr:x} — struct-field aliasing"
                        ),
                        details={
                            "pattern": "struct_field_aliasing",
                            "callee": callee_fn_name,
                            "field_offset": field_offset,
                            "callee_call_site": hex(caller_addr),
                            "callee_free_addr": hex(callee_free_addr),
                            "second_free_addr": hex(local_free_addr),
                        },
                    ))
    return findings


def _infer_allocation_type(bv, output_var):
    """Return the pointed-to struct type of an alloc SSA return variable, or None.

    Checks the type of `output_var.var` in Binja's type system. If it's a
    pointer to a struct, returns the struct type. If unresolved, returns None.
    """
    if bv is None or output_var is None:
        return None
    # output_var is an SSAVariable. Underlying Variable has .type.
    var = getattr(output_var, "var", None)
    if var is None:
        return None
    ty = getattr(var, "type", None)
    if ty is None:
        return None
    # Pointer type: dereference to get the target struct type.
    # Binja's PointerType has .target; StructureType has .members.
    # Walk through at most two layers of pointers.
    for _ in range(2):
        target = getattr(ty, "target", None)
        if target is None:
            break
        ty = target
    members = getattr(ty, "members", None)
    if members is not None:
        return ty
    return None


def _enrich_with_struct_pointer_field(bv, finding, output_var,
                                       copy_len_expr=None) -> None:
    """Annotate a heap_buffer_overflow Finding with struct pointer-field info.

    Sets finding.details['struct_has_pointer_field'] to:
      True  — Binja resolved the type and found at least one pointer-typed field
      False — Binja resolved the type but found no pointer fields
      None  — type is unknown (Binja has no type info for this alloc site)

    When True, also sets finding.details['pointer_field_offsets'] with the
    byte offsets of each pointer-typed member.

    If copy_len_expr is a MLIL constant expression, also sets
    finding.details['overflow_size'] to its integer value. This annotation
    feeds the composition graph size-constraint demotion check:
      heap_buffer_overflow → arbitrary_write (size_constraint_detail_key)
    """
    if finding is None:
        return
    # Populate overflow_size if the copy-length is a statically-known constant.
    if copy_len_expr is not None:
        const_val = getattr(copy_len_expr, "constant", None)
        if const_val is not None:
            try:
                finding.details["overflow_size"] = int(const_val)
            except (TypeError, ValueError):
                pass
    struct_type = _infer_allocation_type(bv, output_var)
    if struct_type is None:
        finding.details["struct_has_pointer_field"] = None
        return
    # Check each member for pointer type.
    members = getattr(struct_type, "members", []) or []
    pointer_offsets = []
    for m in members:
        member_type = getattr(m, "type", None)
        if member_type is None:
            continue
        # PointerType: has a .target attribute with a non-None value
        if getattr(member_type, "target", None) is not None:
            offset = getattr(m, "offset", None)
            if offset is not None:
                pointer_offsets.append(int(offset))
    has_ptr = len(pointer_offsets) > 0
    finding.details["struct_has_pointer_field"] = has_ptr
    if has_ptr:
        finding.details["pointer_field_offsets"] = pointer_offsets


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
                "output_var": output_var,
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
            len_expr = None
            if len_idx is not None and len_idx < len(params):
                len_expr = params[len_idx]
                len_var = ilh.expr_to_ssa_var(len_expr)
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
            finding = _emit(
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
            )
            _enrich_with_struct_pointer_field(bv, finding, alloc.get("output_var"),
                                               copy_len_expr=len_expr)
            findings.append(finding)

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
    findings.extend(find_struct_field_double_free(
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
