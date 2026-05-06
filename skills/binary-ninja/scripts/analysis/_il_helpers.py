"""Shared MLIL SSA helpers for analysis modules.

Both `taint.py` and `heap.py` need the same primitives:

- Locate call sites of a named import
- Extract SSA parameter / output variables of a call instruction
- Walk SSA def-use chains
- Resolve the named callee at a call instruction

These wrappers are tolerant of bv quirks (missing MLIL on a function,
empty SSA form, version differences in operand naming) — failures
return empty / None rather than raising.
"""

from __future__ import annotations

from typing import Iterable, Optional

from ..heuristics._base import imports_in


def call_sites_of_import(bv, name: str) -> list[tuple[int, object]]:
    """Return [(call_site_addr, mlil_instruction), ...] for every call to `name`.

    Resolves the IAT addresses of `name`, walks `bv.get_code_refs` for
    each, and looks up the MLIL instruction at the call site.
    """
    out: list[tuple[int, object]] = []
    if bv is None:
        return out
    # Find all symbol addresses for this import
    iat_addrs: list[int] = []
    syms_by_name = {}
    try:
        get_typed = getattr(bv, "get_symbols_of_type", None)
        if callable(get_typed):
            for sym in get_typed("ImportedFunctionSymbol"):
                short = getattr(sym, "short_name", None) or getattr(sym, "name", "")
                if short == name:
                    iat_addrs.append(int(sym.address))
            # MinGW-built PE binaries put their actual IAT entries under
            # `__imp_<name>` ImportAddressSymbol; the bare-named
            # ImportedFunctionSymbol is just a thunk wrapper that often
            # has zero direct code refs. Walk both shapes so the
            # call-site enumeration captures both linker patterns.
            for sym in get_typed("ImportAddressSymbol"):
                short = getattr(sym, "short_name", None) or getattr(sym, "name", "")
                if short == name or short == f"__imp_{name}":
                    iat_addrs.append(int(sym.address))
        # Direct symbol lookup — try both bare name and `__imp_` form
        getter = getattr(bv, "get_symbol_by_raw_name", None)
        if callable(getter):
            for candidate in (name, f"__imp_{name}"):
                sym = getter(candidate)
                if sym is not None and getattr(sym, "address", None) is not None:
                    iat_addrs.append(int(sym.address))
    except Exception:
        pass

    code_ref_getter = getattr(bv, "get_code_refs", None)
    if not callable(code_ref_getter):
        return out

    iat_set: set[int] = set(iat_addrs)
    # Dedupe by MLIL address alone — multiple IAT entries (bare-name +
    # `__imp_`) for the same import resolve to the same call site, so
    # `(addr,)` is the right uniqueness key.
    seen_addrs: set[int] = set()
    for iat in iat_addrs:
        try:
            for ref in code_ref_getter(iat):
                addr = int(getattr(ref, "address", 0))
                if addr == 0:
                    continue
                # Resolve MLIL instruction at this address
                func = getattr(ref, "function", None)
                if func is None:
                    funcs = list(bv.get_functions_containing(addr))
                    func = funcs[0] if funcs else None
                if func is None or getattr(func, "mlil", None) is None:
                    if addr not in seen_addrs:
                        seen_addrs.add(addr)
                        out.append((addr, None))
                    continue

                resolved = False
                try:
                    inst = func.get_low_level_il_at(addr)
                    if inst is not None and hasattr(inst, "mlil"):
                        mlil_inst = inst.mlil
                        if mlil_inst is not None:
                            ssa_form = getattr(mlil_inst, "ssa_form", None)
                            chosen = ssa_form if ssa_form is not None else mlil_inst
                            mlil_addr = int(getattr(chosen, "address", addr))
                            if mlil_addr not in seen_addrs:
                                seen_addrs.add(mlil_addr)
                                out.append((mlil_addr, chosen))
                            resolved = True
                except Exception:
                    pass

                if resolved:
                    continue

                # Fallback: walk the function's MLIL Call instructions
                # and find ones whose dest constant matches the IAT.
                # MinGW thunk-via-IAT patterns put the user call's MLIL
                # address slightly after the LLIL `get_code_refs` site,
                # so the direct `get_low_level_il_at` resolution fails.
                try:
                    mlil_root = func.mlil
                    ssa_root = getattr(mlil_root, "ssa_form", None) or mlil_root
                    for cinst in ssa_root.instructions:
                        op_name = type(cinst).__name__
                        if "Call" not in op_name:
                            continue
                        dest = getattr(cinst, "dest", None)
                        if dest is None:
                            continue
                        cval = getattr(dest, "constant", None)
                        if cval is None:
                            continue
                        if int(cval) not in iat_set:
                            continue
                        mlil_addr = int(getattr(cinst, "address", 0))
                        if mlil_addr in seen_addrs:
                            continue
                        seen_addrs.add(mlil_addr)
                        out.append((mlil_addr, cinst))
                except Exception:
                    pass
        except Exception:
            continue
    return out


def call_instructions_in(func) -> Iterable:
    """Yield MLIL Call-class instructions in `func`."""
    if func is None or getattr(func, "mlil", None) is None:
        return
    mlil = func.mlil
    for block in mlil:
        for inst in block:
            op = getattr(inst, "operation", None)
            op_name = getattr(op, "name", "") if op is not None else ""
            if "CALL" in op_name:
                yield inst


def callee_address_of_call(call_inst) -> Optional[int]:
    """Return the destination address of a Call MLIL instruction, or None."""
    if call_inst is None:
        return None
    dest = getattr(call_inst, "dest", None)
    if dest is None:
        return None
    val = getattr(dest, "constant", None)
    if val is None:
        # Some Binja versions: dest is itself an integer expr
        try:
            val = int(dest)
        except Exception:
            val = None
    return int(val) if val is not None else None


def call_params(call_inst) -> list:
    """Return the list of parameter expressions for a MLIL Call.

    Tolerant of operand-naming differences across Binja versions.
    """
    if call_inst is None:
        return []
    for attr in ("params", "operands_params", "operands"):
        val = getattr(call_inst, attr, None)
        if val is None:
            continue
        # `operands` includes dest + params; filter to lists where applicable
        if attr == "operands":
            try:
                return list(val)[1:]
            except Exception:
                continue
        try:
            return list(val)
        except Exception:
            continue
    return []


def call_output_ssa(call_inst):
    """Return the SSA output variable of a Call instruction, or None.

    Looks at `inst.output` then falls back to `inst.ssa_form.dest`.
    """
    if call_inst is None:
        return None
    out = getattr(call_inst, "output", None)
    if out is not None:
        # MediumLevelILCallSsa typically exposes .output as a list of
        # SSAVariable objects.
        if hasattr(out, "__iter__"):
            try:
                lst = list(out)
                if lst:
                    return lst[0]
            except Exception:
                pass
        return out
    ssa = getattr(call_inst, "ssa_form", None)
    if ssa is None:
        return None
    return getattr(ssa, "dest", None)


def expr_to_ssa_var(expr):
    """Best-effort: extract the SSAVariable an expression refers to.

    For MediumLevelILVarSsa expressions, the variable lives on `.src`.
    For raw SSAVariable, returns it unchanged.
    """
    if expr is None:
        return None
    if hasattr(expr, "src") and hasattr(expr.src, "var"):
        return expr.src
    if hasattr(expr, "var") and hasattr(expr, "version"):
        return expr
    src = getattr(expr, "src", None)
    if src is not None:
        return src
    return None


def _to_ssa_form(func):
    """Resolve `func` (Function | MediumLevelILFunction | SSA-form
    MediumLevelILFunction) to its MLIL SSA-form function.

    Returns None if `func` is None or the SSA form can't be reached.
    """
    if func is None:
        return None
    # Already an SSA-form function?
    if hasattr(func, "get_ssa_var_uses") and hasattr(func, "get_ssa_var_definition"):
        return func
    # MediumLevelILFunction → .ssa_form
    ssa = getattr(func, "ssa_form", None)
    if ssa is not None and hasattr(ssa, "get_ssa_var_uses"):
        return ssa
    # Regular Function → .mlil → .ssa_form
    mlil = getattr(func, "mlil", None)
    if mlil is not None:
        ssa = getattr(mlil, "ssa_form", None)
        if ssa is not None and hasattr(ssa, "get_ssa_var_uses"):
            return ssa
    return None


def function_key(func) -> int:
    """Stable identity for a function across `Function` /
    `MediumLevelILFunction` accesses.

    `id(MediumLevelILFunction)` differs across `inst.function` accesses
    because Binja creates fresh wrapper objects. The function's start
    address is stable.

    Returns 0 if the start address can't be determined.
    """
    if func is None:
        return 0
    # Direct .start (regular Function or some MLIL forms)
    start = getattr(func, "start", None)
    if start is not None:
        try:
            return int(start)
        except Exception:
            pass
    # Source function pointer (MediumLevelILFunction)
    src = getattr(func, "source_function", None)
    if src is not None:
        start = getattr(src, "start", None)
        if start is not None:
            try:
                return int(start)
            except Exception:
                pass
    return 0


def function_display_name(func) -> str:
    """Extract a display name from any of Function / MediumLevelILFunction.

    `MediumLevelILFunction` doesn't have `.name`; its `.source_function`
    points back to the regular Function which does.
    """
    if func is None:
        return ""
    name = getattr(func, "name", None)
    if name:
        return str(name)
    src = getattr(func, "source_function", None)
    if src is not None:
        return str(getattr(src, "name", "") or "")
    return ""


def ssa_uses_of(func, ssa_var) -> list:
    """Wrap `func.mlil.ssa_form.get_ssa_var_uses(ssa_var)` defensively."""
    if ssa_var is None:
        return []
    ssa = _to_ssa_form(func)
    if ssa is None:
        return []
    getter = getattr(ssa, "get_ssa_var_uses", None)
    if not callable(getter):
        return []
    try:
        return list(getter(ssa_var))
    except Exception:
        return []


def ssa_def_of(func, ssa_var):
    """Single-definition lookup for an SSA variable."""
    if ssa_var is None:
        return None
    ssa = _to_ssa_form(func)
    if ssa is None:
        return None
    getter = getattr(ssa, "get_ssa_var_definition", None)
    if not callable(getter):
        return None
    try:
        return getter(ssa_var)
    except Exception:
        return None


def resolves_to_stack_variable(expr, function=None, max_def_hops: int = 3) -> bool:
    """True iff `expr` resolves to a StackVariable in the analysed binary.

    Two paths:

    1. Direct: `expr` already references a stack variable (typed
       `Variable.source_type == StackVariableSourceType` or
       `is_stack_variable == True`).

    2. Indirect: `expr` is an SSA register var (e.g., `rcx#N`) whose
       SSA definition writes the address of a stack variable. We
       walk up to `max_def_hops` SSA-def edges looking for the
       address-of-stack pattern. Function context is required for
       the SSA-def lookup; pass `function` to enable. With no
       function context only the direct path runs.

    Used by the stack-OF detector to gate the SPECIFIC
    `stack_write_exceeds_compile_size` signal: only fire it when the
    write destination is actually a stack-allocated buffer.
    """
    if _expr_contains_stack_var(expr):
        return True
    if function is None:
        return False
    # SSA-def chase: extract the SSA var from `expr`, look up its def,
    # check whether the def's source is an address-of-stack expr.
    ssa_var = expr_to_ssa_var(expr)
    if ssa_var is None:
        return False
    seen: set = set()
    return _ssa_def_resolves_to_stack(function, ssa_var, max_def_hops, seen)


def _ssa_def_resolves_to_stack(function, ssa_var, hops_left: int, seen: set) -> bool:
    if hops_left <= 0 or ssa_var is None:
        return False
    key = str(ssa_var)
    if key in seen:
        return False
    seen.add(key)
    defn = ssa_def_of(function, ssa_var)
    if defn is None:
        return False
    # Common shapes for `dst = &stack_var` or `dst = stack_var_ptr`:
    # - SetVarSsa whose .src is AddressOf / VarSsa pointing to a stack var
    # - SetVarSsa whose .src is another SSA var that itself resolves to stack
    src_expr = getattr(defn, "src", None)
    if src_expr is None:
        return False
    # Direct stack-var contained in src expr
    if _expr_contains_stack_var(src_expr):
        return True
    # AddressOf: `&stack_var` — src.src may be the stack var
    op_name = type(src_expr).__name__
    if "AddressOf" in op_name or "Addr" in op_name:
        target = getattr(src_expr, "src", None) or getattr(src_expr, "var", None)
        if target is not None and _expr_contains_stack_var(target):
            return True
        # Recurse on operands
        for op in getattr(src_expr, "operands", []) or []:
            if _expr_contains_stack_var(op):
                return True
    # Recurse: the src is another SSA var; chase it
    nested_ssa = expr_to_ssa_var(src_expr)
    if nested_ssa is not None:
        if _ssa_def_resolves_to_stack(function, nested_ssa, hops_left - 1, seen):
            return True
    return False


def _is_stack_var(var) -> bool:
    """True iff `var` is a Binja Variable whose source-type is Stack.

    Tolerant of API variations: checks `source_type.name`, falls back
    to `is_stack_variable` predicate, falls back to checking that
    `storage` is a small negative integer (typical stack-frame offset).
    """
    if var is None:
        return False
    stype = getattr(var, "source_type", None)
    stype_name = getattr(stype, "name", "") if stype is not None else ""
    if "Stack" in stype_name:
        return True
    if getattr(var, "is_stack_variable", False):
        return True
    return False


def _expr_contains_stack_var(expr, max_depth: int = 8) -> bool:
    """Recursive helper for `resolves_to_stack_variable`."""
    if expr is None or max_depth <= 0:
        return False
    # Bare Variable leaf (operand of AddressOf / VarField / etc.)
    if hasattr(expr, "source_type") and not hasattr(expr, "operands"):
        if _is_stack_var(expr):
            return True
    # SSA-var wrapper: expr.src is an SSAVariable; its .var is the Variable
    src = getattr(expr, "src", None)
    if src is not None and hasattr(src, "var"):
        if _is_stack_var(getattr(src, "var", None)):
            return True
    # Some MLIL nodes expose .var directly (VarField, VarSplit, etc.)
    if hasattr(expr, "var"):
        v = getattr(expr, "var", None)
        # If `expr.var` is itself a Variable with source_type
        if v is not None and hasattr(v, "source_type"):
            if _is_stack_var(v):
                return True
        # Or it's an SSAVariable with .var
        if v is not None and hasattr(v, "var"):
            if _is_stack_var(getattr(v, "var", None)):
                return True
    # Recurse into operands
    operands = getattr(expr, "operands", None)
    if operands is not None:
        for op in operands:
            if _expr_contains_stack_var(op, max_depth - 1):
                return True
    return False


def function_uses_red_zone(function) -> bool:
    """Heuristic: True iff `function` is a leaf function on x86_64 SysV
    that uses the 128-byte red zone instead of allocating a stack frame.

    The classic red-zone shape: no `sub rsp, N` in the prologue, but
    stores below `rsp` (negative offsets). Compilers emit this for
    leaf functions — those that don't make any calls.

    Detection heuristic for v1:

    1. Function makes no calls (leaf).
    2. Function's stack-adjustment is 0 (no `sub rsp, N`).
    3. Function has at least one variable in the negative-offset range
       (`-128 <= storage < 0`).

    Tolerant of API variation; returns False on Windows binaries
    (which don't use the SysV red zone) and on functions where the
    information isn't recoverable.
    """
    if function is None:
        return False
    # Quick platform filter — Win64 ABI doesn't have a red zone.
    bv = getattr(function, "view", None) or getattr(function, "_view", None)
    if bv is not None:
        plat = str(getattr(bv, "platform", "") or "")
        if "windows" in plat.lower():
            return False
    # Leaf check
    callees = getattr(function, "callees", None)
    if callees is None:
        return False
    try:
        if list(callees):
            return False
    except Exception:
        return False
    # Stack adjust = 0 (no `sub rsp, N`)
    stack_adjust = getattr(function, "stack_adjustment", None)
    if stack_adjust is None:
        # Some Binja versions: function.frame_pointer_offset / .stack_layout
        # If we can't determine, conservative-False.
        return False
    try:
        if int(stack_adjust) != 0:
            return False
    except Exception:
        return False
    # Negative-offset stack vars present?
    stack_vars = getattr(function, "stack_layout", None) or getattr(function, "vars", [])
    try:
        for v in stack_vars:
            storage = getattr(v, "storage", None)
            if storage is None:
                continue
            try:
                so = int(storage)
            except Exception:
                continue
            if -128 <= so < 0:
                return True
    except Exception:
        pass
    return False


def is_sink_call_to(call_inst, sink_names: set[str]) -> Optional[str]:
    """If `call_inst` is a Call to one of `sink_names`, return that name."""
    addr = callee_address_of_call(call_inst)
    if addr is None or call_inst is None:
        return None
    func = getattr(call_inst, "function", None)
    if func is None:
        return None
    bv = getattr(func, "view", None) or getattr(func, "_view", None)
    if bv is None:
        return None
    sym = bv.get_symbol_at(addr)
    if sym is None:
        return None
    name = getattr(sym, "short_name", None) or getattr(sym, "name", "")
    return name if name in sink_names else None
