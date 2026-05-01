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
        # Also direct symbol lookup
        getter = getattr(bv, "get_symbol_by_raw_name", None)
        if callable(getter):
            sym = getter(name)
            if sym is not None and getattr(sym, "address", None) is not None:
                iat_addrs.append(int(sym.address))
    except Exception:
        pass

    code_ref_getter = getattr(bv, "get_code_refs", None)
    if not callable(code_ref_getter):
        return out

    seen: set[int] = set()
    for iat in iat_addrs:
        try:
            for ref in code_ref_getter(iat):
                addr = int(getattr(ref, "address", 0))
                if addr == 0 or addr in seen:
                    continue
                seen.add(addr)
                # Resolve MLIL instruction at this address
                func = getattr(ref, "function", None)
                if func is None:
                    funcs = list(bv.get_functions_containing(addr))
                    func = funcs[0] if funcs else None
                if func is None or getattr(func, "mlil", None) is None:
                    out.append((addr, None))
                    continue
                try:
                    inst = func.get_low_level_il_at(addr)
                    if inst is not None and hasattr(inst, "mlil"):
                        out.append((addr, inst.mlil))
                        continue
                except Exception:
                    pass
                out.append((addr, None))
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


def ssa_uses_of(func, ssa_var) -> list:
    """Wrap `func.mlil.ssa_form.get_ssa_var_uses(ssa_var)` defensively."""
    if func is None or ssa_var is None:
        return []
    mlil = getattr(func, "mlil", None)
    if mlil is None:
        return []
    ssa = getattr(mlil, "ssa_form", None)
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
    if func is None or ssa_var is None:
        return None
    mlil = getattr(func, "mlil", None)
    if mlil is None:
        return None
    ssa = getattr(mlil, "ssa_form", None)
    if ssa is None:
        return None
    getter = getattr(ssa, "get_ssa_var_definition", None)
    if not callable(getter):
        return None
    try:
        return getter(ssa_var)
    except Exception:
        return None


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
