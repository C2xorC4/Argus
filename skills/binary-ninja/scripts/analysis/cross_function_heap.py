"""Cross-function / class-aware heap analysis.

Covers three structural shapes that single-function heap.py misses:

  - **Cross-function double-free (C)** — function F passes a pointer
    to function G; G calls `free(arg->field)`; F then calls
    `free(local->field)` on the same field of the same local.

  - **Shallow-copy double-free (C++)** — class C has a destructor
    that calls `operator delete(this->ptr_member)`. The class lacks
    an explicit copy-ctor symbol (compiler-generated shallow copy
    shares the raw pointer). The destructor is invoked 2+ times in
    a single function path. Both destructors hit the same heap
    allocation.

  - **Cross-method use-after-free (C++)** — method A calls
    `operator delete(this->field)` WITHOUT a subsequent store of
    0/null to that field. Method B (same class) loads `this->field`
    and dereferences. The two methods can be invoked in sequence by
    a caller — the typical Manager-Resource lifecycle bug.

All three shapes are recognisable from MLIL SSA without full inter-
procedural taint. The detector emits per-class / per-callsite
findings into the existing `double_free`, `use_after_free`
categories.

Knowledge: `[[Memory/Knowledge/wnapi_heap_internals]]`,
`[[Memory/Knowledge/argus_detector_design_principles]]`
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh


CATEGORY_META = {
    "double_free": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-415"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/wnapi_heap_internals]]",
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "use_after_free": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-416"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/wnapi_heap_internals]]",
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "heap_buffer_overflow": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-122"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/wnapi_heap_internals]]",
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
}


_DELETE_CALLEES: frozenset[str] = frozenset({
    "operator delete", "operator delete[]",
    "free", "_free", "__free",
})


# Unbounded / under-bounded buffer copies. arg-index of the size
# operand maps to `_arg_size_index`. When the dst arg traces to a
# `this->field` load AND the size operand is non-constant, the
# call is a candidate heap-buffer-overflow in a class method.
_COPY_INTO_BUFFER_SINKS: dict[str, int] = {
    "memcpy":    2,
    "memmove":   2,
    "strncpy":   2,
    "strncat":   2,
    "wcsncpy":   2,
    "lstrcpyn":  2,
    "lstrcpynA": 2,
    "lstrcpynW": 2,
    "memcpy_s":  2,
    # Unbounded family — even more dangerous; no size operand at all.
    "strcpy":    None,
    "strcat":    None,
    "wcscpy":    None,
    "lstrcpy":   None,
    "lstrcpyA":  None,
    "lstrcpyW":  None,
}


def _ssa_id(ssa_var) -> str:
    """Stable short-form identity for an SSA variable: `name#version`.
    `str(SSAVariable)` returns a verbose `<SSAVariable: name version N>`
    which doesn't match seed-form keys. Normalise."""
    if ssa_var is None:
        return ""
    name = getattr(getattr(ssa_var, "var", None), "name", None)
    version = getattr(ssa_var, "version", None)
    if name is not None and version is not None:
        return f"{name}#{version}"
    return str(ssa_var)


def _is_delete_call(bv, call_inst) -> bool:
    """True iff `call_inst` calls a free/delete-class function."""
    dest = getattr(call_inst, "dest", None)
    if dest is None:
        return False
    cval = getattr(dest, "constant", None)
    if cval is None:
        return False
    sym = bv.get_symbol_at(int(cval))
    if sym is None:
        return False
    sn = getattr(sym, "short_name", None) or getattr(sym, "name", None) or ""
    return sn in _DELETE_CALLEES


def _function_callees_by_name(bv, fn) -> set[str]:
    """Return {short_name} of every function called from `fn`."""
    out: set[str] = set()
    for ca in (getattr(fn, "callee_addresses", []) or []):
        try:
            tf = bv.get_function_at(int(ca))
        except Exception:
            tf = None
        if tf is None:
            continue
        sym = getattr(tf, "symbol", None)
        sn = (getattr(sym, "short_name", None) if sym else None) or getattr(tf, "name", "")
        if sn:
            out.add(sn)
    return out


def _extract_field_offset_from_load(expr) -> Optional[int]:
    """If `expr` is a Load like `[ptr + N].q`, return N. Else None."""
    if expr is None:
        return None
    op_name = type(expr).__name__
    if "Load" not in op_name:
        return None
    src = getattr(expr, "src", None)
    if src is None:
        return None
    # Add( base, const ) — direct offset
    if "Add" in type(src).__name__:
        left = getattr(src, "left", None)
        right = getattr(src, "right", None)
        for cand in (right, left):
            if cand is None:
                continue
            cv = getattr(cand, "constant", None)
            if cv is not None:
                try:
                    return int(cv)
                except Exception:
                    pass
    # Bare [ptr] = offset 0
    sv = ilh.expr_to_ssa_var(src)
    if sv is not None:
        return 0
    return None


def _expr_field_load_of_arg(expr, arg_ssa_set) -> Optional[int]:
    """If `expr` is a Load like `[arg + offset]` where arg is in
    `arg_ssa_set`, return the offset. Else None.

    Handles two MLIL Load shapes:
      - `MediumLevelILLoadSsa` — generic Load. The address is a
        sub-expression that may be an Add(base, const) or a bare
        base var (offset 0).
      - `MediumLevelILLoadStructSsa` — typed Load. The offset is
        an integer attribute `.offset` on the Load itself, and
        `.src` is the bare base var.
    """
    if expr is None:
        return None
    op_name = type(expr).__name__
    if "Load" not in op_name:
        return None
    # Typed struct Load — offset is on the instruction itself.
    struct_off = getattr(expr, "offset", None)
    if struct_off is not None and isinstance(struct_off, int):
        base = getattr(expr, "src", None)
        sv = ilh.expr_to_ssa_var(base) if base is not None else None
        if sv is not None and _ssa_id(sv) in arg_ssa_set:
            return int(struct_off)
    src = getattr(expr, "src", None)
    if src is None:
        return None
    # Direct: [arg] (offset 0)
    sv = ilh.expr_to_ssa_var(src)
    if sv is not None and _ssa_id(sv) in arg_ssa_set:
        return 0
    # Add( arg, const )
    if "Add" in type(src).__name__:
        operands = (getattr(src, "left", None), getattr(src, "right", None))
        base_var = None
        offset = None
        for op in operands:
            if op is None:
                continue
            sv = ilh.expr_to_ssa_var(op)
            if sv is not None and _ssa_id(sv) in arg_ssa_set:
                base_var = sv
                continue
            cv = getattr(op, "constant", None)
            if cv is not None:
                try:
                    offset = int(cv)
                except Exception:
                    pass
        if base_var is not None and offset is not None:
            return offset
    return None


def _ssa_field_writes_by_arg(function, arg_ssa_set) -> set[int]:
    """Return the set of field offsets `N` for which there's a
    Store `[arg + N].* = 0` (null-out) in `function`. arg_ssa_set
    is the set of SSA-var string identities representing `this` /
    `arg` family variables.
    """
    out: set[int] = set()
    if function is None:
        return out
    mlil = getattr(function, "mlil", None) or function
    ssa = getattr(mlil, "ssa_form", None) or mlil
    for inst in (getattr(ssa, "instructions", []) or []):
        if "Store" not in type(inst).__name__:
            continue
        dest = getattr(inst, "dest", None)
        src = getattr(inst, "src", None)
        if dest is None or src is None:
            continue
        # Check store value is constant zero
        cv = getattr(src, "constant", None)
        if cv is None:
            # could be wrapped
            val = getattr(src, "value", None)
            if val is None:
                continue
            cv = getattr(val, "value", None)
        try:
            if cv is None or int(cv) != 0:
                continue
        except Exception:
            continue
        # Check dest is [arg + N]
        if "Add" not in type(dest).__name__:
            # Bare [arg] — offset 0
            sv = ilh.expr_to_ssa_var(dest)
            if sv is not None and _ssa_id(sv) in arg_ssa_set:
                out.add(0)
            continue
        left = getattr(dest, "left", None)
        right = getattr(dest, "right", None)
        base_var = None
        offset = None
        for op in (left, right):
            if op is None:
                continue
            sv = ilh.expr_to_ssa_var(op)
            if sv is not None and _ssa_id(sv) in arg_ssa_set:
                base_var = sv
                continue
            v = getattr(op, "constant", None)
            if v is not None:
                try:
                    offset = int(v)
                except Exception:
                    pass
        if base_var is not None and offset is not None:
            out.add(offset)
    return out


def _arg0_ssa_family(function) -> set[str]:
    """Return the set of SSA-var string identities that represent
    the function's first argument (`this` for member methods, or
    the lone pointer arg for `void f(T*)`). The set includes the
    raw arg var plus any SSA vars transitively defined as a copy
    of it (fixed-point closure over SetVarSsa def chains).
    """
    out: set[str] = set()
    if function is None:
        return out
    mlil = getattr(function, "mlil", None) or function
    ssa = getattr(mlil, "ssa_form", None) or mlil

    # Seed with the parameter SSA variants. Binja names the first
    # param `this` for C++ methods, `arg1` (or similar) for free
    # functions, and the local copy frequently surfaces as
    # `arg_8` (frame-relative).
    src_fn = getattr(function, "source_function", None) or function
    fn_params = list(getattr(src_fn, "parameter_vars", None) or [])
    if fn_params:
        first = fn_params[0]
        first_name = getattr(first, "name", "") or ""
        if first_name:
            out.add(f"{first_name}#0")
            out.add(f"{first_name}#1")
    # Common defaults across Binja versions.
    out.update({"this#0", "this#1", "arg1#0", "arg1#1"})

    # Fixed-point: any SSA var defined as a copy of something in
    # `out` joins `out`. Iterate until no change.
    changed = True
    iterations = 0
    while changed and iterations < 8:
        changed = False
        iterations += 1
        for inst in (getattr(ssa, "instructions", []) or []):
            if "SetVar" not in type(inst).__name__:
                continue
            src = getattr(inst, "src", None)
            if src is None:
                continue
            src_var = ilh.expr_to_ssa_var(src)
            if src_var is None:
                continue
            if _ssa_id(src_var) not in out:
                continue
            dst = getattr(inst, "dest", None)
            if dst is None:
                continue
            key = _ssa_id(dst)
            if key not in out:
                out.add(key)
                changed = True
    return out


# ─────────────────────────────────────────────────────────────────
# (1) Cross-method UAF — delete-without-null + load on same field
# ─────────────────────────────────────────────────────────────────


def _classify_class_methods(bv):
    """Group function symbols by class name. Returns
    {class_name: [(method_name, function)]}.
    """
    classes: dict[str, list[tuple[str, object]]] = {}
    for fn in (bv.functions or []):
        sym = getattr(fn, "symbol", None)
        sn = (getattr(sym, "short_name", None) if sym else None) or getattr(fn, "name", "")
        if not sn or "::" not in sn:
            continue
        if sn.startswith("std::") or sn.startswith("__cxxabi") or sn.startswith("_TLS_"):
            continue
        cls, _, mth = sn.rpartition("::")
        if not cls or cls.startswith("std::"):
            continue
        classes.setdefault(cls, []).append((mth, fn))
    return classes


def _method_deletes_field_without_null(bv, fn) -> set[int]:
    """Return {offset, ...} for fields the method deletes via
    `operator delete(this->field)` AND does NOT subsequently null
    via `this->field = 0` before return.
    """
    if fn is None:
        return set()
    mlil = getattr(fn, "mlil", None) or fn
    ssa = getattr(mlil, "ssa_form", None) or mlil
    arg_family = _arg0_ssa_family(fn)
    if not arg_family:
        return set()

    deletes: set[int] = set()
    null_writes = _ssa_field_writes_by_arg(fn, arg_family)
    for inst in (getattr(ssa, "instructions", []) or []):
        if "Call" not in type(inst).__name__:
            continue
        if not _is_delete_call(bv, inst):
            continue
        params = ilh.call_params(inst)
        if not params:
            continue
        offset = _resolve_load_offset_for_arg(ssa, params[0], arg_family)
        if offset is None:
            continue
        deletes.add(int(offset))
    # Subtract fields that were nulled.
    return deletes - null_writes


def _resolve_load_offset_for_arg(ssa, expr, arg_family,
                                 *, max_hops: int = 6) -> Optional[int]:
    """Walk back from `expr` through SSA SetVar copy chains until
    reaching a Load whose base is in `arg_family`. Returns the field
    offset of that Load, or None if the chain doesn't terminate at a
    qualifying Load within `max_hops`.
    """
    if expr is None:
        return None
    # Direct: expr is the Load.
    direct = _expr_field_load_of_arg(expr, arg_family)
    if direct is not None:
        return direct
    sv = ilh.expr_to_ssa_var(expr)
    if sv is None:
        return None
    seen: set = set()
    cur = sv
    for _ in range(max_hops):
        if cur is None:
            return None
        key = _ssa_id(cur)
        if key in seen:
            return None
        seen.add(key)
        defn = ilh.ssa_def_of(ssa, cur)
        if defn is None:
            return None
        src = getattr(defn, "src", None)
        if src is None:
            return None
        # If src is a Load, try to extract the offset.
        if "Load" in type(src).__name__:
            return _expr_field_load_of_arg(src, arg_family)
        # Otherwise keep walking through SetVar copies.
        nxt = ilh.expr_to_ssa_var(src)
        if nxt is None:
            return None
        cur = nxt
    return None


def _method_loads_field(bv, fn) -> set[int]:
    """Return {offset, ...} for fields the method loads from
    `this->field` and then dereferences via a Call."""
    if fn is None:
        return set()
    mlil = getattr(fn, "mlil", None) or fn
    ssa = getattr(mlil, "ssa_form", None) or mlil
    arg_family = _arg0_ssa_family(fn)
    if not arg_family:
        return set()

    # Loaded field offsets (records as ssa-var → field-offset).
    loaded: dict[str, int] = {}
    for inst in (getattr(ssa, "instructions", []) or []):
        if "SetVar" not in type(inst).__name__:
            continue
        src = getattr(inst, "src", None)
        if src is None:
            continue
        offset = _expr_field_load_of_arg(src, arg_family)
        if offset is None:
            continue
        dst = getattr(inst, "dest", None)
        if dst is None:
            continue
        loaded[_ssa_id(dst)] = int(offset)
    if not loaded:
        return set()

    # Fixed-point closure: any SSA var defined as a copy of a
    # `loaded` var inherits the same field offset.
    changed = True
    iterations = 0
    while changed and iterations < 8:
        changed = False
        iterations += 1
        for inst in (getattr(ssa, "instructions", []) or []):
            if "SetVar" not in type(inst).__name__:
                continue
            src = getattr(inst, "src", None)
            if src is None:
                continue
            src_var = ilh.expr_to_ssa_var(src)
            if src_var is None:
                continue
            src_id = _ssa_id(src_var)
            if src_id not in loaded:
                continue
            dst = getattr(inst, "dest", None)
            if dst is None:
                continue
            dst_id = _ssa_id(dst)
            if dst_id not in loaded:
                loaded[dst_id] = loaded[src_id]
                changed = True

    # Any Call whose first arg is one of `loaded` SSA vars → that
    # field was used as a `this` pointer for a method call → UAF.
    used_offsets: set[int] = set()
    for inst in (getattr(ssa, "instructions", []) or []):
        if "Call" not in type(inst).__name__:
            continue
        params = ilh.call_params(inst)
        if not params:
            continue
        sv = ilh.expr_to_ssa_var(params[0])
        if sv is None:
            continue
        if _ssa_id(sv) in loaded:
            used_offsets.add(loaded[_ssa_id(sv)])
    return used_offsets


def find_cross_method_uaf(bv, *, binary: str, arch: str, platform: str,
                          detector: str = "analysis.cross_function_heap",
                          ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    classes = _classify_class_methods(bv)
    if not classes:
        return findings
    meta = CATEGORY_META["use_after_free"]
    for cls, methods in classes.items():
        # Compute per-method delete-without-null and load-and-use sets.
        method_deletes: dict[str, tuple[set[int], object]] = {}
        method_loads: dict[str, tuple[set[int], object]] = {}
        for mname, fn in methods:
            d = _method_deletes_field_without_null(bv, fn)
            if d:
                method_deletes[mname] = (d, fn)
            l = _method_loads_field(bv, fn)
            if l:
                method_loads[mname] = (l, fn)
        # Pair: shared offsets between a delete-method and a load-method.
        for dname, (d_offsets, d_fn) in method_deletes.items():
            for lname, (l_offsets, l_fn) in method_loads.items():
                if dname == lname:
                    continue
                shared = d_offsets & l_offsets
                if not shared:
                    continue
                offset = sorted(shared)[0]
                sf = getattr(l_fn, "source_function", None) or l_fn
                fname = getattr(sf, "name", "") or f"sub_{getattr(sf, 'start', 0):x}"
                findings.append(Finding(
                    id="",
                    category="use_after_free",
                    severity=meta["severity"],
                    address=int(getattr(l_fn, "start", 0)),
                    function=fname,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=(
                        f"{cls}::{dname} calls operator delete on "
                        f"`this->[+0x{offset:x}]` and does NOT null the "
                        f"field after free. {cls}::{lname} loads the "
                        f"same field and invokes a method through it — "
                        f"cross-method use-after-free."
                    ),
                    evidence=[Evidence(
                        kind="cross_method_delete_then_use",
                        source=detector,
                        payload=(f"class={cls} delete_method={dname} "
                                 f"use_method={lname} field_offset=0x{offset:x}"),
                        address=int(getattr(l_fn, "start", 0)),
                        function=fname,
                    )],
                    details={
                        "class_name": cls,
                        "delete_method": dname,
                        "use_method": lname,
                        "field_offset": hex(offset),
                    },
                ))
    return findings


# ─────────────────────────────────────────────────────────────────
# (2) Shallow-copy double-free — destructor deletes `this->field`,
#     no copy-ctor declared, 2+ destructor calls in a caller path.
# ─────────────────────────────────────────────────────────────────


def _is_destructor(method_name: str) -> bool:
    return method_name.startswith("~")


def _class_has_explicit_copy_ctor(bv, cls: str, methods) -> bool:
    """True iff the class has an explicit copy-constructor function
    (`Class::Class(Class const&)` — typically demangled by Binja as
    `Class::Class`). The destructor uniquely identifies the ctor
    family; we check for a method whose mangled name encodes a
    const-ref parameter to the same class. Heuristic only.
    """
    short_class = cls.rsplit("::", 1)[-1]
    # Look for any *::ClassName-named function whose mangled raw name
    # encodes a `const ClassName&` parameter.
    for mname, fn in methods:
        if mname != short_class:
            continue
        raw = getattr(fn, "name", "") or ""
        # Itanium: `_ZN<ns>...C1ERKS_` indicates ctor taking const ref to self.
        # MSVC: `??0ClassName@@QEAA@AEBV0@@Z` similarly.
        if "RKS" in raw or "AEBV0" in raw or "AEBU0" in raw:
            return True
    return False


def find_shallow_copy_double_free(bv, *, binary: str, arch: str,
                                  platform: str,
                                  detector: str = "analysis.cross_function_heap",
                                  ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    classes = _classify_class_methods(bv)
    if not classes:
        return findings
    meta = CATEGORY_META["double_free"]
    for cls, methods in classes.items():
        # Find destructor(s) that delete a `this->field`.
        dtor_field_targets: list[tuple[str, object, set[int]]] = []
        for mname, fn in methods:
            if not _is_destructor(mname):
                continue
            deletes_unguarded = _method_deletes_field_without_null(bv, fn)
            # Also include "deletes WITH guard" — for shallow-copy
            # double-free, the issue isn't no-null; it's that the
            # SAME pointer is deleted twice. So include all deletes.
            deletes_all: set[int] = set()
            mlil = getattr(fn, "mlil", None) or fn
            ssa = getattr(mlil, "ssa_form", None) or mlil
            arg_family = _arg0_ssa_family(fn)
            for inst in (getattr(ssa, "instructions", []) or []):
                if "Call" not in type(inst).__name__:
                    continue
                if not _is_delete_call(bv, inst):
                    continue
                params = ilh.call_params(inst)
                if not params:
                    continue
                off = _resolve_load_offset_for_arg(ssa, params[0], arg_family)
                if off is not None:
                    deletes_all.add(int(off))
            if deletes_all:
                dtor_field_targets.append((mname, fn, deletes_all))
        if not dtor_field_targets:
            continue
        # Heuristic: class must lack an explicit copy ctor.
        if _class_has_explicit_copy_ctor(bv, cls, methods):
            continue
        # Find a function (not within this class's methods) that
        # calls the destructor 2+ times.
        for mname, dtor_fn, fields in dtor_field_targets:
            try:
                refs = list(bv.get_code_refs(int(getattr(dtor_fn, "start", 0))) or [])
            except Exception:
                refs = []
            callers_count: dict[int, list[int]] = {}
            for ref in refs:
                caller = getattr(ref, "function", None)
                if caller is None:
                    continue
                fkey = int(getattr(caller, "start", 0) or 0)
                callers_count.setdefault(fkey, []).append(int(getattr(ref, "address", 0) or 0))
            for fkey, addrs in callers_count.items():
                if len(addrs) < 2:
                    continue
                caller_fn = bv.get_function_at(fkey)
                if caller_fn is None:
                    continue
                csn = (getattr(getattr(caller_fn, "symbol", None), "short_name", None)
                       or getattr(caller_fn, "name", ""))
                anchor = sorted(addrs)[1]
                # Anchor on the destructor itself — it's the bug
                # site (the Rule-of-Three violation lives there).
                # `csn` (caller name) is recorded in evidence/details.
                dtor_addr = int(getattr(dtor_fn, "start", 0))
                dtor_fullname = f"{cls}::{mname}"
                findings.append(Finding(
                    id="",
                    category="double_free",
                    severity=meta["severity"],
                    address=dtor_addr,
                    function=dtor_fullname,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=(
                        f"{csn}: destructor {cls}::{mname} invoked "
                        f"{len(addrs)} times. The destructor calls "
                        f"operator delete on `this->[+0x{sorted(fields)[0]:x}]` "
                        f"and {cls} declares no explicit copy "
                        f"constructor — compiler-generated shallow "
                        f"copy gives two objects sharing the same raw "
                        f"pointer, and both destructors free it."
                    ),
                    evidence=[Evidence(
                        kind="shallow_copy_double_destruct",
                        source=detector,
                        payload=(f"class={cls} dtor={mname} "
                                 f"call_count={len(addrs)} "
                                 f"deleted_offset={hex(sorted(fields)[0])}"),
                        address=int(anchor),
                        function=csn,
                    )],
                    details={
                        "class_name": cls,
                        "destructor": mname,
                        "destructor_call_count": len(addrs),
                        "deleted_field_offsets": [hex(o) for o in sorted(fields)],
                    },
                ))
    return findings


# ─────────────────────────────────────────────────────────────────
# (3) Cross-function double-free (C) — cleanup_fn(&obj); free(obj.field);
# ─────────────────────────────────────────────────────────────────


def _function_frees_arg_field(bv, fn) -> set[int]:
    """Return {offset, ...} for arg-fields the function frees via
    `free(arg->field)`.
    """
    if fn is None:
        return set()
    arg_family = _arg0_ssa_family(fn)
    if not arg_family:
        return set()
    mlil = getattr(fn, "mlil", None) or fn
    ssa = getattr(mlil, "ssa_form", None) or mlil
    out: set[int] = set()
    for inst in (getattr(ssa, "instructions", []) or []):
        if "Call" not in type(inst).__name__:
            continue
        if not _is_delete_call(bv, inst):
            continue
        params = ilh.call_params(inst)
        if not params:
            continue
        off = _resolve_load_offset_for_arg(ssa, params[0], arg_family)
        if off is not None:
            out.add(int(off))
    return out


def find_cross_function_double_free(bv, *, binary: str, arch: str,
                                    platform: str,
                                    detector: str = "analysis.cross_function_heap",
                                    ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings

    # Index: {fn_start: set(offsets)} for functions that free arg fields.
    free_helper_fns: dict[int, tuple[object, set[int]]] = {}
    for fn in (bv.functions or []):
        # Skip CRT-internal functions
        sym = getattr(fn, "symbol", None)
        sn = (getattr(sym, "short_name", None) if sym else None) or getattr(fn, "name", "")
        if sn.startswith("_") or sn.startswith("std::") or sn.startswith("__"):
            continue
        offs = _function_frees_arg_field(bv, fn)
        if offs:
            free_helper_fns[int(getattr(fn, "start", 0))] = (fn, offs)

    if not free_helper_fns:
        return findings

    meta = CATEGORY_META["double_free"]
    # For each function in the binary: scan call sites of the
    # free-helper functions, and look for subsequent free() of the
    # same field of the same local.
    for caller_fn in (bv.functions or []):
        csn = (getattr(getattr(caller_fn, "symbol", None), "short_name", None)
               or getattr(caller_fn, "name", ""))
        if csn.startswith("_") or csn.startswith("std::") or csn.startswith("__"):
            continue
        mlil = getattr(caller_fn, "mlil", None)
        if mlil is None:
            continue
        ssa = getattr(mlil, "ssa_form", None) or mlil

        # First pass: locate helper-call sites + the local-pointer
        # passed in. Second pass: look for free(local->field) calls
        # AFTER each helper-call.
        helper_calls: list[tuple[int, str, set[int]]] = []  # (addr, local_id, offsets)
        free_calls: list[tuple[int, str, int]] = []        # (addr, local_id, offset)

        for inst in (getattr(ssa, "instructions", []) or []):
            if "Call" not in type(inst).__name__:
                continue
            addr = int(getattr(inst, "address", 0) or 0)
            dest = getattr(inst, "dest", None)
            if dest is None:
                continue
            cval = getattr(dest, "constant", None)
            if cval is None:
                continue
            target = int(cval)
            params = ilh.call_params(inst)
            if not params:
                continue
            arg0 = params[0]
            if target in free_helper_fns:
                # Helper call: arg0 is the pointer to the local
                # (`&e`). Identify by stack offset.
                local_id = _stack_local_id(arg0, caller_fn)
                if local_id is None:
                    continue
                _, offs = free_helper_fns[target]
                helper_calls.append((addr, local_id, offs))
            elif _is_delete_call(bv, inst):
                # free(local.field): arg0 is the field VALUE loaded
                # from the stack local. Resolve both the local id
                # (whose &-address sits in the Load's base SSA) and
                # the field offset.
                local_id, off = _resolve_local_field_access(
                    arg0, caller_fn, ssa,
                )
                if local_id is None or off is None:
                    continue
                free_calls.append((addr, local_id, off))

        # Pair: helper-call followed by a free with matching local_id
        # and overlapping offsets, in program order.
        for h_addr, h_local, h_offsets in helper_calls:
            for f_addr, f_local, f_offset in free_calls:
                if f_addr <= h_addr:
                    continue
                if h_local != f_local:
                    continue
                if f_offset not in h_offsets:
                    continue
                findings.append(Finding(
                    id="",
                    category="double_free",
                    severity=meta["severity"],
                    address=int(f_addr),
                    function=csn,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=(
                        f"{csn}: helper call at 0x{h_addr:x} frees "
                        f"arg->[+0x{f_offset:x}] of the passed pointer; "
                        f"caller then calls free(local->[+0x{f_offset:x}]) "
                        f"at 0x{f_addr:x} on the same local — cross-"
                        f"function double-free."
                    ),
                    evidence=[Evidence(
                        kind="cross_function_double_free",
                        source=detector,
                        payload=(f"helper_call=0x{h_addr:x} "
                                 f"free_call=0x{f_addr:x} "
                                 f"local={h_local} "
                                 f"field_offset=0x{f_offset:x}"),
                        address=int(f_addr),
                        function=csn,
                    )],
                    details={
                        "helper_call_addr": hex(h_addr),
                        "free_call_addr": hex(f_addr),
                        "local_id": h_local,
                        "field_offset": hex(f_offset),
                    },
                ))
                break  # one emission per helper-call is enough
    return findings


def _stack_local_id(expr, function) -> Optional[str]:
    """Identify the stack-allocated local that `expr` refers to.
    Returns a stable string identity (frame offset) or None.
    """
    if expr is None or function is None:
        return None
    # AddressOf( stack_var )
    op_name = type(expr).__name__
    if "AddressOf" in op_name or "Addr" in op_name:
        target = getattr(expr, "src", None) or getattr(expr, "var", None)
        if target is not None:
            storage = getattr(target, "storage", None)
            if storage is not None:
                return f"stack@{int(storage)}"
    # SSA var that traces back to AddressOf(stack_var)
    sv = ilh.expr_to_ssa_var(expr)
    if sv is None:
        return None
    seen: set = set()
    cur = sv
    for _ in range(4):
        if cur is None:
            return None
        key = str(cur)
        if key in seen:
            return None
        seen.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            return None
        src = getattr(defn, "src", None)
        if src is None:
            return None
        on = type(src).__name__
        if "AddressOf" in on or "Addr" in on:
            target = getattr(src, "src", None) or getattr(src, "var", None)
            if target is not None:
                storage = getattr(target, "storage", None)
                if storage is not None:
                    return f"stack@{int(storage)}"
            return None
        nxt = ilh.expr_to_ssa_var(src)
        if nxt is None:
            return None
        cur = nxt
    return None


def _ssa_arg_id(expr) -> Optional[str]:
    sv = ilh.expr_to_ssa_var(expr)
    if sv is None:
        return None
    return str(sv)


def _resolve_local_field_access(expr, function, ssa,
                                *, max_hops: int = 6
                                ) -> tuple[Optional[str], Optional[int]]:
    """For an expression that's the result of loading a field of a
    stack local — `[&stack_local + offset]` — return
    `(local_id, offset)`. Walks SSA copy chains until reaching the
    Load (or Binja's `VarAliasedField` equivalent), then resolves
    the base back to a `&stack_local`. Returns (None, None) if no
    terminating field-access is found within `max_hops`.
    """
    if expr is None or function is None or ssa is None:
        return (None, None)
    # Direct cases: Load or VarAliasedField.
    op_name = type(expr).__name__
    if "Load" in op_name:
        return _load_to_local_field(expr, function)
    if "AliasedField" in op_name or "AliasField" in op_name:
        return _aliased_field_to_local_field(expr, function)
    sv = ilh.expr_to_ssa_var(expr)
    if sv is None:
        return (None, None)
    seen: set = set()
    cur = sv
    for _ in range(max_hops):
        if cur is None:
            return (None, None)
        key = _ssa_id(cur)
        if key in seen:
            return (None, None)
        seen.add(key)
        defn = ilh.ssa_def_of(ssa, cur)
        if defn is None:
            return (None, None)
        src = getattr(defn, "src", None)
        if src is None:
            return (None, None)
        if "Load" in type(src).__name__:
            return _load_to_local_field(src, function)
        if "AliasedField" in type(src).__name__ or "AliasField" in type(src).__name__:
            return _aliased_field_to_local_field(src, function)
        nxt = ilh.expr_to_ssa_var(src)
        if nxt is None:
            return (None, None)
        cur = nxt
    return (None, None)


def _aliased_field_to_local_field(expr, function) -> tuple[Optional[str], Optional[int]]:
    """For a `MediumLevelILVarAliasedField` (`local.field` direct
    access) return (local_id, offset).
    """
    if expr is None:
        return (None, None)
    src = getattr(expr, "src", None)
    offset = getattr(expr, "offset", None)
    if src is None or offset is None:
        return (None, None)
    # src may be the SSAVariable directly or a VarSsa wrapper.
    var = getattr(src, "var", None) or src
    storage = getattr(var, "storage", None)
    if storage is None:
        return (None, None)
    try:
        return (f"stack@{int(storage)}", int(offset))
    except Exception:
        return (None, None)


def _load_to_local_field(load_expr, function) -> tuple[Optional[str], Optional[int]]:
    """For a Load expression, resolve `(local_id, offset)` if the
    load's base traces back to `&stack_local + offset`.
    """
    if load_expr is None:
        return (None, None)
    # LoadStructSsa exposes offset directly.
    typed_off = getattr(load_expr, "offset", None)
    if typed_off is not None and isinstance(typed_off, int):
        base = getattr(load_expr, "src", None)
        local_id = _stack_local_id(base, function) if base is not None else None
        if local_id is not None:
            return (local_id, int(typed_off))
    inner = getattr(load_expr, "src", None)
    if inner is None:
        return (None, None)
    # Plain Load — inner might be an Add or a bare base var.
    inner_op = type(inner).__name__
    if "Add" in inner_op:
        left = getattr(inner, "left", None)
        right = getattr(inner, "right", None)
        local_id = None
        offset = None
        for op in (left, right):
            if op is None:
                continue
            cv = getattr(op, "constant", None)
            if cv is not None:
                try:
                    offset = int(cv)
                    continue
                except Exception:
                    pass
            li = _stack_local_id(op, function)
            if li is not None:
                local_id = li
        if local_id is not None and offset is not None:
            return (local_id, offset)
    # Bare base var case — offset 0.
    local_id = _stack_local_id(inner, function)
    if local_id is not None:
        return (local_id, 0)
    return (None, None)


def _stack_local_field_offset(expr, function) -> Optional[int]:
    """If `expr` is a Load `[&stack_local + offset]` or a copy of one,
    return the offset. Used to detect `free(local.field)`."""
    if expr is None or function is None:
        return None
    # Load expr
    op_name = type(expr).__name__
    if "Load" in op_name:
        src = getattr(expr, "src", None)
        return _addr_local_field_offset(src, function)
    # SSA var — walk back
    sv = ilh.expr_to_ssa_var(expr)
    if sv is None:
        return None
    defn = ilh.ssa_def_of(function, sv)
    if defn is None:
        return None
    src = getattr(defn, "src", None)
    if src is None:
        return None
    on = type(src).__name__
    if "Load" in on:
        return _addr_local_field_offset(getattr(src, "src", None), function)
    if "Add" in on:
        return _addr_local_field_offset(src, function)
    return None


def _addr_local_field_offset(expr, function) -> Optional[int]:
    if expr is None:
        return None
    op_name = type(expr).__name__
    if "Add" in op_name:
        left = getattr(expr, "left", None)
        right = getattr(expr, "right", None)
        base_is_stack = False
        offset = None
        for op in (left, right):
            if op is None:
                continue
            cv = getattr(op, "constant", None)
            if cv is not None:
                try:
                    offset = int(cv)
                    continue
                except Exception:
                    pass
            # Check if op is an AddressOf-stack
            if _stack_local_id(op, function) is not None:
                base_is_stack = True
        if base_is_stack and offset is not None:
            return offset
    return None


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.cross_function_heap",
            ) -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    out: list[Finding] = []
    out.extend(find_cross_method_uaf(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    out.extend(find_shallow_copy_double_free(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    out.extend(find_cross_function_double_free(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    out.extend(find_cpp_class_heap_overflow(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    return out


# ─────────────────────────────────────────────────────────────────
# (4) Heap buffer overflow in C++ class methods — memcpy into
#     `this->field` with non-constant size and no dominating bound.
# ─────────────────────────────────────────────────────────────────


def _is_copy_into_buffer(bv, call_inst):
    """If `call_inst` calls a buffer-copy sink, return
    (sink_name, size_arg_index_or_None). Else (None, None).
    """
    dest = getattr(call_inst, "dest", None)
    if dest is None:
        return (None, None)
    cval = getattr(dest, "constant", None)
    if cval is None:
        return (None, None)
    sym = bv.get_symbol_at(int(cval))
    if sym is None:
        return (None, None)
    sn = getattr(sym, "short_name", None) or getattr(sym, "name", None) or ""
    if sn not in _COPY_INTO_BUFFER_SINKS:
        return (None, None)
    return (sn, _COPY_INTO_BUFFER_SINKS[sn])


def _is_constant_expr(expr) -> bool:
    """True iff `expr` resolves to a constant integer (literal or
    `value` constant)."""
    if expr is None:
        return False
    cv = getattr(expr, "constant", None)
    if cv is not None:
        return True
    val = getattr(expr, "value", None)
    if val is not None:
        vtype = getattr(val, "type", None)
        type_name = (getattr(vtype, "name", "") or str(vtype) or "").lower()
        if "constant" in type_name:
            return True
    return False


def find_cpp_class_heap_overflow(bv, *, binary: str, arch: str,
                                 platform: str,
                                 detector: str = "analysis.cross_function_heap",
                                 ) -> list[Finding]:
    """Class-method heap-buffer-overflow detector.

    For each member method (function whose demangled name contains
    `::`), find calls to buffer-copy sinks (`memcpy`, `strncpy`,
    `strcpy`, etc.) where:
      - The destination arg resolves to a load of `this->[+offset]`
        (Add-form Load or VarAliasedField).
      - The size arg (when present) is NOT a constant integer.

    The shape captures `class Buffer { ...; data_ = new char[N];
    void store(const std::string& s) { memcpy(data_, s.data(),
    s.size()); } };` — the canonical heap-overflow class-method
    pattern where the destination is sized at construction and
    the copy length is attacker-controlled.

    v1 emits regardless of dominating bound check — false-positive
    rate stays low because the dst-is-this-field constraint is
    strong. v2 would gate emission on absence of dominating
    comparison against `this->size_` (or similar).
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    classes = _classify_class_methods(bv)
    if not classes:
        return findings
    meta = CATEGORY_META["heap_buffer_overflow"]
    seen_keys: set[tuple[str, str, int]] = set()
    for cls, methods in classes.items():
        for mname, fn in methods:
            arg_family = _arg0_ssa_family(fn)
            if not arg_family:
                continue
            mlil = getattr(fn, "mlil", None) or fn
            ssa = getattr(mlil, "ssa_form", None) or mlil
            for inst in (getattr(ssa, "instructions", []) or []):
                if "Call" not in type(inst).__name__:
                    continue
                sink_name, size_idx = _is_copy_into_buffer(bv, inst)
                if sink_name is None:
                    continue
                params = ilh.call_params(inst)
                if not params:
                    continue
                # Destination arg traces to `this->[+offset]`.
                dst_offset = _resolve_load_offset_for_arg(
                    ssa, params[0], arg_family,
                )
                if dst_offset is None:
                    continue
                # Size operand: when present, non-constant flags it.
                # When the sink is unbounded (strcpy / strcat / wcscpy),
                # there's no size to check — always flag.
                if size_idx is not None:
                    if size_idx >= len(params):
                        continue
                    if _is_constant_expr(params[size_idx]):
                        continue
                addr = int(getattr(inst, "address", 0) or 0)
                method_full = f"{cls}::{mname}"
                key = (cls, mname, addr)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(Finding(
                    id="",
                    category="heap_buffer_overflow",
                    severity=meta["severity"],
                    address=addr,
                    function=method_full,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=(
                        f"{method_full}: {sink_name}@0x{addr:x} writes "
                        f"into `this->[+0x{dst_offset:x}]` with a "
                        f"non-constant size operand. The destination "
                        f"is a heap-allocated field of the class; "
                        f"unless the size is bounded against the "
                        f"allocation, attacker-controlled input "
                        f"length produces a heap-buffer-overflow."
                    ),
                    evidence=[Evidence(
                        kind="class_method_memcpy_into_this_field",
                        source=detector,
                        payload=(f"class={cls} method={mname} "
                                 f"sink={sink_name} "
                                 f"dst_offset=0x{dst_offset:x} "
                                 f"call_addr=0x{addr:x}"),
                        address=addr,
                        function=method_full,
                    )],
                    details={
                        "class_name": cls,
                        "method": mname,
                        "sink": sink_name,
                        "dst_this_offset": hex(dst_offset),
                    },
                ))
    return findings
