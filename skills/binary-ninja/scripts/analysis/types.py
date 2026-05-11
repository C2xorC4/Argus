"""Type-confusion / vtable-misuse detection — minimal v1.

The full Tier-2 #6 detector requires substrate that's beyond
practical scope for this iteration:

- Per-call-site downcast tracking (`static_cast` is compile-time,
  leaves no MLIL trace — detection from binary alone is
  fundamentally limited).
- ABI-aware vtable extraction (MSVC `__thiscall` ECX vs GCC
  explicit-first-param; RTTI layout differences; template-
  instantiation diversity).
- Distinguishing legitimate vtable diversity (templates) from
  actual confusion (downcast without check).

This module ships a v1 that captures the *one* signal that's
reliably extractable from a stripped binary:

**Pattern:** the binary makes virtual-method calls (indirect calls
through a vtable slot) AND imports no RTTI helpers (no
`__cxa_dynamic_cast`, no `__RTDynamicCast`, no equivalent). In
this configuration every downcast in the source code is
unverified — a *necessary* condition for type-confusion exploitation,
though not *sufficient*.

The finding is therefore an **info-grade hint**, not a confirmed
type-confusion finding. Categorised as `type_confusion_candidate`
to distinguish from a true positive. Confidence is low by design.

Future Tier-2 #6 v2 enhancements (Plan-D-class, source-driven):

- Source-pattern detection on `static_cast<X*>(...)` without a
  guarding `if (dynamic_cast<X*>(...))` or `typeid()` check.
- Vtable-extraction with MSVC + GCC ABI awareness; flag mismatched
  vtable-slot indices across siblings of a class hierarchy.
- Tagged-union analysis (C variant): identify union-member access
  not preceded by a tag check — needs struct layout from debug info
  or grey-box source enrichment.

Knowledge anchors:
- `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` — UB on
  invalid downcasts
- `[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]` — manual cast
  pattern catalogue
- `[[Memory/Knowledge/gb_obfuscated_code_analysis]]` — vtable
  recovery / ABI distinctions
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..heuristics._base import imports_in
from ..lib.scoring import apply_signals_to_finding
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh


# ─────────────────────────────────────────────────────────────────
# RTTI-helper imports — the canonical set
# ─────────────────────────────────────────────────────────────────


_NON_USER_FUNCTION_PREFIXES: tuple[str, ...] = (
    # GCC / MinGW init / unwind helpers
    "__gcc_", "__do_global_", "_GLOBAL__sub_", "_TLS_Entry_",
    "_register_", "_register_frame", "__deregister_",
    "__main", "__do_pseudo", "__cxa_atexit", "__cxa_finalize",
    "_gnu_", "__gnu_",
    # MSVC CRT runtime
    "__scrt_", "__report_", "__crt_", "__chkstk",
    "__security_", "__std_exception_",
    # MinGW thread / TLS helpers (note: __mingwthr_* has no underscore
    # between mingw and thr, so use the shorter prefix).
    "__mingw", "___w64_",
    # C++ standard library demangled prefixes
    "std::", "__gnu_cxx::",
    # C++ Itanium-ABI mangled prefixes for std/stl
    "_ZSt", "_ZNSt", "_ZNKSt", "_ZNS", "_ZNK", "_Znw", "_Znd",
    "_Zdl", "_Zda",
    # Itanium-ABI typeinfo / vtable
    "_ZTV", "_ZTI", "_ZTS",
    # GCC C++ runtime
    "_Unwind_", "__cxa_",
)


def _is_user_function(name: str) -> bool:
    """True if the function name appears to be user-authored code,
    not CRT / STL / runtime-init."""
    if not name:
        return False
    for prefix in _NON_USER_FUNCTION_PREFIXES:
        if name.startswith(prefix):
            return False
    return True


_RTTI_HELPERS: frozenset[str] = frozenset({
    # Itanium ABI (Linux, macOS, MinGW, most non-MSVC) — only the
    # actual RTTI / type-check helpers, NOT exception-unwind helpers
    # (those fire on any C++ binary using exceptions, regardless of
    # whether RTTI is checked at downcasts).
    "__cxa_dynamic_cast",
    "__cxa_bad_typeid",
    "__cxa_bad_cast",
    # MSVC ABI
    "__RTDynamicCast",
    "__RTtypeid",
    "__RTCastToVoid",
})


CATEGORY_META = {
    "type_confusion_candidate": {
        "severity": Severity.LOW,
        "cwe": ["CWE-843"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]",
            "[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]",
        ],
    },
    "type_confusion": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-843"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]",
            "[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]",
        ],
    },
}


# ─────────────────────────────────────────────────────────────────
# Indirect-call enumeration
# ─────────────────────────────────────────────────────────────────


def _is_indirect_call_via_pointer_chain(inst, function) -> bool:
    """True iff `inst` is an indirect MLIL call whose dest's SSA
    definition chain reaches a memory load.

    The canonical vtable-dispatch sequence in MLIL SSA is:

        rax = [obj + 0]          # load vtable pointer
        rdx = [rax + slot_N]     # load method function pointer
        rdx(args)                # indirect call

    The call's `dest` is `rdx` (a register), not a Load directly.
    We chase `rdx`'s SSA def to confirm the value originated from a
    memory load.

    Limited to ~3 def hops to keep the analysis bounded; real vtable
    chains rarely indirect more than that.
    """
    if inst is None:
        return False
    op_name = type(inst).__name__
    if "Call" not in op_name:
        return False
    dest = getattr(inst, "dest", None)
    if dest is None:
        return False
    cval = getattr(dest, "constant", None)
    if cval is not None:
        return False              # direct call
    # Walk SSA defs from dest looking for a Load
    cur = ilh.expr_to_ssa_var(dest)
    if cur is None:
        # dest is itself a Load expression directly?
        return "Load" in type(dest).__name__
    seen: set = set()
    for _ in range(4):
        key = str(cur)
        if key in seen:
            return False
        seen.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            return False
        src = getattr(defn, "src", None)
        if src is None:
            return False
        if "Load" in type(src).__name__:
            return True
        # Recurse into operand for arithmetic shapes (Add/Sub on a load)
        for op in getattr(src, "operands", []) or []:
            if "Load" in type(op).__name__:
                return True
        nested = ilh.expr_to_ssa_var(src)
        if nested is None:
            return False
        cur = nested
    return False


def _count_indirect_vtable_calls(bv) -> tuple[int, list[tuple[int, str]]]:
    """Return (count, [(addr, function_name), ...]) of indirect calls
    whose dest's SSA def chain reaches a memory load — the
    canonical vtable / function-pointer-table dispatch shape.

    Filters out CRT / STL / runtime-init functions where indirect
    dispatch is expected and not a user-code type-confusion candidate
    (every C++ binary uses iostreams; without filtering every cpp cell
    would FP).
    """
    if bv is None:
        return (0, [])
    sites: list[tuple[int, str]] = []
    for func in bv.functions:
        fname = ilh.function_display_name(func)
        if not _is_user_function(fname):
            continue
        mlil = getattr(func, "mlil", None)
        if mlil is None:
            continue
        ssa = getattr(mlil, "ssa_form", None)
        if ssa is None:
            continue
        for inst in ssa.instructions:
            if _is_indirect_call_via_pointer_chain(inst, func):
                addr = int(getattr(inst, "address", 0))
                sites.append((addr, fname))
    return (len(sites), sites)


# ─────────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────────


def _binary_uses_cpp(bv) -> bool:
    """True iff the binary contains C++-class-related symbols.

    Looks for vtable / typeinfo symbols (Itanium ABI: `_ZTV*` /
    `_ZTI*`; MSVC: names containing `vftable` / `vbtable`) and for
    mangled-name imports / functions. Pure C binaries don't contain
    any of these.
    """
    if bv is None:
        return False
    syms = getattr(bv, "get_symbols", None)
    if not callable(syms):
        # Fallback: scan function names
        for f in getattr(bv, "functions", []):
            n = getattr(f, "name", "") or ""
            if n.startswith("_Z") or "vftable" in n or "vbtable" in n:
                return True
        return False
    try:
        for sym in bv.get_symbols():
            # Binja exposes the mangled raw name on `.name` and the
            # demangled short form on `.short_name`. Check both —
            # `.short_name` is the source-level prettified name and
            # may not reveal mangling.
            for attr in ("name", "raw_name", "full_name", "short_name"):
                n = getattr(sym, attr, "") or ""
                if not n:
                    continue
                # Itanium ABI: vtable `_ZTV*`, typeinfo `_ZTI*`,
                # constructor `_ZN*C1*`/`_ZN*C2*`, etc. — any `_Z`
                # prefix is enough to confirm C++ presence.
                if n.startswith("_Z") and len(n) > 2:
                    return True
                # MSVC: virtual function table symbols
                if "vftable" in n or "vbtable" in n:
                    return True
    except Exception:
        pass
    # Fallback: scan function names
    for f in getattr(bv, "functions", []):
        n = getattr(f, "name", "") or ""
        if n.startswith("_Z") and len(n) > 2:
            return True
        if "vftable" in n or "vbtable" in n:
            return True
    return False


def find_type_confusion_candidates(bv, *, binary: str, arch: str, platform: str,
                                   detector: str = "analysis.types") -> list[Finding]:
    findings: list[Finding] = []
    # Gate to C++ binaries — pure C has no virtual dispatch class to
    # confuse, and CRT-internal indirect calls (`__gcc_deregister_frame`,
    # `__do_global_dtors`, etc.) would otherwise fire universally.
    if not _binary_uses_cpp(bv):
        return findings

    imports = imports_in(bv)
    rtti_present = bool(imports & _RTTI_HELPERS)
    if rtti_present:
        # Binary uses RTTI helpers — at least some downcasts are
        # checked. Without per-call-site analysis we can't flag
        # individual sites; defer to v2.
        return findings

    indirect_count, sites = _count_indirect_vtable_calls(bv)
    if indirect_count == 0:
        return findings

    # Emit one Finding per binary, not per call site — the signal is
    # binary-level (RTTI absent) plus the count of unverified sites.
    # Anchor at the first site for address localisation.
    first_addr, first_func = sites[0]
    meta = CATEGORY_META["type_confusion_candidate"]
    finding = Finding(
        id="",
        category="type_confusion_candidate",
        severity=meta["severity"],
        address=first_addr,
        function=first_func,
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta["knowledge_refs"]),
        cwe=list(meta["cwe"]),
        mitre_attack=list(meta["mitre"]),
        description=(
            f"Binary makes {indirect_count} indirect call(s) through vtable / "
            f"function-pointer load, but imports no RTTI helpers "
            f"(__cxa_dynamic_cast, __RTDynamicCast, etc.). All downcasts in "
            f"this binary are unverified at runtime — a necessary (not "
            f"sufficient) condition for type-confusion exploitation. "
            f"Source-level audit recommended to find unguarded static_cast "
            f"sites."
        ),
        evidence=[Evidence(
            kind="binary_level_rtti_absence",
            source=detector,
            payload=f"indirect_vtable_calls={indirect_count} rtti_imports=none",
            address=first_addr,
            function=first_func,
        )],
        details={
            "indirect_call_count": indirect_count,
            "rtti_imports_present": False,
            "first_site_addr": hex(first_addr),
            "first_site_function": first_func,
        },
    )
    # Deliberately do NOT call `apply_signals_to_finding` — the v1
    # binary-level signal is research-grade ("this binary's downcast
    # discipline is worth auditing"), not detection-grade. Leaving
    # confidence at the neutral 0.5 default reflects that honestly;
    # consumers reading `confidence` for triage prioritisation will
    # weight this below detector findings that DO claim per-site
    # signal anchoring. v2 (per-call-site SPECIFIC anchoring) will
    # wire `vtable_dispatch_after_unguarded_downcast` correctly.
    findings.append(finding)

    # Per-call-site `type_confusion` HIGH emissions. In a binary
    # that uses C++ classes and makes vtable-indirect calls but
    # imports no RTTI helpers, EACH such site is a potential type-
    # confusion sink — the operator can't tell if the pointer
    # being dispatched has been downcast safely. v2 will refine by
    # checking whether the dispatch target is reached via a
    # function-parameter pointer (the classic "downcast a Shape*
    # to a Circle* then call ->area()" shape).
    type_meta = CATEGORY_META["type_confusion"]
    seen_site_keys: set[tuple[str, int]] = set()
    for site_addr, site_func in sites:
        key = (site_func, site_addr)
        if key in seen_site_keys:
            continue
        seen_site_keys.add(key)
        findings.append(Finding(
            id="",
            category="type_confusion",
            severity=type_meta["severity"],
            address=int(site_addr),
            function=site_func,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(type_meta["knowledge_refs"]),
            cwe=list(type_meta["cwe"]),
            mitre_attack=list(type_meta["mitre"]),
            description=(
                f"{site_func}: vtable-indirect call at 0x{site_addr:x} "
                f"in a binary that imports no RTTI helpers — the "
                f"pointer being dispatched may have been downcast "
                f"via unguarded `static_cast` from a different "
                f"runtime type. Canonical type-confusion sink: "
                f"calling a method through a virtual-dispatch slot "
                f"that's actually the wrong type's vtable."
            ),
            evidence=[Evidence(
                kind="vtable_dispatch_without_rtti",
                source=detector,
                payload=(f"site_addr=0x{site_addr:x} "
                         f"rtti_imports=none "
                         f"binary_indirect_calls={indirect_count}"),
                address=int(site_addr),
                function=site_func,
            )],
            details={
                "site_addr": hex(int(site_addr)),
                "rtti_imports_present": False,
                "binary_indirect_call_count": indirect_count,
            },
        ))
    return findings


# ─────────────────────────────────────────────────────────────────
# Tagged-union misuse (C variant) — struct with enum-tag + union
# accessed without preceding tag-check.
# ─────────────────────────────────────────────────────────────────


def _find_tagged_union_structs(bv):
    """Enumerate type definitions for structs that look like tagged
    unions: at least one member typed as an enum AND at least one
    member typed as a union. Returns
    {struct_type_name: (tag_offset, union_offset)}.
    """
    out: dict[str, tuple[int, int]] = {}
    try:
        type_list = list(bv.types)
    except Exception:
        return out
    for entry in type_list:
        # entry is (QualifiedName, Type) in recent Binja.
        try:
            qname, ty = entry
        except Exception:
            continue
        if ty is None:
            continue
        # Structure types expose `.members`. Union types do too, but
        # they don't carry the tag/union shape themselves.
        members = getattr(ty, "members", None)
        if not members:
            continue
        tag_off = None
        union_off = None
        for m in members:
            mtype = getattr(m, "type", None)
            if mtype is None:
                continue
            type_str = str(mtype).lower()
            tcls = getattr(mtype, "type_class", None)
            tcls_name = (getattr(tcls, "name", "") if tcls is not None else "") or ""
            # Tag-like: explicit enum, or an integer field named
            # `tag` / `type` / `kind` / `discriminator` / `which`.
            is_enum = ("enum" in type_str or "Enumeration" in tcls_name)
            mname = (getattr(m, "name", "") or "").lower()
            is_named_tag = mname in {"tag", "type", "kind",
                                     "discriminator", "which"}
            if (is_enum or is_named_tag) and tag_off is None:
                tag_off = int(getattr(m, "offset", 0))
            # Union-like: explicit union or named-type-ref to a union.
            if "union" in type_str:
                if union_off is None:
                    union_off = int(getattr(m, "offset", 0))
        if tag_off is not None and union_off is not None and tag_off != union_off:
            qstr = str(qname)
            out[qstr] = (tag_off, union_off)
    return out


def _function_takes_pointer_to_struct(fn, struct_name: str) -> bool:
    """True iff `fn` has at least one parameter typed as a pointer
    to a struct whose qualified name matches `struct_name`."""
    if fn is None:
        return False
    src_fn = getattr(fn, "source_function", None) or fn
    params = list(getattr(src_fn, "parameter_vars", None) or [])
    for p in params:
        type_str = ilh.safe_type_str(p)
        if type_str and struct_name in type_str and "*" in type_str:
            return True
    return False


def _field_accesses_in_function(function, target_offset: int) -> list[int]:
    """Return addresses where the function loads from `this->[+target_offset]`
    via Binja's struct-aware field-load shapes (LoadStructSsa with
    matching `.offset`, VarAliasedField with matching `.offset`, or
    Add(base, const)-style Load whose const matches target_offset).
    """
    out: list[int] = []
    if function is None:
        return out
    mlil = getattr(function, "mlil", None) or function
    ssa = getattr(mlil, "ssa_form", None) or mlil
    for inst in (getattr(ssa, "instructions", []) or []):
        src = getattr(inst, "src", None)
        if src is None:
            continue
        op_name = type(src).__name__
        # LoadStructSsa or VarAliasedField — `.offset` attribute
        if ("LoadStruct" in op_name or "AliasedField" in op_name or
                "AliasField" in op_name):
            off = getattr(src, "offset", None)
            if isinstance(off, int) and int(off) == int(target_offset):
                out.append(int(getattr(inst, "address", 0) or 0))
                continue
        # Generic Load with Add(base, const)
        if "Load" in op_name:
            inner = getattr(src, "src", None)
            if inner is not None and "Add" in type(inner).__name__:
                left = getattr(inner, "left", None)
                right = getattr(inner, "right", None)
                for op in (left, right):
                    if op is None:
                        continue
                    cv = getattr(op, "constant", None)
                    if cv is not None and int(cv) == int(target_offset):
                        out.append(int(getattr(inst, "address", 0) or 0))
                        break
    return out


def _has_compare_on_tag(function, tag_load_addrs: list[int]) -> bool:
    """True if any compare/conditional-branch instruction in the
    function reads a value transitively defined by a tag load."""
    if function is None or not tag_load_addrs:
        return False
    mlil = getattr(function, "mlil", None) or function
    ssa = getattr(mlil, "ssa_form", None) or mlil
    # Collect SSA vars defined at the tag load addresses.
    tag_def_vars: set[str] = set()
    for inst in (getattr(ssa, "instructions", []) or []):
        addr = int(getattr(inst, "address", 0) or 0)
        if addr not in tag_load_addrs:
            continue
        dst = getattr(inst, "dest", None)
        if dst is None:
            continue
        name = getattr(getattr(dst, "var", None), "name", None) or getattr(dst, "name", None)
        version = getattr(dst, "version", None)
        if name is not None and version is not None:
            tag_def_vars.add(f"{name}#{version}")
    if not tag_def_vars:
        return False

    # BFS through SetVar copy chains starting from tag_def_vars.
    reachable = set(tag_def_vars)
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
            sv = ilh.expr_to_ssa_var(src)
            if sv is None:
                continue
            name = getattr(getattr(sv, "var", None), "name", None) or ""
            version = getattr(sv, "version", None)
            key = f"{name}#{version}" if version is not None else ""
            if key in reachable:
                dst = getattr(inst, "dest", None)
                if dst is None:
                    continue
                dn = getattr(getattr(dst, "var", None), "name", None) or ""
                dv = getattr(dst, "version", None)
                dk = f"{dn}#{dv}" if dv is not None else ""
                if dk and dk not in reachable:
                    reachable.add(dk)
                    changed = True

    # Look for any Cmp/If whose operand is in `reachable`.
    for inst in (getattr(ssa, "instructions", []) or []):
        op = type(inst).__name__
        cond = None
        if "If" in op:
            cond = getattr(inst, "condition", None)
        if cond is None and "Cmp" in op:
            cond = inst
        if cond is None:
            continue
        # Walk operands looking for an SSA var in `reachable`.
        for child in (getattr(cond, "operands", None) or [cond]):
            sv = ilh.expr_to_ssa_var(child)
            if sv is None:
                continue
            name = getattr(getattr(sv, "var", None), "name", None) or ""
            version = getattr(sv, "version", None)
            key = f"{name}#{version}" if version is not None else ""
            if key in reachable:
                return True
    return False


def find_tagged_union_misuse(bv, *, binary: str, arch: str,
                             platform: str,
                             detector: str = "analysis.types",
                             ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    struct_index = _find_tagged_union_structs(bv)
    if not struct_index:
        return findings

    meta = {
        "severity": Severity.HIGH,
        "cwe": ["CWE-843"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]",
            "[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]",
        ],
    }

    for struct_name, (tag_off, union_off) in struct_index.items():
        for fn in (bv.functions or []):
            if not _function_takes_pointer_to_struct(fn, struct_name):
                continue
            union_accesses = _field_accesses_in_function(fn, union_off)
            if not union_accesses:
                continue
            tag_loads = _field_accesses_in_function(fn, tag_off)
            # If there's a tag load AND a compare dominated by it,
            # consider the function tag-checked. Otherwise emit.
            if tag_loads and _has_compare_on_tag(fn, tag_loads):
                continue
            sf = getattr(fn, "source_function", None) or fn
            fname = getattr(sf, "name", "") or f"sub_{getattr(sf, 'start', 0):x}"
            addr = int(union_accesses[0])
            findings.append(Finding(
                id="",
                category="type_confusion",
                severity=meta["severity"],
                address=addr,
                function=fname,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre"]),
                description=(
                    f"{fname}: accesses union member at "
                    f"`{struct_name}.[+0x{union_off:x}]` without a "
                    f"preceding compare on the tag field at "
                    f"`+0x{tag_off:x}`. Tagged-union misuse — if the "
                    f"tag indicates a different variant, the union "
                    f"bytes are reinterpreted as the wrong type."
                ),
                evidence=[Evidence(
                    kind="tagged_union_access_without_tag_check",
                    source=detector,
                    payload=(f"struct={struct_name} "
                             f"tag_offset=0x{tag_off:x} "
                             f"union_offset=0x{union_off:x} "
                             f"union_access_addr=0x{addr:x} "
                             f"tag_load_count={len(tag_loads)}"),
                    address=addr,
                    function=fname,
                )],
                details={
                    "struct_name": struct_name,
                    "tag_offset": hex(tag_off),
                    "union_offset": hex(union_off),
                    "tag_load_count": len(tag_loads),
                },
            ))
    return findings


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.types") -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    out: list[Finding] = []
    out.extend(find_type_confusion_candidates(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    out.extend(find_tagged_union_misuse(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    return out
