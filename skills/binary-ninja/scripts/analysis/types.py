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

    return find_type_confusion_candidates(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
