"""Evasion structural detectors.

Closes the gap where `heuristics/evasion.py` declares StructuralPattern
shapes (e.g. `pe_directory_present` for IMAGE_TLS_DIRECTORY) but no
analysis module evaluates them. Each detector in this module emits a
Finding using the category declared by the corresponding heuristic
pattern.

Categories emitted:
  - `tls_callback_first_stage`     — user-defined TLS callback in .CRT$XL*
  - `hidden_from_debugger_thread`  — NtSetInformationThread(0x11) call

Knowledge: `[[Memory/Knowledge/em_covert_execution_tls_seh]]`
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in, strings_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh


CATEGORY_META = {
    "tls_callback_first_stage": {
        "severity": Severity.MEDIUM,
        "cwe": [],
        "mitre": ["T1106"],
        "knowledge_refs": [
            "[[Memory/Knowledge/em_covert_execution_tls_seh]]",
        ],
    },
    "hidden_from_debugger_thread": {
        "severity": Severity.MEDIUM,
        "cwe": [],
        "mitre": ["T1622"],
        "knowledge_refs": [
            "[[Memory/Knowledge/em_covert_execution_tls_seh]]",
        ],
    },
}


# CRT-internal callback names that aren't user-defined TLS callbacks
# even when they appear in `.CRT$XL*`. Don't trip on these.
_CRT_INTERNAL_CALLBACKS: frozenset[str] = frozenset({
    "__dyn_tls_init_callback",
    "__dyn_tls_dtor_callback",
})


def _find_user_tls_callbacks(bv) -> list[tuple[int, int, str, str]]:
    """Return [(ptr_addr, target_addr, ptr_symbol_name, target_function_name), ...]
    for each function pointer in `.CRT` whose host symbol is user-named
    (doesn't start with `_.CRT$` and isn't one of the known CRT
    internals) AND whose target function is in `.text`.
    """
    out: list[tuple[int, int, str, str]] = []
    crt_section = None
    for s in (bv.sections.values() if hasattr(bv, "sections") else []):
        if s.name == ".CRT":
            crt_section = s
            break
    if crt_section is None:
        return out
    ptr_size = 8 if bv.address_size == 8 else 4
    for off in range(int(crt_section.start), int(crt_section.end), ptr_size):
        try:
            ptr = bv.read_int(off, ptr_size)
        except Exception:
            continue
        if not ptr:
            continue
        target_fn = bv.get_function_at(int(ptr))
        if target_fn is None:
            continue
        # Target must be in .text (.code) to count as a real callback.
        target_sec = next(
            (s for s in bv.sections.values()
             if s.start <= int(ptr) < s.end),
            None,
        )
        if target_sec is None:
            continue
        if not any(t in target_sec.name.lower() for t in (".text", "code")):
            continue
        ptr_sym = bv.get_symbol_at(off)
        ptr_sym_name = (getattr(ptr_sym, "name", "") or
                        getattr(ptr_sym, "short_name", "") or
                        "")
        # Filter out CRT-internal slots.
        if ptr_sym_name.startswith("_.CRT$"):
            # Compiler-generated slot (XCA, XIA, XLA, XLZ etc.). The
            # callback may or may not be user code — check the target
            # function's name.
            target_name = getattr(target_fn, "name", "")
            if (target_name in _CRT_INTERNAL_CALLBACKS
                    or target_name.startswith("_TLS_Entry_")
                    or target_name.startswith("pre_c_init")
                    or target_name.startswith("pre_cpp_init")
                    or target_name.startswith("my_lconv_init")):
                continue
        target_name = getattr(target_fn, "name", "") or f"sub_{int(ptr):x}"
        out.append((off, int(ptr), ptr_sym_name, target_name))
    return out


def find_tls_callbacks(bv, *, binary: str, arch: str, platform: str,
                       detector: str = "analysis.evasion_structures",
                       ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    callbacks = _find_user_tls_callbacks(bv)
    if not callbacks:
        return findings
    meta = CATEGORY_META["tls_callback_first_stage"]
    for ptr_addr, target_addr, ptr_name, target_name in callbacks:
        findings.append(Finding(
            id="",
            category="tls_callback_first_stage",
            severity=meta["severity"],
            address=int(target_addr),
            function=target_name,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre"]),
            description=(
                f"PE has IMAGE_TLS_DIRECTORY with a user-defined "
                f"callback `{target_name}@0x{target_addr:x}` registered "
                f"at `.CRT[{hex(ptr_addr)}]`"
                f"{f' (symbol `{ptr_name}`)' if ptr_name else ''}. "
                f"TLS callbacks fire BEFORE the binary's entry point — "
                f"useful for malware that wants execution during the "
                f"loader's own initialisation."
            ),
            evidence=[Evidence(
                kind="pe_directory_present",
                source=detector,
                payload=(f"IMAGE_DIRECTORY_ENTRY_TLS callback_count>=1 "
                         f"ptr_addr=0x{ptr_addr:x} target=0x{target_addr:x}"),
                address=int(target_addr),
                function=target_name,
            ), Evidence(
                kind="tls_callback_count_nonzero",
                source=detector,
                payload=f"target={target_name} symbol={ptr_name!r}",
                address=int(ptr_addr),
                function=target_name,
            )],
            details={
                "tls_callback_addr": hex(int(target_addr)),
                "tls_callback_ptr_addr": hex(int(ptr_addr)),
                "tls_callback_ptr_symbol": ptr_name,
                "tls_callback_target_function": target_name,
            },
        ))
    return findings


# ─────────────────────────────────────────────────────────────────
# Hidden-from-debugger thread — NtSetInformationThread(0x11)
# ─────────────────────────────────────────────────────────────────


_THREAD_HIDE_FROM_DEBUGGER = 0x11


def find_hidden_from_debugger_thread(
        bv, *, binary: str, arch: str, platform: str,
        detector: str = "analysis.evasion_structures",
) -> list[Finding]:
    """Emit when the binary calls (or dynamically resolves)
    NtSetInformationThread AND references the constant 0x11
    (ThreadHideFromDebugger).

    Two trigger shapes:
      1. NtSetInformationThread is a direct import — find call sites
         and check the ThreadInformationClass arg (param[1]) for 0x11.
      2. NtSetInformationThread is dynamically resolved (string literal
         in `.rdata` + GetProcAddress) — the constant 0x11 is referenced
         elsewhere in the binary. Lower confidence (no direct callsite),
         but matches the canonical fixture shape.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    strings = strings_in(bv) or []
    string_values = {s for s, _ in strings}
    meta = CATEGORY_META["hidden_from_debugger_thread"]

    NSIT = "NtSetInformationThread"
    has_direct_import = NSIT in imports
    has_dynamic_string = NSIT in string_values

    if not has_direct_import and not has_dynamic_string:
        return findings

    # Shape 1: direct import. Scan callsites for arg[1] == 0x11.
    if has_direct_import:
        for call_addr, mlil in ilh.call_sites_of_import(bv, NSIT):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if len(params) < 2:
                continue
            info_class = _expr_const(params[1])
            if info_class != _THREAD_HIDE_FROM_DEBUGGER:
                continue
            func = getattr(mlil, "function", None)
            if func is None:
                continue
            sf = getattr(func, "source_function", None) or func
            fname = getattr(sf, "name", "") or f"sub_{getattr(sf, 'start', 0):x}"
            findings.append(Finding(
                id="",
                category="hidden_from_debugger_thread",
                severity=meta["severity"],
                address=int(call_addr),
                function=fname,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre"]),
                description=(
                    f"{fname}: NtSetInformationThread@0x{call_addr:x} "
                    f"called with ThreadInformationClass = 0x11 "
                    f"(ThreadHideFromDebugger). The thread suppresses "
                    f"creation events from debuggers."
                ),
                evidence=[Evidence(
                    kind="literal_string",
                    source=detector,
                    payload=f"value=NtSetInformationThread (imported)",
                    address=int(call_addr), function=fname,
                ), Evidence(
                    kind="constant_argument",
                    source=detector,
                    payload=(f"callee=NtSetInformationThread arg_index=1 "
                             f"value=17"),
                    address=int(call_addr), function=fname,
                )],
                details={
                    "info_class": _THREAD_HIDE_FROM_DEBUGGER,
                    "import_kind": "direct",
                    "call_addr": hex(int(call_addr)),
                },
            ))
        return findings

    # Shape 2: dynamic resolution. Check that the constant 0x11 is
    # referenced somewhere in the binary's code.
    if has_dynamic_string and _binary_has_constant(bv, _THREAD_HIDE_FROM_DEBUGGER):
        # Anchor at the entry point / main if available.
        anchor_func = None
        for fn in (bv.functions or []):
            nm = getattr(fn, "name", "") or ""
            if nm in ("main", "wmain", "WinMain", "wWinMain", "_main"):
                anchor_func = fn
                break
        if anchor_func is None:
            anchor_func = bv.entry_function or (
                bv.functions[0] if bv.functions else None)
        addr = int(getattr(anchor_func, "start", 0) or 0)
        fname = getattr(anchor_func, "name", "<entry>") if anchor_func else "<binary>"
        findings.append(Finding(
            id="",
            category="hidden_from_debugger_thread",
            severity=meta["severity"],
            address=addr,
            function=fname,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre"]),
            description=(
                f"Binary references the literal string "
                f"`NtSetInformationThread` (likely via "
                f"GetProcAddress runtime resolution) AND references "
                f"the constant 0x11 (ThreadHideFromDebugger). Canonical "
                f"dynamic-resolution shape for thread-hiding evasion."
            ),
            evidence=[Evidence(
                kind="literal_string",
                source=detector,
                payload="value=NtSetInformationThread (dynamic via GetProcAddress)",
                address=addr, function=fname,
            ), Evidence(
                kind="constant_argument",
                source=detector,
                payload=(f"callee=NtSetInformationThread arg_index=1 "
                         f"value=17 (referenced; binding to call site "
                         f"requires dynamic-resolution tracking)"),
                address=addr, function=fname,
            )],
            details={
                "info_class": _THREAD_HIDE_FROM_DEBUGGER,
                "import_kind": "dynamic_via_string",
            },
        ))
    return findings


def _expr_const(expr) -> Optional[int]:
    if expr is None:
        return None
    cv = getattr(expr, "constant", None)
    if cv is not None:
        try:
            return int(cv)
        except Exception:
            return None
    val = getattr(expr, "value", None)
    if val is not None:
        v = getattr(val, "value", None)
        if v is not None:
            try:
                return int(v)
            except Exception:
                return None
    return None


def _binary_has_constant(bv, value: int) -> bool:
    """True iff `value` appears as a 32- or 64-bit constant in any
    MLIL instruction in the binary."""
    try:
        for fn in (bv.functions or []):
            mlil = getattr(fn, "mlil", None)
            if mlil is None:
                continue
            for inst in getattr(mlil, "instructions", []) or []:
                # Walk operands recursively
                if _expr_contains_const(inst, value, max_depth=6):
                    return True
    except Exception:
        return False
    return False


def _expr_contains_const(expr, want: int, max_depth: int = 6) -> bool:
    if expr is None or max_depth <= 0:
        return False
    cv = _expr_const(expr)
    if cv is not None and int(cv) == int(want):
        return True
    for op in (getattr(expr, "operands", None) or []):
        if _expr_contains_const(op, want, max_depth - 1):
            return True
    return False


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.evasion_structures",
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
    out.extend(find_tls_callbacks(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    out.extend(find_hidden_from_debugger_thread(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    return out
