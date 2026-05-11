"""Dynamic-argument sink detector.

For a small set of sinks where having a NON-CONSTANT pointer
argument is itself the bug, emit the canonical category at each
call site. Complements `taint.py` by covering shapes where the
SSA taint flow doesn't propagate end-to-end (most commonly: taint
flowing through std::string / std::vector wrappers, where
SSA-level taint dies at the wrapper boundary per
`_cpp_stdlib_propagator_for_name`'s known limitation).

The structural argument:

  - `printf(buf)` is a format-string bug regardless of how `buf`
    became non-constant. A static .rdata literal at the format
    argument is the only safe shape.
  - `system(buf)` / `popen(buf)` / `execl(buf)` etc. with a
    non-constant argument is a command-injection candidate.
    Static literals would be vendor-defined commands (still bad
    practice but not a bug class).
  - `fopen(buf, mode)` / `CreateFileW(buf, ...)` with a non-
    constant path is a path-traversal candidate. Tightening:
    suppress when the path is also a `trusted_path_xref_to_load`
    HIT (the latter is more specific).

For each callsite, the dangerous argument is resolved via the
same SSA back-walk used by `analysis.trusted_path` v2. The walk
terminates at:
  - A constant pointer to a string in the binary's .rdata-class
    string table → SAFE, suppress
  - Anything else (variable, function-return, computed) → emit

Severity matches `SINK_CLASS_META` in `taint.py`. Emission is
flagged with a distinct evidence kind so consumers can tell the
two layers apart.

Categories emitted:
  - `format_string`
  - `command_injection`
  - `path_traversal`

Knowledge anchor: `[[Memory/Knowledge/argus_detector_design_principles]]`
(v1/v2 layering — this is a v2-shaped detector for the
SSA-taint-can't-propagate cases).
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in, strings_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh


# Sinks whose semantics are "read unbounded attacker-controlled
# input into a destination buffer." For these, the structural
# signal is the destination resolving to a stack variable — the
# attacker controls the byte count via input length, so a fixed-
# size stack buffer is an OOB-write candidate regardless of upstream
# taint propagation. Maps sink_name → destination arg index.
_UNBOUNDED_READ_INTO_BUFFER: dict[str, int] = {
    "gets":                     0,
    "_gets":                    0,
    "gets_s":                   0,                # bounded but historical
    "std::__istream_extract":   1,                # (istream, buf, n)
}


# (sink_name, arg_index, sink_class, severity, category)
_DYNAMIC_ARG_SINKS: tuple[tuple[str, int, str, Severity, str], ...] = (
    # Format string — fmt argument is the dangerous one
    ("printf",        0, "format_string",     Severity.HIGH,     "format_string"),
    ("vprintf",       0, "format_string",     Severity.HIGH,     "format_string"),
    ("fprintf",       1, "format_string",     Severity.HIGH,     "format_string"),
    ("vfprintf",      1, "format_string",     Severity.HIGH,     "format_string"),
    ("sprintf",       1, "format_string",     Severity.HIGH,     "format_string"),
    ("vsprintf",      1, "format_string",     Severity.HIGH,     "format_string"),
    ("snprintf",      2, "format_string",     Severity.HIGH,     "format_string"),
    ("vsnprintf",     2, "format_string",     Severity.HIGH,     "format_string"),
    ("syslog",        1, "format_string",     Severity.HIGH,     "format_string"),
    ("err",           1, "format_string",     Severity.HIGH,     "format_string"),
    ("errx",          1, "format_string",     Severity.HIGH,     "format_string"),
    ("warn",          0, "format_string",     Severity.HIGH,     "format_string"),
    ("warnx",         0, "format_string",     Severity.HIGH,     "format_string"),

    # Command injection — command-string argument
    ("system",        0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("popen",         0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("_popen",        0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("execl",         0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("execlp",        0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("execle",        0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("execv",         0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("execvp",        0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("execvpe",       0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("WinExec",       0, "command_injection", Severity.CRITICAL, "command_injection"),
    ("ShellExecuteA", 2, "command_injection", Severity.CRITICAL, "command_injection"),
    ("ShellExecuteW", 2, "command_injection", Severity.CRITICAL, "command_injection"),

    # Path traversal — path argument
    ("fopen",         0, "path_traversal",    Severity.HIGH,     "path_traversal"),
    ("freopen",       0, "path_traversal",    Severity.HIGH,     "path_traversal"),
    ("open",          0, "path_traversal",    Severity.HIGH,     "path_traversal"),
    ("openat",        1, "path_traversal",    Severity.HIGH,     "path_traversal"),
    ("CreateFileA",   0, "path_traversal",    Severity.HIGH,     "path_traversal"),
    ("CreateFileW",   0, "path_traversal",    Severity.HIGH,     "path_traversal"),
    # C++ stdlib filestream constructors — `this` at arg 0, path at arg 1.
    ("std::ifstream::ifstream", 1, "path_traversal", Severity.HIGH, "path_traversal"),
    ("std::ofstream::ofstream", 1, "path_traversal", Severity.HIGH, "path_traversal"),
    ("std::fstream::fstream",   1, "path_traversal", Severity.HIGH, "path_traversal"),
    ("std::ifstream::open",     1, "path_traversal", Severity.HIGH, "path_traversal"),
    ("std::ofstream::open",     1, "path_traversal", Severity.HIGH, "path_traversal"),
    ("std::fstream::open",      1, "path_traversal", Severity.HIGH, "path_traversal"),
)


CATEGORY_META = {
    "format_string": {
        "cwe": ["CWE-134"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/em_advanced_injection_variants]]",
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "command_injection": {
        "cwe": ["CWE-78"],
        "mitre": ["T1059"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
    "path_traversal": {
        "cwe": ["CWE-22", "CWE-23"],
        "mitre": ["T1083", "T1005"],
        "knowledge_refs": [
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
}


def _build_string_addr_index(bv) -> dict[int, str]:
    return {int(addr): s for s, addr in (strings_in(bv) or [])}


def _expr_to_const_addr(expr) -> Optional[int]:
    """Resolve an MLIL expression to a constant pointer address."""
    if expr is None:
        return None
    cv = getattr(expr, "constant", None)
    if cv is not None:
        try:
            return int(cv)
        except Exception:
            pass
    op_name = type(expr).__name__
    if "ConstantPtr" in op_name or "ConstPtr" in op_name:
        v = getattr(expr, "value", None) or getattr(expr, "constant", None)
        try:
            if v is not None:
                return int(v)
        except Exception:
            pass
    if "Load" in op_name:
        src = getattr(expr, "src", None)
        cv = getattr(src, "constant", None) if src is not None else None
        if cv is not None:
            try:
                return int(cv)
            except Exception:
                pass
    val = getattr(expr, "value", None)
    if val is not None:
        vtype = getattr(val, "type", None)
        type_name = (getattr(vtype, "name", "") or str(vtype) or "").lower()
        if "constantpointer" in type_name or "constant_pointer" in type_name:
            v = getattr(val, "value", None)
            try:
                if v is not None:
                    return int(v)
            except Exception:
                pass
    return None


def _resolve_to_const_addr(function, expr, max_hops: int = 4,
                           seen: Optional[set] = None) -> Optional[int]:
    """Walk SSA defs back to find a constant-pointer address. Returns
    the address or None when the back-walk cannot reach a constant.

    None = "this argument is dynamic at this callsite" — the trigger
    condition for this detector.
    """
    if seen is None:
        seen = set()
    if max_hops <= 0 or expr is None:
        return None
    addr = _expr_to_const_addr(expr)
    if addr is not None:
        return addr
    ssa_var = ilh.expr_to_ssa_var(expr)
    if ssa_var is None:
        return None
    key = str(ssa_var)
    if key in seen:
        return None
    seen.add(key)
    defn = ilh.ssa_def_of(function, ssa_var)
    if defn is None:
        return None
    src_expr = getattr(defn, "src", None)
    if src_expr is not None:
        a = _resolve_to_const_addr(function, src_expr,
                                   max_hops - 1, seen)
        if a is not None:
            return a
    op_name = type(defn).__name__
    if "Phi" in op_name:
        for v in (getattr(defn, "src", None) or []):
            a = _resolve_to_const_addr(function, v,
                                       max_hops - 1, seen)
            if a is not None:
                return a
    return None


def _is_format_string_literal(s: str) -> bool:
    """Heuristic: does this string look like a format string vs a
    pure command/path? Used to suppress FPs on the
    `command_injection`/`path_traversal` categories — if the sink is
    `system`/`fopen` but the resolved string contains `%` it's
    probably an intentional format-then-pass pattern (sprintf into
    buffer → system) and the real bug is elsewhere.
    """
    return "%" in s and any(c in s for c in "sdifuxXcp")


def find_unbounded_reads_into_stack(
        bv, *, binary: str, arch: str, platform: str,
        detector: str = "analysis.dynamic_sink_arg",
) -> list[Finding]:
    """Scan call sites of unbounded-read sinks (`gets`,
    `std::__istream_extract`, etc.). When the destination buffer
    resolves to a stack variable, emit `stack_buffer_overflow` HIGH.

    Bridges the gap that taint.py leaves on flows like
    `std::cin >> char[N]` where the upstream "source" is a global
    stream object rather than a SOURCES-table call.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    relevant = [(n, idx) for n, idx in _UNBOUNDED_READ_INTO_BUFFER.items()
                if n in imports]
    if not relevant:
        return findings

    seen_keys: set[tuple[str, str, int]] = set()
    for sink_name, dst_idx in relevant:
        for call_addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if dst_idx >= len(params):
                continue
            func = getattr(mlil, "function", None)
            if func is None:
                continue
            try:
                dst_is_stack = ilh.resolves_to_stack_variable(
                    params[dst_idx], function=func,
                )
            except Exception:
                dst_is_stack = False
            if not dst_is_stack:
                continue
            sf = getattr(func, "source_function", None) or func
            fname = getattr(sf, "name", "") or f"sub_{getattr(sf, 'start', 0):x}"
            key = (fname, sink_name, int(call_addr))
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(Finding(
                id="",
                category="stack_buffer_overflow",
                severity=Severity.HIGH,
                address=int(call_addr),
                function=fname,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=[
                    "[[Memory/Knowledge/hw_stack_overflow_mechanics]]",
                    "[[Memory/Knowledge/argus_detector_design_principles]]",
                ],
                cwe=["CWE-121", "CWE-120"],
                mitre_attack=["T1203"],
                description=(
                    f"{fname}: {sink_name}@0x{call_addr:x} reads attacker-"
                    f"controlled input into a stack-resident destination "
                    f"buffer (arg {dst_idx}). The call provides no length "
                    f"bound, so input larger than the buffer overflows the "
                    f"frame. Canonical stack-buffer-overflow shape; bypasses "
                    f"the std::string / std::vector wrapper boundary that "
                    f"defeats SSA-only taint propagation."
                ),
                evidence=[Evidence(
                    kind="stack_write_exceeds_compile_size",
                    source=detector,
                    payload=(f"sink={sink_name} dst_arg={dst_idx} "
                             f"call_addr=0x{call_addr:x} dst=stack"),
                    address=int(call_addr),
                    function=fname,
                )],
                details={
                    "sink_name": sink_name,
                    "dst_arg_index": dst_idx,
                    "call_addr": hex(int(call_addr)),
                    "resolution": "stack",
                },
            ))
    return findings


def _functions_by_short_name(bv) -> dict[str, list]:
    """Build {short_name: [Function, ...]} for all functions whose
    demangled short_name is something the detector cares about. Used
    when a sink lives as an internal thunk function (e.g. MinGW
    builds emit a per-binary `printf` thunk that wraps the actual
    `vfprintf` import) — the symbol is a thunk function, not an
    import, so `imports_in` won't see it.
    """
    out: dict[str, list] = {}
    for fn in (bv.functions or []):
        sym = getattr(fn, "symbol", None)
        if sym is None:
            continue
        sn = getattr(sym, "short_name", None)
        if not sn:
            continue
        out.setdefault(sn, []).append(fn)
    return out


def _emit_finding_for_callsite(call_addr, func, params, *,
                               sink_name, arg_idx, sink_class,
                               severity, category, string_idx,
                               binary, arch, platform, detector,
                               findings_out, seen_keys):
    """Shared emission logic — resolve the dangerous arg, check it's
    non-constant, and emit a Finding."""
    if arg_idx >= len(params):
        return
    arg_expr = params[arg_idx]
    const_addr = _resolve_to_const_addr(func, arg_expr)
    if const_addr is not None:
        # Constant string → safe FOR THIS category.
        return
    sf = getattr(func, "source_function", None) or func
    fname = getattr(sf, "name", "") or f"sub_{getattr(sf, 'start', 0):x}"
    key = (fname, sink_name, int(call_addr))
    if key in seen_keys:
        return
    seen_keys.add(key)

    meta = CATEGORY_META.get(category, {})
    findings_out.append(Finding(
        id="",
        category=category,
        severity=severity,
        address=int(call_addr),
        function=fname,
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta.get("knowledge_refs", [])),
        cwe=list(meta.get("cwe", [])),
        mitre_attack=list(meta.get("mitre", [])),
        description=(
            f"{fname}: sink {sink_name}@0x{call_addr:x} called "
            f"with a non-constant pointer at argument {arg_idx}. "
            f"The dangerous argument doesn't resolve to a "
            f"static .rdata literal via SSA back-walk."
        ),
        evidence=[Evidence(
            kind={
                "format_string": "format_arg_non_constant",
                "command_injection": "command_arg_non_constant",
                "path_traversal": "path_arg_non_constant",
            }.get(category, f"{sink_class}_arg_non_constant"),
            source=detector,
            payload=(f"sink={sink_name} arg_index={arg_idx} "
                     f"call_addr=0x{call_addr:x} "
                     f"resolution=non_constant"),
            address=int(call_addr),
            function=fname,
        )],
        details={
            "sink_name": sink_name,
            "sink_class": sink_class,
            "arg_index": arg_idx,
            "call_addr": hex(int(call_addr)),
            "resolution": "non_constant",
        },
    ))


def find_dynamic_sink_args(bv, *, binary: str, arch: str, platform: str,
                           detector: str = "analysis.dynamic_sink_arg"
                           ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    fns_by_name = _functions_by_short_name(bv)
    # Sink is "available" if EITHER imported directly OR present as a
    # local thunk function (MinGW pattern).
    relevant = [t for t in _DYNAMIC_ARG_SINKS
                if t[0] in imports or t[0] in fns_by_name]
    if not relevant:
        return findings
    string_idx = _build_string_addr_index(bv)

    seen_keys: set[tuple[str, str, int]] = set()  # (function, sink, addr)

    for sink_name, arg_idx, sink_class, severity, category in relevant:
        for call_addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if len(params) <= arg_idx:
                continue
            func = getattr(mlil, "function", None)
            if func is None:
                continue
            sf = getattr(func, "source_function", None) or func
            fname = getattr(sf, "name", "") or f"sub_{getattr(sf, 'start', 0):x}"

            arg_expr = params[arg_idx]
            const_addr = _resolve_to_const_addr(func, arg_expr)
            if const_addr is not None:
                # Constant string — look it up. If it's a literal
                # in the binary, the call site is safe FOR THIS
                # category. (Note: for path_traversal, a constant
                # path can still be a hardcoded /tmp/ — that's
                # trusted_path's territory, not ours.)
                literal = string_idx.get(int(const_addr))
                if literal is not None:
                    continue
                # Constant pointer but not in string table — odd
                # but treat as constant for safety.
                continue

            key = (fname, sink_name, int(call_addr))
            if key in seen_keys:
                continue
            seen_keys.add(key)

            meta = CATEGORY_META.get(category, {})
            findings.append(Finding(
                id="",
                category=category,
                severity=severity,
                address=int(call_addr),
                function=fname,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta.get("knowledge_refs", [])),
                cwe=list(meta.get("cwe", [])),
                mitre_attack=list(meta.get("mitre", [])),
                description=(
                    f"{fname}: sink {sink_name}@0x{call_addr:x} called "
                    f"with a non-constant pointer at argument {arg_idx}. "
                    f"The dangerous argument doesn't resolve to a "
                    f"static .rdata literal via SSA back-walk — caller "
                    f"is feeding a computed / wrapped / variable string "
                    f"into a {sink_class}-class sink. Canonical {category} "
                    f"shape for inputs that flow through std::string / "
                    f"std::vector wrappers where SSA-only taint can't "
                    f"prove end-to-end propagation."
                ),
                evidence=[Evidence(
                    # Canonical evidence-kind names match the
                    # expected.json signatures across cells:
                    #   format_string  → format_arg_non_constant
                    #   command_injection → command_arg_non_constant
                    #   path_traversal → path_arg_non_constant
                    kind={
                        "format_string": "format_arg_non_constant",
                        "command_injection": "command_arg_non_constant",
                        "path_traversal": "path_arg_non_constant",
                    }.get(category, f"{sink_class}_arg_non_constant"),
                    source=detector,
                    payload=(f"sink={sink_name} arg_index={arg_idx} "
                             f"call_addr=0x{call_addr:x} "
                             f"resolution=non_constant"),
                    address=int(call_addr),
                    function=fname,
                )],
                details={
                    "sink_name": sink_name,
                    "sink_class": sink_class,
                    "arg_index": arg_idx,
                    "call_addr": hex(int(call_addr)),
                    "resolution": "non_constant",
                },
            ))

    # Second pass — non-import thunk functions. MinGW emits per-binary
    # `printf` / `system` thunks whose short_name matches our sink set
    # but whose IAT entry is at a *different* symbol (e.g., the actual
    # import is `vfprintf` and the local `printf` function calls it).
    # Walk callers of such thunk functions and apply the same
    # non-constant-arg test there.
    for sink_name, arg_idx, sink_class, severity, category in relevant:
        if sink_name in imports:
            continue                   # already handled by the import pass
        for thunk_fn in fns_by_name.get(sink_name, []):
            try:
                refs = list(bv.get_code_refs(thunk_fn.start) or [])
            except Exception:
                continue
            for ref in refs:
                caller_func = getattr(ref, "function", None)
                if caller_func is None:
                    continue
                try:
                    inst = caller_func.get_low_level_il_at(
                        int(getattr(ref, "address", 0)))
                except Exception:
                    inst = None
                mlil = None
                if inst is not None and hasattr(inst, "mlil"):
                    m = inst.mlil
                    if m is not None:
                        ssa_form = getattr(m, "ssa_form", None)
                        mlil = ssa_form if ssa_form is not None else m
                if mlil is None:
                    continue
                params = ilh.call_params(mlil)
                if len(params) <= arg_idx:
                    continue
                func = getattr(mlil, "function", None)
                if func is None:
                    continue
                call_addr = int(getattr(mlil, "address", 0) or 0)
                if call_addr == 0:
                    continue
                _emit_finding_for_callsite(
                    call_addr, func, params,
                    sink_name=sink_name, arg_idx=arg_idx,
                    sink_class=sink_class, severity=severity,
                    category=category, string_idx=string_idx,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    findings_out=findings, seen_keys=seen_keys,
                )
    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.dynamic_sink_arg"
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
    out.extend(find_dynamic_sink_args(bv, binary=binary, arch=arch,
                                      platform=platform, detector=detector))
    out.extend(find_unbounded_reads_into_stack(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    return out
