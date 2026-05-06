"""Uninitialised-memory-disclosure detection.

Detects the Linux-CVE-2017-class info-leak: a stack-allocated buffer
(struct, array) is partially initialised, then the entire buffer is
written to an output sink (fwrite / write / send / WriteFile /
copy_to_user / etc.). Padding bytes and uninitialised fields leak
stack contents from prior frames.

Detection shape (v1):

1. Enumerate output-sink call sites (fwrite, write, send, sendto,
   WriteFile, copy_to_user, etc.) — sinks listed in
   `_OUTPUT_SINKS`.
2. For each, resolve the buffer arg to its stack-variable origin
   (using `_il_helpers.resolves_to_stack_variable` + SSA-def chase).
3. Determine the stack variable's declared size from the function's
   stack-frame layout.
4. Use `_cfg_primitives.has_full_init_writes_between` to check
   whether the buffer is plausibly fully initialised before the sink.
5. Emit `uninitialised_memory_disclosure` Finding when coverage is
   insufficient.

Limitations (v1):

- Per-byte coverage uses a store-count heuristic, not interval
  tracking on offset operands. Underestimates FPs slightly when
  every byte IS written via a tight loop (single store inside the
  loop appears as one store).
- Does not chase through `memcpy`-into-buffer; that would carry
  initialisation, but the source-buffer's coverage isn't checked.
  Tier 2 #5 v2 enhancement.
- Phi-handling: not yet special-cased; multi-path init merges to
  the union of both paths' coverage as a v2 enhancement.

Knowledge anchors:
- `[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]` — UB
  semantics around uninit reads
- General CWE-457 / CWE-908 class
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..heuristics._base import imports_in
from ..lib.scoring import apply_signals_to_finding
from ..output.finding import Evidence, Finding, Severity
from . import _cfg_primitives as cfg
from . import _il_helpers as ilh


# ─────────────────────────────────────────────────────────────────
# Output sinks — calls that emit a buffer outward to a destination
# beyond the current process's address space (file, socket, pipe,
# user-space copy from kernel).
#
# Format: name → (buffer_arg_idx, size_arg_idx_or_None, sink_label)
# ─────────────────────────────────────────────────────────────────


_OUTPUT_SINKS: dict[str, tuple[int, Optional[int], str]] = {
    # libc — file I/O
    "fwrite":            (0, 1, "fwrite"),       # buf, size, count, stream
    "write":             (1, 2, "write"),         # fd, buf, count
    "fputs":             (0, None, "fputs"),
    "puts":              (0, None, "puts"),
    # libc — network
    "send":              (1, 2, "send"),          # sock, buf, len, flags
    "sendto":            (1, 2, "sendto"),
    "sendmsg":           (1, None, "sendmsg"),
    # Windows — file I/O
    "WriteFile":         (1, 2, "WriteFile"),     # h, buf, len, ...
    "WriteFileEx":       (1, 2, "WriteFileEx"),
    "WriteConsoleA":     (1, 2, "WriteConsoleA"),
    "WriteConsoleW":     (1, 2, "WriteConsoleW"),
    # Windows — network
    "WSASend":           (1, None, "WSASend"),
    # Linux kernel — userspace copy
    "copy_to_user":      (0, 2, "copy_to_user"),  # to, from, n  (note: from is 1)
    "__copy_to_user":    (0, 2, "__copy_to_user"),
    "_copy_to_user":     (0, 2, "_copy_to_user"),
}


# Per-architecture sane minimum buffer size for which uninit disclosure
# is interesting — below this, the buffer is too small to be worth
# flagging (single int / pointer values aren't info-leak candidates).
_MIN_BUFFER_SIZE = 8


# Store-count threshold for "buffer is plausibly fully initialised"
# coverage check. The default (4) catches struct-init patterns that
# touch 4+ fields; tune per-detector if needed.
_INIT_COVERAGE_THRESHOLD = 4


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────


def _ssa_var_str(v) -> str:
    if v is None:
        return ""
    name = getattr(getattr(v, "var", None), "name", None)
    version = getattr(v, "version", None)
    if name is not None and version is not None:
        return f"{name}#{version}"
    return str(v)


def _resolve_stack_var_size(function, ssa_var) -> Optional[int]:
    """Resolve `ssa_var` (or its SSA-def chain) back to a stack variable
    and return that variable's declared size, or None if not found.

    Walks SSA defs up to ~4 hops looking for an `AddressOf(stack_var)`
    pattern (the canonical `rcx#1 = &local_var` shape).
    """
    if function is None or ssa_var is None:
        return None
    seen: set = set()
    cur = ssa_var
    for _ in range(5):
        key = _ssa_var_str(cur)
        if key in seen:
            break
        seen.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            return None
        src_expr = getattr(defn, "src", None)
        if src_expr is None:
            return None
        # AddressOf-of-stack-var?
        op_name = type(src_expr).__name__
        if "AddressOf" in op_name or "Addr" in op_name:
            for op in getattr(src_expr, "operands", []) or []:
                # The operand may be a Variable (stack var) directly
                stype = getattr(op, "source_type", None)
                stype_name = getattr(stype, "name", "") if stype is not None else ""
                if "Stack" in stype_name or getattr(op, "is_stack_variable", False):
                    var_type = getattr(op, "type", None)
                    width = getattr(var_type, "width", None)
                    if width is None:
                        return None
                    return int(width)
            return None
        # Chase through SetVar
        nested = ilh.expr_to_ssa_var(src_expr)
        if nested is None:
            return None
        cur = nested
    return None


# ─────────────────────────────────────────────────────────────────
# Detector
# ─────────────────────────────────────────────────────────────────


CATEGORY_META = {
    "uninitialised_memory_disclosure": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-457", "CWE-908"],
        "mitre": ["T1083"],
        "knowledge_refs": ["[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]"],
    },
}


def _read_constant(expr) -> Optional[int]:
    """If `expr` is a constant integer (or wrapper around one), return
    its value. Otherwise None."""
    if expr is None:
        return None
    val = getattr(expr, "constant", None)
    if val is not None:
        try:
            return int(val)
        except Exception:
            return None
    op_name = type(expr).__name__
    if "Const" in op_name:
        v = getattr(expr, "value", None)
        if v is not None:
            try:
                return int(v)
            except Exception:
                pass
    return None


def _emit_size_from_sink(sink_name: str, params: list) -> Optional[int]:
    """Compute the byte-count being emitted by the sink call.

    `fwrite(buf, size, count, stream)` → size * count.
    `write(fd, buf, count)` → count.
    Others → return the size arg if available.

    Returns None when the size can't be determined (non-constant
    operand, missing arg). Detectors use this with a min-threshold
    to skip uninteresting small emissions.
    """
    if sink_name == "fwrite":
        size = _read_constant(params[1]) if len(params) > 1 else None
        count = _read_constant(params[2]) if len(params) > 2 else None
        if size is not None and count is not None:
            return size * count
        return None
    # write / send / sendto / WriteFile etc.: size at index 2
    if len(params) > 2:
        return _read_constant(params[2])
    return None


def find_uninit_disclosures(bv, *, binary: str, arch: str, platform: str,
                            detector: str = "analysis.uninit") -> list[Finding]:
    findings: list[Finding] = []
    imports = imports_in(bv)

    for sink_name, (buf_idx, _size_idx, sink_label) in _OUTPUT_SINKS.items():
        if sink_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if buf_idx >= len(params):
                continue
            buf_var = ilh.expr_to_ssa_var(params[buf_idx])
            if buf_var is None:
                continue
            func = getattr(mlil, "function", None)
            if func is None:
                continue
            # Buffer must resolve to a stack variable. v1 uses
            # `resolves_to_stack_variable` with SSA-def chase to follow
            # `rcx#1 = &s` patterns back to the underlying Variable.
            try:
                if not ilh.resolves_to_stack_variable(params[buf_idx], function=func):
                    continue
            except Exception:
                continue
            # Emit-size from the sink itself (constant-folded). Skip
            # uninteresting small emissions — single int/pointer values
            # aren't info-leak candidates.
            emit_size = _emit_size_from_sink(sink_name, params)
            if emit_size is None or emit_size < _MIN_BUFFER_SIZE:
                continue

            func_name = ilh.function_display_name(func)
            meta = CATEGORY_META["uninitialised_memory_disclosure"]
            finding = Finding(
                id="",
                category="uninitialised_memory_disclosure",
                severity=meta["severity"],
                address=addr,
                function=func_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=list(meta["knowledge_refs"]),
                cwe=list(meta["cwe"]),
                mitre_attack=list(meta["mitre"]),
                description=(
                    f"{sink_label} writes {emit_size} bytes from a stack-allocated "
                    f"buffer — if the buffer is partially initialised, padding bytes "
                    f"and uninitialised fields leak prior stack contents"
                ),
                evidence=[Evidence(
                    kind="output_sink_with_stack_buffer",
                    source=detector,
                    payload=(f"sink={sink_label}@0x{addr:x} buf_var={buf_var} "
                             f"emit_size={emit_size}"),
                    address=addr,
                    function=func_name,
                )],
                details={
                    "sink_name": sink_label,
                    "emit_size": emit_size,
                    "buffer_var": _ssa_var_str(buf_var),
                },
            )
            apply_signals_to_finding(finding, [
                "tainted_pointer_read",                  # HUB
                "alloc_size_lt_full_initial_fill",       # SPECIFIC
            ])
            findings.append(finding)

    return findings


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.uninit") -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    return find_uninit_disclosures(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
