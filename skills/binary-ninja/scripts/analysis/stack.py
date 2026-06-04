"""Stack buffer overflow detection.

Detects cases where a copy function writes into a stack-allocated buffer
with an unbounded or non-constant length argument.

Two detection shapes:

- **Unbounded sinks** (`gets`, sprintf family): any call with a stack-
  allocated destination is flagged — there is no safe use of these with
  a stack buffer.

- **Bounded sinks** (memcpy, strcpy, read, recv, ...): flagged when:
  - there is no length argument (strcpy, strcat), OR
  - the length argument is not a statically-known small constant.

The destination check uses `ilh.resolves_to_stack_variable()` to confirm
the destination SSA variable lives on the stack.
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in
from ..output.finding import Finding, Severity
from . import _il_helpers as ilh
from . import mitigations as mitigations_mod


# ─────────────────────────────────────────────────────────────────
# Sink tables
# ─────────────────────────────────────────────────────────────────

# Functions with no effective length bound — any stack destination is a finding.
_UNBOUNDED_SINKS: frozenset[str] = frozenset({
    "gets", "_gets",
    "sprintf", "vsprintf", "wsprintf", "vswprintf", "swprintf",
})

# (function_name) → (dst_arg_index, len_arg_index_or_None)
# dst_arg_index: position of the destination buffer parameter (0-based)
# len_arg_index: position of the length/count argument, or None if absent
_BOUNDED_SINKS: dict[str, tuple[int, Optional[int]]] = {
    "strcpy":    (0, None),    # no length arg
    "strcat":    (0, None),
    "wcscpy":    (0, None),
    "wcscat":    (0, None),
    "lstrcpyA":  (0, None),
    "lstrcpyW":  (0, None),
    "lstrcatA":  (0, None),
    "lstrcatW":  (0, None),
    "memcpy":    (0, 2),       # dst, src, len
    "memmove":   (0, 2),
    "bcopy":     (1, 2),       # src, dst, len
    "strncpy":   (0, 2),
    "strncat":   (0, 2),
    "wcsncpy":   (0, 2),
    "wcsncat":   (0, 2),
    "snprintf":  (0, 1),       # dst, size, fmt, ...
    "vsnprintf": (0, 1),
    "read":      (1, 2),       # fd, buf, count
    "recv":      (1, 2),       # sockfd, buf, len, flags
    "fgets":     (0, 1),       # str, num, stream
}

# Stack buffer size threshold: constants ≤ this are treated as safe
# (assumption: the programmer sized the buffer correctly for a literal).
_SAFE_CONSTANT_THRESHOLD = 4096

_CRT_NAME_PREFIXES: tuple[str, ...] = (
    "__mingw_", "___w64_", "___main",
    "__scrt_", "__report_", "__crt_", "__chkstk",
    "_register_onexit", "_initialize_", "_initterm",
)


def _is_crt_internal(func_name: str) -> bool:
    if not func_name:
        return False
    for prefix in _CRT_NAME_PREFIXES:
        if func_name.startswith(prefix):
            return True
    return False


def _emit_stack_of(*, addr: int, function: str, binary: str, arch: str,
                   platform: str, detector: str, sink_name: str,
                   description_extra: str = "") -> Finding:
    desc = f"Stack buffer overflow via {sink_name}"
    if description_extra:
        desc = f"{desc} — {description_extra}"
    return Finding(
        id="",
        category="stack_buffer_overflow",
        severity=Severity.HIGH,
        address=addr,
        function=function,
        binary=binary,
        arch=arch,
        platform=platform,
        detector=detector,
        knowledge_refs=[],
        cwe=["CWE-121"],
        mitre_attack=[],
        evidence=[],
        description=desc,
        details={"sink_name": sink_name},
        cia_impact=frozenset({"I"}),
        detection_altitude="ttp",
    )


# ─────────────────────────────────────────────────────────────────
# Core detector
# ─────────────────────────────────────────────────────────────────


def find_stack_overflow(bv, *, binary: str, arch: str, platform: str,
                        detector: str) -> list[Finding]:
    """Return stack_buffer_overflow findings for the given BinaryView."""
    findings: list[Finding] = []
    imports = imports_in(bv)

    # ── Unbounded sinks ──────────────────────────────────────────
    for sink_name in _UNBOUNDED_SINKS:
        if sink_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if not params:
                continue
            dst_var = ilh.expr_to_ssa_var(params[0])
            if dst_var is None:
                continue
            func = getattr(mlil, "function", None)
            func_name = ilh.function_display_name(func)
            if _is_crt_internal(func_name):
                continue
            if not ilh.resolves_to_stack_variable(func, dst_var):
                continue
            findings.append(_emit_stack_of(
                addr=addr, function=func_name, binary=binary,
                arch=arch, platform=platform, detector=detector,
                sink_name=sink_name,
            ))

    # ── Bounded sinks ────────────────────────────────────────────
    for sink_name, (dst_idx, len_idx) in _BOUNDED_SINKS.items():
        if sink_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if dst_idx >= len(params):
                continue
            dst_var = ilh.expr_to_ssa_var(params[dst_idx])
            if dst_var is None:
                continue
            func = getattr(mlil, "function", None)
            func_name = ilh.function_display_name(func)
            if _is_crt_internal(func_name):
                continue
            if not ilh.resolves_to_stack_variable(func, dst_var):
                continue

            # No length arg (strcpy, strcat) → flag unconditionally
            if len_idx is None:
                findings.append(_emit_stack_of(
                    addr=addr, function=func_name, binary=binary,
                    arch=arch, platform=platform, detector=detector,
                    sink_name=sink_name,
                    description_extra="no length argument",
                ))
                continue

            # Length arg absent at this call site
            if len_idx >= len(params):
                findings.append(_emit_stack_of(
                    addr=addr, function=func_name, binary=binary,
                    arch=arch, platform=platform, detector=detector,
                    sink_name=sink_name,
                    description_extra="length argument missing at call site",
                ))
                continue

            # Known small constant → probably safe; skip
            len_expr = params[len_idx]
            const_val = getattr(len_expr, "constant", None)
            if const_val is not None:
                try:
                    if int(const_val) <= _SAFE_CONSTANT_THRESHOLD:
                        continue
                except (TypeError, ValueError):
                    pass

            # Non-constant or large constant length → candidate
            findings.append(_emit_stack_of(
                addr=addr, function=func_name, binary=binary,
                arch=arch, platform=platform, detector=detector,
                sink_name=sink_name,
                description_extra="non-constant or large length argument",
            ))

    return findings


# ─────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            score_against_mitigations: bool = True,
            detector: str = "analysis.stack") -> list[Finding]:
    """Run stack overflow detection against the session's BinaryView."""
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    findings = find_stack_overflow(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
    if score_against_mitigations and findings:
        mit = mitigations_mod.detect(bv)
        for f in findings:
            try:
                from ..lib.scoring import apply_signals_to_finding
                apply_signals_to_finding(f, mit)
            except Exception:
                pass
    return findings
