"""Format string vulnerability detection.

Detects calls where a non-constant (user-controlled) value is passed as the
format string argument to a printf-family or kernel logging function.

Detection shape:
- For each call to a format-string sink, extract the format argument at the
  configured index.
- If the argument is a constant (numeric literal / string address in .rodata),
  the call is safe — skip it.
- Otherwise the format argument may be attacker-influenced — emit a finding.

A one-hop SSA def walk is performed on non-constant format args to capture the
taint origin (function parameter, return value, etc.) in the finding's evidence
list.

Kernel logging sinks (printk / dev_*/pr_*) are included because kernel drivers
frequently pass dev/err descriptors as the first argument, shifting the format
index to 1, and misuse is a common pattern in driver code.
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in
from ..output.finding import Finding, Severity
from . import _il_helpers as ilh
from . import mitigations as mitigations_mod


# ─────────────────────────────────────────────────────────────────
# Sink table
# ─────────────────────────────────────────────────────────────────

# (function_name) → fmt_arg_index (0-based position of the format string arg)
_FORMAT_SINKS: dict[str, int] = {
    "printf":    0,
    "fprintf":   1,   # FILE*, fmt, ...
    "sprintf":   1,   # buf, fmt, ...
    "snprintf":  2,   # buf, size, fmt, ...
    "vprintf":   0,
    "vfprintf":  1,
    "vsprintf":  1,
    "vsnprintf": 2,
    "dprintf":   1,   # fd, fmt, ...
    # Kernel logging (Linux)
    "printk":    0,
    "dev_err":   1,   # dev*, fmt, ...
    "dev_warn":  1,
    "dev_info":  1,
    "dev_dbg":   1,
    "pr_err":    0,
    "pr_warn":   0,
    "pr_info":   0,
    "pr_debug":  0,
}


def _emit_fmt(*, addr: int, function: str, binary: str, arch: str,
              platform: str, detector: str, sink_name: str,
              evidence: list[str]) -> Finding:
    return Finding(
        id="",
        category="format_string",
        severity=Severity.HIGH,
        address=addr,
        function=function,
        binary=binary,
        arch=arch,
        platform=platform,
        detector=detector,
        knowledge_refs=[],
        cwe=["CWE-134"],
        mitre_attack=[],
        evidence=evidence,
        description=f"Format string vulnerability via {sink_name} — non-constant format argument",
        details={"sink_name": sink_name},
        cia_impact=frozenset({"C", "I"}),
        detection_altitude="ttp",
    )


# ─────────────────────────────────────────────────────────────────
# Core detector
# ─────────────────────────────────────────────────────────────────


def find_format_string_bugs(bv, *, binary: str, arch: str, platform: str,
                            detector: str) -> list[Finding]:
    """Return format_string findings for the given BinaryView."""
    findings: list[Finding] = []
    imports = imports_in(bv)

    for sink_name, fmt_idx in _FORMAT_SINKS.items():
        if sink_name not in imports:
            continue
        for addr, mlil in ilh.call_sites_of_import(bv, sink_name):
            if mlil is None:
                continue
            params = ilh.call_params(mlil)
            if fmt_idx >= len(params):
                continue
            fmt_expr = params[fmt_idx]

            # Constant address → string literal in .rodata → safe
            if getattr(fmt_expr, "constant", None) is not None:
                continue

            func = getattr(mlil, "function", None)
            func_name = ilh.function_display_name(func)

            # One-hop SSA def walk — record taint origin in evidence
            evidence: list[str] = []
            ssa_var = ilh.expr_to_ssa_var(fmt_expr)
            if ssa_var is not None:
                defn = ilh.ssa_def_of(func, ssa_var)
                if defn is not None:
                    evidence.append(f"format string taint origin: {defn}")

            findings.append(_emit_fmt(
                addr=addr, function=func_name, binary=binary,
                arch=arch, platform=platform, detector=detector,
                sink_name=sink_name, evidence=evidence,
            ))

    return findings


# ─────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            score_against_mitigations: bool = True,
            detector: str = "analysis.format_string") -> list[Finding]:
    """Run format string detection against the session's BinaryView."""
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    findings = find_format_string_bugs(
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
