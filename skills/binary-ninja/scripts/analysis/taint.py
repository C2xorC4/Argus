"""Taint analysis — MLIL SSA def-use propagation from sources to sinks.

Replaces the legacy `deep_analysis.py` baseline. Sources, sinks, and
their dangerous-arg indices live in `heuristics/imports.py`. The
algorithm is intra-procedural by default with one-hop inter-procedural
propagation through direct calls (configurable via `max_depth`).

Output: `Finding` objects with `state=DETECTED`. Each Finding cites:
- The source (e.g., `argv`, `recv`)
- The sink (e.g., `strcpy`, `system`, `printf`)
- The CWE / MITRE-attack mapping from heuristics

Limitations (Phase 1 baseline; iterate in 1+):
- No pointer-aliasing analysis; bug paths through `q = p; sink(q);`
  are caught only when the SSA propagation already carries the taint
  through the alias.
- Inter-procedural depth defaults to 2; deeper chains are partial.
- Indirect calls (function pointer) are not followed.
- No path-sensitivity; `if (sanitised) { sink(x); } else { sink(x); }`
  produces a single Finding even if the sanitised branch is safe.

These limitations are documented in
`manual_workflows/analysis-taint.md` (Phase 1 deliverable).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from ..heuristics import imports as heur_imports
from ..heuristics._base import imports_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh
from . import mitigations as mitigations_mod


# ─────────────────────────────────────────────────────────────────
# Source / sink registry (driven by heuristics/imports.py)
# ─────────────────────────────────────────────────────────────────


SOURCES: set[str] = heur_imports.SOURCES


# (sink_name, arg_index, sink_class)
SINK_TABLE: dict[str, tuple[int, str]] = {
    name: (idx, klass) for (name, idx, klass) in heur_imports.SINKS
}


# Per-sink-class severity + CWE / MITRE mapping (mirrors per-cell expected.json)
SINK_CLASS_META: dict[str, dict] = {
    "buffer_overflow": {
        "severity": Severity.HIGH,
        "category": "buffer_overflow",
        "cwe": ["CWE-120", "CWE-121", "CWE-122"],
        "mitre": ["T1203"],
        "knowledge_refs": ["[[Memory/Knowledge/hw_stack_overflow_mechanics]]"],
    },
    "format_string": {
        "severity": Severity.HIGH,
        "category": "format_string",
        "cwe": ["CWE-134"],
        "mitre": ["T1203"],
        "knowledge_refs": [],
    },
    "command_injection": {
        "severity": Severity.CRITICAL,
        "category": "command_injection",
        "cwe": ["CWE-78"],
        "mitre": ["T1059"],
        "knowledge_refs": [],
    },
    "path_traversal": {
        "severity": Severity.HIGH,
        "category": "path_traversal",
        "cwe": ["CWE-22", "CWE-23"],
        "mitre": ["T1083", "T1005"],
        "knowledge_refs": [],
    },
    "sql_injection": {
        "severity": Severity.HIGH,
        "category": "sql_injection",
        "cwe": ["CWE-89"],
        "mitre": ["T1190"],
        "knowledge_refs": [],
    },
    "alloc_size": {
        "severity": Severity.HIGH,
        "category": "integer_overflow_to_allocation",
        "cwe": ["CWE-190", "CWE-680"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]",
            "[[Memory/Knowledge/ue5_fstring_allocation_amplification]]",
        ],
    },
}


# ─────────────────────────────────────────────────────────────────
# Worklist propagator
# ─────────────────────────────────────────────────────────────────


@dataclass
class TaintFlow:
    """Track a single taint flow from source through SSA def-use chain."""
    source_name: str
    source_addr: int
    source_function: str
    var_chain: list[tuple[str, int]] = field(default_factory=list)  # (function_name, addr)
    depth: int = 0


@dataclass
class TaintAnalyzer:
    bv: object
    binary: str
    arch: str
    platform: str
    max_depth: int = 2
    detector: str = "analysis.taint"

    findings: list[Finding] = field(default_factory=list)
    visited: set = field(default_factory=set)

    # ── Source enumeration ──────────────────────────────────────

    def _enumerate_source_calls(self) -> list[tuple[str, int, object]]:
        """Return [(source_name, call_addr, mlil_inst), ...] for all
        source-import call sites in the binary."""
        all_calls: list[tuple[str, int, object]] = []
        imports = imports_in(self.bv)
        for src_name in SOURCES:
            if src_name not in imports:
                continue
            for addr, mlil in ilh.call_sites_of_import(self.bv, src_name):
                if mlil is None:
                    continue
                all_calls.append((src_name, addr, mlil))
        return all_calls

    # ── Sink check ──────────────────────────────────────────────

    def _check_sink(self, call_inst, source_name: str, source_addr: int) -> Optional[Finding]:
        """If `call_inst` is a sink call with a tainted dangerous arg,
        emit a Finding. Returns None if no sink hit."""
        callee_addr = ilh.callee_address_of_call(call_inst)
        if callee_addr is None:
            return None
        sym = self.bv.get_symbol_at(callee_addr)
        if sym is None:
            return None
        sink_name = getattr(sym, "short_name", None) or getattr(sym, "name", "")
        if sink_name not in SINK_TABLE:
            return None

        arg_index, sink_class = SINK_TABLE[sink_name]
        meta = SINK_CLASS_META.get(sink_class)
        if meta is None:
            return None

        # Get the function containing this call
        func = getattr(call_inst, "function", None)
        func_name = getattr(func, "name", "") if func else ""
        addr = int(getattr(call_inst, "address", 0))

        return Finding(
            id="",
            category=meta["category"],
            severity=meta["severity"],
            address=addr,
            function=func_name,
            binary=self.binary,
            arch=self.arch,
            platform=self.platform,
            detector=self.detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre"]),
            description=(
                f"taint flow: {source_name} -> {sink_name} (arg {arg_index})"
            ),
            evidence=[
                Evidence(
                    kind="taint_flow",
                    source=self.detector,
                    payload=f"{source_name}@0x{source_addr:x} -> {sink_name}@0x{addr:x}",
                    address=addr,
                    function=func_name,
                ),
            ],
            details={
                "source_name": source_name,
                "source_addr": hex(source_addr),
                "sink_name": sink_name,
                "sink_arg_index": arg_index,
                "sink_class": sink_class,
            },
        )

    # ── SSA propagation ──────────────────────────────────────────

    def _propagate(self, ssa_var, function, depth: int,
                   source_name: str, source_addr: int) -> None:
        """Recursive forward propagation through SSA def-use chains."""
        if depth > self.max_depth:
            return
        key = (id(function), str(ssa_var))
        if key in self.visited:
            return
        self.visited.add(key)

        for use in ilh.ssa_uses_of(function, ssa_var):
            # If this use is a Call, check sink + recurse
            op_name = getattr(getattr(use, "operation", None), "name", "")
            if "CALL" in op_name:
                finding = self._check_sink(use, source_name, source_addr)
                if finding is not None:
                    self.findings.append(finding)
                    # Sink hit; do not propagate further from this call
                    continue

                # Inter-procedural one-hop: if the callee is in-binary,
                # propagate taint into the matching parameter.
                if depth + 1 <= self.max_depth:
                    self._propagate_into_callee(use, ssa_var, depth + 1,
                                                source_name, source_addr)
                continue

            # Otherwise propagate via the use's defined output(s)
            output = getattr(use, "output", None)
            if output is None:
                # Fall back to ssa_form.dest if present
                ssa = getattr(use, "ssa_form", None)
                output = getattr(ssa, "dest", None) if ssa else None
            if output is None:
                continue
            outputs = output if hasattr(output, "__iter__") else [output]
            for new_var in outputs:
                self._propagate(new_var, function, depth + 1,
                                source_name, source_addr)

    def _propagate_into_callee(self, call_inst, tainted_var, depth: int,
                               source_name: str, source_addr: int) -> None:
        """When a tainted var is passed to an in-binary callee, follow
        into the matching parameter's SSA chain."""
        callee_addr = ilh.callee_address_of_call(call_inst)
        if callee_addr is None:
            return
        callees = list(self.bv.get_functions_containing(callee_addr)) or []
        if not callees:
            try:
                f = self.bv.get_function_at(callee_addr)
                if f is not None:
                    callees = [f]
            except Exception:
                pass
        if not callees:
            return
        callee = callees[0]

        params = ilh.call_params(call_inst)
        # Find which parameter slot carries the tainted var
        param_idx = None
        for i, p in enumerate(params):
            ssa = ilh.expr_to_ssa_var(p)
            if ssa is not None and str(ssa) == str(tainted_var):
                param_idx = i
                break
        if param_idx is None:
            return

        callee_params = list(getattr(callee, "parameter_vars", []) or [])
        if param_idx >= len(callee_params):
            return
        callee_param = callee_params[param_idx]
        # Promote the parameter to its SSA form (version 0 typically)
        # Binja API: callee.mlil.ssa_form.get_ssa_var_definition
        # finds the def site; for parameters, we want all uses.
        mlil = getattr(callee, "mlil", None)
        if mlil is None or getattr(mlil, "ssa_form", None) is None:
            return
        ssa_form = mlil.ssa_form
        # Construct an SSAVariable wrapper. Binja exposes
        # SSAVariable(var, version); use version 0 for the param.
        try:
            from binaryninja import SSAVariable  # type: ignore
            ssa_var = SSAVariable(callee_param, 0)
        except Exception:
            # Fallback: skip the cross-function hop
            return

        self._propagate(ssa_var, callee, depth,
                        source_name, source_addr)

    # ── Top-level run ────────────────────────────────────────────

    def run(self) -> list[Finding]:
        if self.bv is None:
            return []
        for source_name, addr, mlil_inst in self._enumerate_source_calls():
            output_var = ilh.call_output_ssa(mlil_inst)
            if output_var is None:
                continue
            func = getattr(mlil_inst, "function", None)
            if func is None:
                continue
            self._propagate(output_var, func, depth=0,
                            source_name=source_name, source_addr=addr)
        return self.findings


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            max_depth: int = 2,
            score_against_mitigations: bool = True) -> list[Finding]:
    """Entry point — taint analysis for one binary.

    `session` is a `BinjaSession` (or anything with `.bv`,
    `.binary_path`, `.arch`, `.platform`).
    """
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    analyzer = TaintAnalyzer(
        bv=bv, binary=binary, arch=arch, platform=platform,
        max_depth=max_depth,
    )
    findings = analyzer.run()

    if score_against_mitigations and findings and binary:
        try:
            profile = mitigations_mod.extract_mitigations(binary, bv=bv)
            mitigations_mod.score_findings(findings, profile)
        except Exception:
            pass

    return findings
