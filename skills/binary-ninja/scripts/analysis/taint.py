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
from ..lib.scoring import apply_signals_to_finding
from ..output.finding import Evidence, Finding, Severity
from . import _cfg_primitives as cfg
from . import _il_helpers as ilh
from . import mitigations as mitigations_mod


# ─────────────────────────────────────────────────────────────────
# Sink-class → signal mapping
# ─────────────────────────────────────────────────────────────────
#
# Each sink class declares the signals that anchor its findings.
# Detectors call `apply_signals_to_finding` after constructing the
# Finding to compute fan-discount-aware confidence. Sink classes not
# listed here fall back to neutral confidence (0.5).
#
# Some sink classes additionally augment their signals based on CFG
# context (see `_augment_signals_for_sink` below) — e.g., the
# integer-OF class adds a SPECIFIC `missing_alloc_size_guard_dominator`
# signal when no comparison on the tainted size dominates the alloc
# call site. This is the daydream-surfaced design choice for Tier 2
# #2: detect the *absence* of the guard, not the *presence* of the
# overflow expression — compilers can dead-code-eliminate the
# present-but-redundant guard under signed-OF UB.
#
# As Tier 2 detectors are rebuilt with their own substrate (stack.py,
# types.py, race.py), the signal mappings here will move to those
# modules and become richer (per-finding signal sets, not per-sink-
# class).

_SINK_CLASS_SIGNALS: dict[str, tuple[str, ...]] = {
    "format_string":    ("tainted_format_arg",),
    "alloc_size":       ("tainted_size_arg",),         # HUB; specific added below
    "buffer_overflow":  ("tainted_pointer_write",),    # HUB; specific added below
}


# Unbounded copy-class sinks — strcpy/strcat/sprintf-family. Bounded
# copies (memcpy/strncpy/snprintf with explicit length) are NOT in
# this set; they get HUB only unless len-arg analysis proves the
# write size is uncontrolled.
_UNBOUNDED_COPY_SINKS: frozenset[str] = frozenset({
    "strcpy", "stpcpy", "strcat",
    "wcscpy", "wcscat",
    "lstrcpyA", "lstrcpyW", "lstrcatA", "lstrcatW",
    "sprintf", "vsprintf",
})


def _cpp_stdlib_propagator_for_name(name: str) -> Optional[list[tuple[int, int]]]:
    """Pattern-match a callee's demangled short_name against known
    C++ stdlib propagators; return `[(src_arg_idx, dst_arg_idx), ...]`
    or None.

    Covers std::basic_string ctor from const char* (taint flows arg 1
    → arg 0 = this) and std::vector ctor from range. Template
    parameters in the demangled name are tolerated.

    Limitation — memory-region taint not modelled. The propagator
    marks the this-ptr SSA var as tainted, but for std::string-
    mediated flows the taint is in the *memory* the this-ptr
    addresses (the string's internal buffer), not in the SSA var.
    Subsequent code that takes a fresh `&stack_var` to load from the
    same memory gets a fresh SSA var — taint doesn't transfer. End-
    to-end propagation through `std::string ctor → log_message(...)
    → c_str() → printf(...)` requires stack-region taint, which is
    a v3-class enhancement beyond simple propagator tables.

    Concretely: this propagator fires correctly when the tainted
    value is consumed directly (e.g., `size_t n = strtoull(argv[1])`
    flowing into a C++ `alloc_records(n)` — integer-overflow/cpp
    case works). It does NOT fire end-to-end when taint must flow
    through a constructed std::string object. The format-string,
    stack-overflow, heap-overflow cpp variants need memory-region
    taint to propagate through the wrapper.

    SSO is orthogonal — Small String Optimization (MSVC: 15 chars
    inline) doesn't matter for SSA-level taint; the issue is the
    same regardless of storage.
    """
    if not name:
        return None
    # Itanium / GCC / Clang demangled forms
    if "string::string" in name or "string<std::allocator" in name:
        return [(1, 0)]
    if "::basic_string" in name and ("basic_string<" in name or "::basic_string(" in name):
        return [(1, 0)]
    if ("std::vector" in name or "vector<" in name) and "::vector" in name:
        return [(1, 0)]
    return None


def _augment_signals_for_sink(signals: list[str], *,
                              sink_class: str, sink_name: str,
                              function, call_addr: int,
                              tainted_var, call_inst) -> list[str]:
    """Per-class CFG-aware signal augmentation.

    Returns a (possibly extended) signal list. Mutates nothing.

    Per-class augmentations:

    - `alloc_size` (integer-OF): add `missing_alloc_size_guard_dominator`
      when no comparison on the tainted SSA size variable dominates the
      alloc site. Per the daydream-surfaced lesson +
      `ec_undefined_behavior_taxonomy`: GCC/Clang/MSVC can dead-code-
      eliminate present-but-redundant guards under signed-OF UB, so the
      load-bearing signal is the *absence* of a dominating comparison.

    - `buffer_overflow` (stack-OF): add `stack_write_exceeds_compile_size`
      when the destination resolves to a stack variable AND the sink is
      an unbounded copy (strcpy/strcat/sprintf-family). Add
      `leaf_redzone_use_with_tainted_offset` when the function is a
      leaf using the SysV 128-byte red zone — invisible to detectors
      keyed on `sub rsp, N` alone.
    """
    augmented = list(signals)

    if sink_class == "alloc_size":
        try:
            has_guard = cfg.has_dominating_comparison_on(
                function, call_addr, tainted_var,
            )
        except Exception:
            has_guard = True              # fail-safe: don't false-flag on errors
        if not has_guard:
            augmented.append("missing_alloc_size_guard_dominator")

    elif sink_class == "buffer_overflow":
        # Inspect destination (params[0] for these sinks). Pass
        # function context so the helper can chase SSA defs back to
        # the stack-variable origin (call sites typically pass
        # register-form SSA vars like `rcx#N`, not the stack var
        # directly).
        params = ilh.call_params(call_inst)
        dst_is_stack = False
        if params:
            try:
                dst_is_stack = ilh.resolves_to_stack_variable(
                    params[0], function=function,
                )
            except Exception:
                dst_is_stack = False
        # Only fire SPECIFIC for unbounded copies — bounded ones
        # (memcpy/strncpy/etc.) require additional len-arg analysis to
        # cleanly establish overflow potential.
        if dst_is_stack and sink_name in _UNBOUNDED_COPY_SINKS:
            augmented.append("stack_write_exceeds_compile_size")
        # Red-zone leaf — independent SPECIFIC.
        try:
            if dst_is_stack and ilh.function_uses_red_zone(function):
                augmented.append("leaf_redzone_use_with_tainted_offset")
        except Exception:
            pass

    return augmented


def _dst_resolves_to_heap_alloc(call_inst, function) -> bool:
    """True if the destination arg (params[0]) of a buffer_overflow
    sink resolves to a heap allocation — i.e. the SSA-def chain of
    the dst SSA var reaches a Call to malloc / calloc / realloc /
    HeapAlloc / VirtualAlloc / operator new. Used to re-categorise
    `stack_buffer_overflow` to `heap_buffer_overflow` when the
    underlying buffer is heap-allocated.
    """
    if call_inst is None or function is None:
        return False
    bv = getattr(function, "view", None) or getattr(function, "_view", None)
    if bv is None:
        src = getattr(function, "source_function", None)
        if src is not None:
            bv = getattr(src, "view", None)
    if bv is None:
        return False
    params = ilh.call_params(call_inst)
    if not params:
        return False
    dst_var = ilh.expr_to_ssa_var(params[0])
    if dst_var is None:
        return False
    # SSA-def chase up to 5 hops looking for an alloc-class call
    seen: set = set()
    cur = dst_var
    alloc_names = {"malloc", "calloc", "realloc",
                   "HeapAlloc", "VirtualAlloc", "_malloc_base",
                   "operator new", "operator new[]",
                   "ExAllocatePool", "ExAllocatePoolWithTag"}
    for _ in range(6):
        if cur is None:
            return False
        key = str(cur)
        if key in seen:
            return False
        seen.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            return False
        # Is the def itself a Call to an alloc?
        op_name = type(defn).__name__
        if "Call" in op_name:
            cval = getattr(getattr(defn, "dest", None), "constant", None)
            if cval is not None:
                sym = bv.get_symbol_at(int(cval))
                if sym is not None:
                    cname = (getattr(sym, "short_name", None) or sym.name or "")
                    if cname in alloc_names:
                        return True
            return False
        src_expr = getattr(defn, "src", None)
        if src_expr is None:
            return False
        # Embedded Call?
        if "Call" in type(src_expr).__name__:
            cval = getattr(getattr(src_expr, "dest", None), "constant", None)
            if cval is not None:
                sym = bv.get_symbol_at(int(cval))
                if sym is not None:
                    cname = (getattr(sym, "short_name", None) or sym.name or "")
                    if cname in alloc_names:
                        return True
        nested = ilh.expr_to_ssa_var(src_expr)
        if nested is None:
            return False
        cur = nested
    return False


# ─────────────────────────────────────────────────────────────────
# Source / sink registry (driven by heuristics/imports.py)
# ─────────────────────────────────────────────────────────────────


SOURCES: set[str] = heur_imports.SOURCES


# (sink_name, arg_index, sink_class)
SINK_TABLE: dict[str, tuple[int, str]] = {
    name: (idx, klass) for (name, idx, klass) in heur_imports.SINKS
}


# Propagator functions — write taint from source-arg(s) into a
# destination buffer. When taint flows into the source-arg slot of
# one of these calls, the destination-arg buffer becomes tainted
# and propagation continues from the destination.
#
# Format: callee_name -> [(source_arg_idx, dest_arg_idx), ...]
#
# C++ stdlib propagators are NOT in this table — their demangled names
# contain template parameters that vary per instantiation. They're
# matched at lookup time by `_cpp_stdlib_propagator_for_name` below.
# That helper handles std::basic_string ctor, std::vector ctor, the
# `c_str()` / `data()` accessors (call-return transit; subsumed by
# the generic mechanism), and equivalent MSVC-mangled forms.
#
# SSO note (per Run-19 daydream): MSVC's Small String Optimization
# stores up to 15 characters inline in the std::string struct (no
# heap pointer involved). Tainted const-char* into ctor + SSO path
# means the tainted bytes live at a fixed struct offset — load-from-
# struct-field propagation already covered by the existing E4 deref
# detection (load-via-tainted-base). Explicit SSO modelling not
# required for this propagator; the taint reaches the buffer either
# way.
PROPAGATORS: dict[str, list[tuple[int, int]]] = {
    # libc memory copies / printf-into-buffer
    "memcpy":     [(1, 0)],
    "memmove":    [(1, 0)],
    "strcpy":     [(1, 0)],
    "stpcpy":     [(1, 0)],
    "strncpy":    [(1, 0)],
    "strcat":     [(1, 0)],
    "strncat":    [(1, 0)],
    "wcscpy":     [(1, 0)],
    "wcsncpy":    [(1, 0)],
    "wcscat":     [(1, 0)],
    "sprintf":    [(1, 0), (2, 0), (3, 0), (4, 0)],   # fmt + varargs all flow to dst
    "snprintf":   [(2, 0), (3, 0), (4, 0)],            # fmt + varargs (after size) flow to dst
    "vsprintf":   [(1, 0), (2, 0)],
    "vsnprintf":  [(2, 0), (3, 0)],
    # Win32 wrappers
    "lstrcpyA":   [(1, 0)],
    "lstrcpyW":   [(1, 0)],
    "lstrcatA":   [(1, 0)],
    "lstrcatW":   [(1, 0)],
    "StringCchCopyA":  [(2, 0)],
    "StringCchCopyW":  [(2, 0)],
    "StringCchCatA":   [(2, 0)],
    "StringCchCatW":   [(2, 0)],
    "StringCbCopyA":   [(2, 0)],
    "StringCbCopyW":   [(2, 0)],
    # Win32 path-build (returns dest path with tainted input)
    "PathCombineA":    [(2, 0), (1, 0)],
    "PathCombineW":    [(2, 0), (1, 0)],
}


# Per-sink-class severity + CWE / MITRE mapping (mirrors per-cell expected.json)
SINK_CLASS_META: dict[str, dict] = {
    "buffer_overflow": {
        # Default to stack_buffer_overflow — strcpy/memcpy on a stack
        # buffer is the canonical case. heap.py owns heap-OF
        # detection via the alloc-vs-copy-size mismatch heuristic.
        "severity": Severity.HIGH,
        "category": "stack_buffer_overflow",
        "cwe": ["CWE-121", "CWE-120"],
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
    "kernel_oob_write": {
        # CVE-2026-31431 ("copy.fail") class — scatterwalk_map_and_copy
        # / copy_to_iter / memcpy_to_iter with attacker-controlled
        # offset arg writes past the legitimate buffer into chained
        # scatterlist regions (page cache).
        "severity": Severity.CRITICAL,
        "category": "kernel_oob_write_at_offset",
        "cwe": ["CWE-787"],
        "mitre": ["T1068", "T1611"],
        "knowledge_refs": [],
    },
    "kernel_arbitrary_rw": {
        # CVE-2021-21551 ("dbutil_2_3.sys") class — IOCTL handler
        # passes attacker-controlled physical / virtual address into
        # MmMapIoSpace / ZwMapViewOfSection family. Combined with a
        # subsequent memcpy yields arbitrary kernel R/W primitive.
        # BYOVD design vocabulary; recurs across the public driver
        # inventory (RTCore64, dbutildrv2, asusio, processhacker
        # ring0, kdmapper-bundled drivers).
        "severity": Severity.CRITICAL,
        "category": "kernel_arbitrary_rw_primitive",
        "cwe": ["CWE-782", "CWE-822"],
        "mitre": ["T1068", "T1611", "T1014"],
        "knowledge_refs": [
            "[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]",
        ],
    },
    "kernel_phys_disclosure": {
        # MmGetPhysicalAddress called with tainted virtual address
        # leaks the physical-memory layout to user space. By itself
        # an info-disclosure; combined with an arbitrary write it
        # builds a controllable physical-address staging buffer.
        "severity": Severity.MEDIUM,
        "category": "kernel_physical_address_disclosure",
        "cwe": ["CWE-200"],
        "mitre": ["T1083"],
        "knowledge_refs": [],
    },
    "kernel_alloc_size": {
        # MmAllocateContiguousMemory* with attacker-controlled size.
        # DoS / memory-exhaustion class; in some kernels also a
        # primitive for constructing physical-address staging buffers.
        "severity": Severity.HIGH,
        "category": "kernel_alloc_size_attacker_controlled",
        "cwe": ["CWE-789", "CWE-770"],
        "mitre": ["T1499"],
        "knowledge_refs": [],
    },
    "kernel_msr_write": {
        # __writemsr with attacker-controlled MSR index. Direct
        # privilege escalation: SYSCALL/IDT/SMRR/LSTAR overwrite,
        # PatchGuard bypass, virtualisation handoff. Hard-line
        # critical — there's no benign IOCTL-exposed MSR write.
        "severity": Severity.CRITICAL,
        "category": "kernel_arbitrary_msr_write",
        "cwe": ["CWE-782"],
        "mitre": ["T1014", "T1068", "T1601"],
        "knowledge_refs": [],
    },
    "kernel_msr_read": {
        # __readmsr with attacker-controlled MSR index. Info
        # disclosure of CPU control-register state — KASLR slide,
        # IA32_LSTAR address, KVM/Hyper-V configuration.
        "severity": Severity.HIGH,
        "category": "kernel_arbitrary_msr_read",
        "cwe": ["CWE-200"],
        "mitre": ["T1014"],
        "knowledge_refs": [],
    },
    "tainted_pointer_dereference": {
        # Generic write-where-what / read-where shape — any memory
        # access whose address operand traces back to user-controlled
        # input. The dbutil sub_15294 path (memcpy(dst, src, len)
        # where dst was loaded from the user buffer) is the canonical
        # example, but the pattern applies broadly: tainted load
        # whose result is reused as a pointer in another load/store.
        "severity": Severity.CRITICAL,
        "category": "tainted_pointer_dereference",
        "cwe": ["CWE-822", "CWE-908"],
        "mitre": ["T1068"],
        "knowledge_refs": [],
    },
    "kernel_arbitrary_process_handle": {
        # BYOVD process-killer class. ZwOpenProcess called with a
        # CLIENT_ID whose UniqueProcess (PID) is attacker-controlled.
        # On its own this is a privilege-escalation precursor; chained
        # with TerminateProcess it's the canonical "EDR killer"
        # primitive used by ransomware loaders (EDRKillShifter etc.).
        # Source-of-truth for primitive class: the BYOVD repo's
        # Step-0 import-screening filter.
        "severity": Severity.CRITICAL,
        "category": "kernel_arbitrary_process_handle",
        "cwe": ["CWE-862", "CWE-732"],
        "mitre": ["T1068", "T1562.001", "T1003"],
        "knowledge_refs": [
            "[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]",
        ],
    },
    "kernel_arbitrary_process_terminate": {
        # Direct call to ZwTerminateProcess with a handle whose
        # provenance traces back to a tainted CLIENT_ID. The handle
        # came from a tainted ZwOpenProcess; the position-aware sink
        # check catches the second-order flow.
        "severity": Severity.CRITICAL,
        "category": "kernel_arbitrary_process_terminate",
        "cwe": ["CWE-862"],
        "mitre": ["T1562.001"],
        "knowledge_refs": [],
    },
    "kernel_arbitrary_file_open": {
        "severity": Severity.HIGH,
        "category": "kernel_arbitrary_file_open",
        "cwe": ["CWE-22", "CWE-732"],
        "mitre": ["T1565.001", "T1547"],
        "knowledge_refs": [],
    },
    "kernel_arbitrary_file_write": {
        "severity": Severity.CRITICAL,
        "category": "kernel_arbitrary_file_write",
        "cwe": ["CWE-22", "CWE-732"],
        "mitre": ["T1565.001", "T1547"],
        "knowledge_refs": [],
    },
    "kernel_arbitrary_registry_write": {
        "severity": Severity.HIGH,
        "category": "kernel_arbitrary_registry_write",
        "cwe": ["CWE-732"],
        "mitre": ["T1547.001", "T1112"],
        "knowledge_refs": [],
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
    # Per-seed visited tracking: each top-level _propagate() call
    # creates a fresh visited set internally. There's no instance-
    # level visited state — that was the source of the Run-13
    # nondeterminism (seed iteration order pre-empted later seeds
    # at shared SSA vars).
    _emitted_deref_sigs: set = field(default_factory=set)
    # E5: addresses of in-binary functions identified as inlined-memcpy.
    # Populated by `_detect_inlined_memcpy_functions` at run() entry,
    # consumed by (a) PROPAGATORS lookup (so taint flows through them),
    # (b) callee-seeding skip-set (so we don't seed taint INTO their
    # bodies — internal copy loops are noise for E4), (c) E4 emit
    # filter (suppress findings inside these functions).
    _inlined_memcpy_addrs: set[int] = field(default_factory=set)
    _inlined_memcpy_names: set[str] = field(default_factory=set)

    # Buffer-content taint (Tier 1.2, 2026-05-08): when a propagator
    # like snprintf taints a destination SSA var that holds the
    # address of a stack slot (`&var_N`), we record the stack slot
    # as tainted. Subsequent SSA vars that resolve to the same
    # `&var_N` (e.g., a fresh `mov rcx_1, &var_N` before a `system()`
    # call that MSVC emits independently of the snprintf-side
    # `&var_N` SSA var) inherit the taint at the stack-slot level.
    # Closes the buffer-content vs SSA-variable taint gap that left
    # `snprintf(buf,…,argv); system(buf)` undetected. Key shape:
    # `(id(function), str(stack_var))`.
    _tainted_stack_slots: set[tuple[int, str]] = field(default_factory=set)

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

    def _to_ssa_form(self, function):
        """Normalise `function` (Function | MLILFunction | SSA form)
        to the SSA form. Returns None if no SSA form is available."""
        if function is None:
            return None
        # Already SSA — has get_ssa_var_definition
        if hasattr(function, "get_ssa_var_definition"):
            return function
        # MLIL function — has .ssa_form
        ssa = getattr(function, "ssa_form", None)
        if ssa is not None and hasattr(ssa, "get_ssa_var_definition"):
            return ssa
        # Function — has .mlil
        mlil = getattr(function, "mlil", None)
        if mlil is not None:
            mssa = getattr(mlil, "ssa_form", None)
            if mssa is not None and hasattr(mssa, "get_ssa_var_definition"):
                return mssa
            if hasattr(mlil, "get_ssa_var_definition"):
                return mlil
        return None

    def _stack_slot_of(self, ssa_var, function) -> Optional[str]:
        """If `ssa_var` is defined as `&local_var` (address-of a
        stack slot), return the stack-slot variable's stringified
        name. Else return None.

        Used by the buffer-content taint mechanism to record stack
        slots reached by propagators (so subsequent SSA vars
        independently aliased to the same slot inherit taint).
        """
        if ssa_var is None:
            return None
        ssa_form = self._to_ssa_form(function)
        if ssa_form is None:
            return None
        getdef = getattr(ssa_form, "get_ssa_var_definition", None)
        if not callable(getdef):
            return None
        try:
            defn = getdef(ssa_var)
        except Exception:
            return None
        if defn is None:
            return None
        src = getattr(defn, "src", None)
        if src is None:
            return None
        op_name = type(src).__name__
        if "AddressOf" not in op_name and "Addr" not in op_name:
            return None
        slot = (getattr(src, "src", None)
                or getattr(src, "var", None))
        if slot is None:
            return None
        return str(slot)

    def _arg_stack_slot(self, expr, function) -> Optional[str]:
        """If a call-arg expression is itself `&local_var` (direct
        AddressOf, no SSA-var indirection), return the slot name."""
        if expr is None:
            return None
        op_name = type(expr).__name__
        if "AddressOf" in op_name or "Addr" in op_name:
            slot = (getattr(expr, "src", None)
                    or getattr(expr, "var", None))
            if slot is not None:
                return str(slot)
        # Or the arg might be an SSA var defined as &local
        ssa = ilh.expr_to_ssa_var(expr)
        if ssa is not None:
            return self._stack_slot_of(ssa, function)
        return None

    def _record_tainted_stack_slot(self, ssa_var, function) -> None:
        """If `ssa_var`'s definition is `&local_var`, record the
        stack slot as tainted. Future arg-checks with the same slot
        match as tainted regardless of SSA-var identity."""
        slot = self._stack_slot_of(ssa_var, function)
        if slot is None:
            return
        self._tainted_stack_slots.add((id(function), slot))

    def _arg_aliases_tainted_stack(self, expr, function) -> bool:
        """True iff the call-arg expression resolves to a tainted
        stack slot. Used in `_check_sink` and `_maybe_propagate_through_call`
        to bridge `&var_N` aliases that the SSA-var-equality check
        misses."""
        slot = self._arg_stack_slot(expr, function)
        if slot is None:
            return False
        return (id(function), slot) in self._tainted_stack_slots

    def _propagate_to_aliases_of_slot(self, slot_name: str, function,
                                      depth: int, source_name: str,
                                      source_addr: int,
                                      visited: Optional[set] = None) -> None:
        """When a stack slot becomes tainted, find every SSA var in
        `function` defined as `&slot_name` and recurse propagation
        from each. Closes the gap where MSVC re-emits `mov <reg>,
        &var_N` separately for each call site — the propagator's
        SSA-var-equality check would otherwise stop at the first
        alias."""
        if function is None or not slot_name:
            return
        ssa_form = self._to_ssa_form(function)
        if ssa_form is None:
            return
        instructions = getattr(ssa_form, "instructions", None)
        if instructions is None:
            return
        try:
            for inst in instructions:
                op_name = type(inst).__name__
                # Only SetVarSsa-class definitions; skip stores etc.
                if "Set" not in op_name or "Var" not in op_name:
                    continue
                src = getattr(inst, "src", None)
                if src is None:
                    continue
                src_op = type(src).__name__
                if "AddressOf" not in src_op and "Addr" not in src_op:
                    continue
                slot_var = (getattr(src, "src", None)
                            or getattr(src, "var", None))
                if slot_var is None or str(slot_var) != slot_name:
                    continue
                # Found a `<dst_ssa> = &<slot_name>` definition.
                dst_ssa = getattr(inst, "dest", None)
                if dst_ssa is None:
                    continue
                self._propagate(dst_ssa, function, depth,
                                source_name, source_addr,
                                visited=visited)
        except Exception:
            return

    def _check_sink(self, call_inst, tainted_var,
                    source_name: str, source_addr: int) -> Optional[Finding]:
        """If `call_inst` is a sink call with `tainted_var` at the
        sink's dangerous arg index, emit a Finding. Returns None
        otherwise (so the caller falls through to propagator / inter-
        proc handling).

        Buffer-content taint (2026-05-08): the arg-index match
        accepts both (a) direct SSA-var equality with `tainted_var`,
        and (b) the arg expression aliasing a previously-tainted
        stack slot (`&var_N` where `var_N` was tainted by a
        prior propagator emission).
        """
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

        # Verify tainted_var is at the dangerous arg position. If
        # taint flows through a non-dangerous arg of a sink (e.g.,
        # the data arg of snprintf where format is arg 2), this
        # call is not a finding here — the propagator path will
        # carry the taint to the destination.
        params = ilh.call_params(call_inst)
        # Resolve the function for stack-slot aliasing lookups.
        sink_func = getattr(call_inst, "function", None)
        tainted_idx = None
        for i, p in enumerate(params):
            ssa = ilh.expr_to_ssa_var(p)
            if ssa is not None and str(ssa) == str(tainted_var):
                tainted_idx = i
                break
            # Buffer-content alias: the arg references a stack slot
            # that was previously tainted by a propagator.
            if sink_func is not None and self._arg_aliases_tainted_stack(p, sink_func):
                tainted_idx = i
                break
        if tainted_idx != arg_index:
            return None

        # Get the function containing this call. `call_inst.function`
        # returns the MLIL function — which doesn't have `.name`.
        # Use `ilh.function_display_name` to traverse to the source
        # function for display, while keeping the MLIL handle for
        # SSA-form ops (it normalises through to SSA form internally).
        func = getattr(call_inst, "function", None)
        func_name = ilh.function_display_name(func)
        addr = int(getattr(call_inst, "address", 0))

        # Re-categorise buffer_overflow → heap_buffer_overflow when
        # the dst is heap-allocated (avoids dual-emit with heap.py).
        # Also clears the stack-specific signals that wouldn't apply.
        category_final = meta["category"]
        signals_override = None
        if sink_class == "buffer_overflow":
            try:
                if _dst_resolves_to_heap_alloc(call_inst, func):
                    category_final = "heap_buffer_overflow"
                    # heap-OF gets a different signal stack
                    signals_override = ("tainted_pointer_write",
                                         "alloc_then_write_no_full_init")
            except Exception:
                pass
        finding = Finding(
            id="",
            category=category_final,
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
        # Fan-discount-aware confidence (Tier-2 foundation). Base
        # signals come from `_SINK_CLASS_SIGNALS`; CFG-aware
        # augmentations come from `_augment_signals_for_sink` (e.g.,
        # the integer-OF missing-guard SPECIFIC). Sink classes not
        # wired here get neutral 0.5.
        # Heap-OF override: when re-categorised, use the heap-specific
        # signal set instead of the stack-OF augmentation.
        if signals_override is not None:
            signals = list(signals_override)
        else:
            signals = list(_SINK_CLASS_SIGNALS.get(sink_class, ()))
            signals = _augment_signals_for_sink(
                signals,
                sink_class=sink_class,
                sink_name=sink_name,
                function=func,
                call_addr=addr,
                tainted_var=tainted_var,
                call_inst=call_inst,
            )
        if signals:
            apply_signals_to_finding(finding, signals)
        return finding

    # ── SSA propagation ──────────────────────────────────────────

    def _propagate(self, ssa_var, function, depth: int,
                   source_name: str, source_addr: int,
                   via_load_count: int = 0,
                   visited: Optional[set] = None) -> None:
        """Recursive forward propagation through SSA def-use chains.

        `via_load_count` tracks how many memory loads the taint has
        crossed since the source. The first load typically reads a
        struct field on the original tainted input (e.g.,
        `IRP.SystemBuffer`) — benign on its own. The *second* load
        reads through a pointer that was itself loaded from tainted
        memory — that's the canonical "user-controlled pointer used
        as kernel address" primitive (CWE-822 / CWE-908). E4 emits
        a Finding when a tainted SSA var with `via_load_count >= 1`
        is dereffed, regardless of whether the deref then reaches a
        named sink.

        `visited` is **per-seed**, not global. Each top-level seed
        entry passes `None` and a fresh set is created here; recursive
        calls within the seed thread the same set so cycles are
        prevented within one exploration. Different seeds get
        independent visited sets so they don't pre-empt each other —
        that fixes the nondeterminism observed during Run 13 where
        seed iteration order (driven by Python hash randomisation)
        would cause findings to drop between runs. Cross-seed
        deduplication of identical findings happens at the
        `Finding.id` level (computed from category + binary +
        address + detector + knowledge_refs).
        """
        if depth > self.max_depth:
            return
        if visited is None:
            visited = set()
        # Visited key includes a boolean "has crossed any load"
        # alongside (function, ssa_var). Without this bit, a node
        # first visited with count=0 (no loads crossed) would block
        # later visits with count>=1 (loads crossed) — losing the E4
        # emission entirely on those paths. Encoding the boolean
        # gives at most 2 states per node, bounded; cycles still
        # resolve because monotonic count escalation past the
        # threshold settles into the count>=1 state.
        crossed_load = via_load_count >= 1
        key = (id(function), str(ssa_var), crossed_load)
        if key in visited:
            return
        visited.add(key)
        # Defensive cap — once the count is high it doesn't matter
        # how high; the E4 emission gate is at >= 1, and the visited
        # key only differentiates 0 from >=1.
        if via_load_count > 5:
            via_load_count = 5

        for use in ilh.ssa_uses_of(function, ssa_var):
            # E4 — tainted-pointer-dereference detection. Fire when
            # a tainted var that itself came via at least one load
            # is being dereffed (load base or store dest). This
            # captures the dbutil-class arbitrary-R/W primitive where
            # the user buffer's first qword is reloaded as a kernel
            # pointer.
            if via_load_count >= 1:
                deref_kind = self._deref_kind_for_use(use, ssa_var)
                if deref_kind is not None:
                    self._emit_tainted_deref_finding(
                        use, function, ssa_var,
                        source_name, source_addr, deref_kind,
                    )

            # If this use is a Call, check sink + recurse
            op_name = getattr(getattr(use, "operation", None), "name", "")
            if "CALL" in op_name:
                finding = self._check_sink(use, ssa_var,
                                            source_name, source_addr)
                if finding is not None:
                    self.findings.append(finding)
                    # Sink hit; do not propagate further from this call
                    continue

                # Check propagator: this call writes taint from a
                # source-arg into a destination-arg buffer. The
                # destination's SSA var becomes tainted; continue
                # propagation from there. Propagator path stays
                # intra-function — no depth bump.
                propagated = self._maybe_propagate_through_call(
                    use, ssa_var, function, depth,
                    source_name, source_addr,
                    visited=visited,
                )
                if propagated:
                    continue

                # Inter-procedural one-hop: if the callee is in-binary,
                # propagate taint into the matching parameter.
                if depth + 1 <= self.max_depth:
                    self._propagate_into_callee(use, ssa_var, depth + 1,
                                                source_name, source_addr,
                                                visited=visited)

                # Generic call-return transit. A function that receives
                # a tainted argument is conservatively treated as
                # returning a tainted value — this carries taint past
                # unnamed wrapper functions (`__byteswap_uint64`,
                # custom intrinsics, MSVC compiler-emitted helpers)
                # without needing each one in PROPAGATORS by name.
                # Same shape as the dataflow-analysis "summary node"
                # idea, applied lazily.
                #
                # Skip when the call has a known propagator entry
                # (already handled above) or when there's no caller-
                # side output SSA var to taint.
                cur_callee_name = self._resolve_callee_name(use)
                if (cur_callee_name in PROPAGATORS
                        or (cur_callee_name is not None
                            and _cpp_stdlib_propagator_for_name(cur_callee_name) is not None)):
                    continue
                call_output = ilh.call_output_ssa(use)
                if call_output is None:
                    continue
                # Only propagate the return when our tainted_var is in
                # the call's parameter list; otherwise this isn't
                # actually a transit-from-tainted-input case.
                params = ilh.call_params(use)
                tainted_in_args = False
                for p in params:
                    ssa = ilh.expr_to_ssa_var(p)
                    if ssa is not None and str(ssa) == str(ssa_var):
                        tainted_in_args = True
                        break
                if tainted_in_args:
                    self._propagate(call_output, function, depth,
                                    source_name, source_addr,
                                    via_load_count=via_load_count,
                                    visited=visited)
                continue

            # Otherwise propagate via the use's defined output(s).
            # Intra-function steps don't consume depth budget — depth
            # counts inter-procedural hops, not compiler-generated
            # register shuffles. The visited set still prevents cycles.
            output = getattr(use, "output", None)
            if output is None:
                # Fall back to ssa_form.dest if present
                ssa = getattr(use, "ssa_form", None)
                output = getattr(ssa, "dest", None) if ssa else None
            if output is None:
                continue
            outputs = output if hasattr(output, "__iter__") else [output]
            # If this use is a load whose address contains our tainted
            # var, the propagated output is one step "further down"
            # the load chain — bump `via_load_count` so the next
            # deref of that output emits the E4 finding.
            crosses_load = self._use_loads_through(use, ssa_var)
            new_load_count = via_load_count + (1 if crosses_load else 0)
            for new_var in outputs:
                self._propagate(new_var, function, depth,
                                source_name, source_addr,
                                via_load_count=new_load_count,
                                visited=visited)

    # ── E4 helpers — tainted-pointer-dereference detection ──────

    def _expr_contains_var(self, expr, target_ssa_var) -> bool:
        """Walk an MLIL expression tree, return True if any leaf
        node is a use of `target_ssa_var`. Tolerant of expression
        wrappers (Add, Sub, ZeroExt, casts, etc.).
        """
        if expr is None:
            return False
        # Direct SSA-var reference
        for attr in ("src", "var"):
            v = getattr(expr, attr, None)
            if v is not None and hasattr(v, "var") and hasattr(v, "version"):
                if str(v) == str(target_ssa_var):
                    return True
        # Recurse into child operands
        operands = getattr(expr, "operands", None)
        if operands is None:
            return False
        for op in operands:
            if self._expr_contains_var(op, target_ssa_var):
                return True
        return False

    def _use_loads_through(self, use, ssa_var) -> bool:
        """True if `use` is/contains a memory load whose address
        operand uses `ssa_var`. Used to bump `via_load_count` so the
        next deref of the load result triggers E4."""
        # Recursively look for a Load node in the expression tree.
        return self._find_load_with_base(use, ssa_var) is not None

    def _find_load_with_base(self, expr, ssa_var, max_depth: int = 6):
        """Return the first Load expression whose address contains
        `ssa_var`, or None."""
        if expr is None or max_depth <= 0:
            return None
        op_name = type(expr).__name__
        if "Load" in op_name:
            src = getattr(expr, "src", None)
            if src is not None and self._expr_contains_var(src, ssa_var):
                return expr
        operands = getattr(expr, "operands", None)
        if operands is None:
            return None
        for op in operands:
            r = self._find_load_with_base(op, ssa_var, max_depth - 1)
            if r is not None:
                return r
        return None

    def _deref_kind_for_use(self, use, ssa_var) -> Optional[str]:
        """If `use` dereferences `ssa_var` (load base or store dest),
        return `"read"` / `"write"`. Otherwise None.

        Used to emit the E4 finding ONLY when the tainted var is
        actually used as a pointer — not when it's used as e.g. a
        sized argument to a function or as an operand in arithmetic.
        """
        op_name = type(use).__name__
        # Store: address operand is `dest` and may be the var directly
        # or arithmetic on the var.
        if "Store" in op_name:
            dest = getattr(use, "dest", None)
            if dest is not None and self._expr_contains_var(dest, ssa_var):
                # MediumLevelILStoreStruct represents typed-struct
                # writes (e.g., `arg1->field = X`). Those are common
                # benign struct mutations and produce huge FP volume
                # — skip unless the base traces from a load chain.
                # The via_load_count gate already enforces that, so
                # we accept all Store shapes here.
                return "write"
        # Load: present inside SetVarSsa.src, or as a top-level Load.
        load = self._find_load_with_base(use, ssa_var)
        if load is not None:
            return "read"
        return None

    def _emit_tainted_deref_finding(self, use, function, ssa_var,
                                    source_name: str, source_addr: int,
                                    deref_kind: str) -> None:
        """Emit one E4 `tainted_pointer_dereference` Finding.

        Two confidence filters apply:

        1. **Suppress inside inlined-memcpy bodies.** Once E5 has
           identified a function as memcpy, its internal byte-by-byte
           / qword-by-qword copy loop's loads/stores are not
           interesting analysis targets — they're the implementation
           of the copy, not the bug.
        2. **Suppress when source is the Linux kernel-arg shotgun.**
           `_seed_kernel_module_taint` seeds taint on every SysV
           arg-register SSA in every defined function of a stripped
           `.ko`. That's the right approach for catching named-sink
           flows (where the position-aware sink check filters noise),
           but it's wrong for E4: the shotgun seeds many "registers"
           that aren't actually function arguments at runtime, and
           every internal struct-field-load idiom in the kernel then
           fires E4. We restrict E4 to high-confidence sources:
           argv, named-import sources, and Win64 IOCTL handler
           seeds.
        """
        meta = SINK_CLASS_META.get("tainted_pointer_dereference")
        if meta is None:
            return
        addr = int(getattr(use, "address", 0) or 0)
        fname = getattr(function, "name", "") or ""
        # Filter 1: skip inside inlined-memcpy bodies
        func_start = int(getattr(function, "start", 0) or 0)
        if func_start in self._inlined_memcpy_addrs:
            return
        if fname in self._inlined_memcpy_names:
            return
        # Filter 2: skip Linux kernel-arg shotgun seeds
        if source_name.startswith("kernel_arg:"):
            return
        category = meta["category"]
        # Dedupe — multiple SSA visits of the same address+function
        # would otherwise produce duplicate findings.
        sig = (category, fname, addr, deref_kind)
        if sig in self._emitted_deref_sigs:
            return
        self._emitted_deref_sigs.add(sig)

        self.findings.append(Finding(
            id="",
            category=category,
            severity=meta["severity"],
            address=addr,
            function=fname,
            binary=self.binary,
            arch=self.arch,
            platform=self.platform,
            detector=self.detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre"]),
            description=(
                f"taint flow: {source_name} -> tainted_pointer_{deref_kind} @ "
                f"{fname}+{hex(addr)} (var {ssa_var}). "
                f"User-controlled value reloaded from tainted memory is "
                f"used as a {('source' if deref_kind == 'read' else 'destination')} "
                f"pointer — the canonical write-where-what / read-where primitive."
            ),
            evidence=[Evidence(
                kind="tainted_deref",
                source=self.detector,
                payload=f"{source_name}@0x{source_addr:x} -> deref({deref_kind}) "
                        f"via {ssa_var} @ 0x{addr:x}",
                address=addr,
                function=fname,
            )],
            details={
                "source_name": source_name,
                "source_addr": hex(source_addr),
                "tainted_var": str(ssa_var),
                "deref_kind": deref_kind,
                "sink_class": "tainted_pointer_dereference",
            },
        ))

    def _resolve_callee_name(self, call_inst) -> Optional[str]:
        """Return the name of the called import, or None."""
        callee_addr = ilh.callee_address_of_call(call_inst)
        if callee_addr is None or self.bv is None:
            return None
        sym = self.bv.get_symbol_at(callee_addr)
        if sym is None:
            return None
        return getattr(sym, "short_name", None) or getattr(sym, "name", "")

    def _maybe_propagate_through_call(self, call_inst, tainted_var,
                                      function, depth: int,
                                      source_name: str, source_addr: int,
                                      visited: Optional[set] = None) -> bool:
        """If `call_inst` is a propagator with `tainted_var` at a
        source-arg slot, taint the destination-arg's SSA var and
        recurse. Returns True when the call was a propagator (the
        caller should NOT also do an inter-proc hop).

        `visited` is the per-seed visited set threaded from the
        caller (`_propagate`); recursive _propagate calls share it
        so cycles within the seed are caught.
        """
        if depth > self.max_depth:
            return False
        callee_name = self._resolve_callee_name(call_inst)
        # Look up in the named PROPAGATORS table first; fall back to
        # C++ stdlib pattern matching (handles per-instantiation
        # template-parameter variation in mangled names).
        propagator = PROPAGATORS.get(callee_name) if callee_name else None
        if propagator is None and callee_name is not None:
            propagator = _cpp_stdlib_propagator_for_name(callee_name)
        if propagator is None:
            return False
        params = ilh.call_params(call_inst)
        if not params:
            return False
        # Locate the parameter slot carrying our tainted var.
        tainted_idx = None
        for i, p in enumerate(params):
            ssa = ilh.expr_to_ssa_var(p)
            if ssa is not None and str(ssa) == str(tainted_var):
                tainted_idx = i
                break
        if tainted_idx is None:
            return False
        any_propagated = False
        for (src_idx, dst_idx) in propagator:
            if src_idx != tainted_idx:
                continue
            if dst_idx >= len(params):
                continue
            dst_expr = params[dst_idx]
            # Buffer-content taint: record the stack slot the dst
            # references, so future calls with arg=&same_slot match
            # as tainted even with a different SSA var.
            dst_slot = self._arg_stack_slot(dst_expr, function)
            if dst_slot is not None:
                self._tainted_stack_slots.add((id(function), dst_slot))
            dst_ssa = ilh.expr_to_ssa_var(dst_expr)
            if dst_ssa is not None:
                self._record_tainted_stack_slot(dst_ssa, function)
                self._propagate(dst_ssa, function, depth,
                                source_name, source_addr,
                                visited=visited)
            # Also explore all OTHER SSA vars that alias the same
            # stack slot — MSVC commonly re-loads `&var_N` separately
            # for each call site, producing distinct SSA vars; the
            # tainted-stack-slot bookkeeping connects them.
            if dst_slot is not None:
                self._propagate_to_aliases_of_slot(
                    dst_slot, function, depth,
                    source_name, source_addr, visited=visited,
                )
            any_propagated = True
        return any_propagated

    def _propagate_into_callee(self, call_inst, tainted_var, depth: int,
                               source_name: str, source_addr: int,
                               visited: Optional[set] = None) -> None:
        """When a tainted var is passed to an in-binary callee, follow
        into the matching parameter's SSA chain. `visited` threaded
        from the caller so cross-function steps remain part of the
        same seed's exploration."""
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
                        source_name, source_addr,
                        visited=visited)

    # ── Top-level run ────────────────────────────────────────────

    def _seed_argv_taint(self) -> None:
        """Seed taint from `main`'s argv parameter — synthetic source.

        argv isn't an import, so import-driven enumeration misses it.
        For CLI tools this is the dominant attack-surface; without
        seeding we lose every command-injection / format-string /
        path-traversal flow originating from argv.
        """
        # Locate main()
        main_func = None
        getters = (
            lambda: self.bv.get_functions_by_name("main"),
            lambda: self.bv.get_functions_by_name("wmain"),
            lambda: self.bv.get_functions_by_name("WinMain"),
            lambda: self.bv.get_functions_by_name("wWinMain"),
        )
        for getter in getters:
            try:
                fns = getter() or []
            except Exception:
                fns = []
            if fns:
                main_func = fns[0]
                break
        if main_func is None:
            return

        params = list(getattr(main_func, "parameter_vars", []) or [])
        if not params:
            return

        # main(int argc, char**argv) — argv is at index 1 if argc is
        # at index 0; some Win-mode signatures shift. Treat every
        # pointer-typed parameter as tainted.
        try:
            from binaryninja import SSAVariable          # type: ignore
        except Exception:
            return
        for idx, p in enumerate(params):
            # argc (first int param) is rarely worth tracking — int
            # values feed loop counters etc. Skip pure-int params.
            try:
                tname = str(getattr(p, "type", "")) if p is not None else ""
            except Exception:
                tname = ""
            if tname and ("*" not in tname and "**" not in tname
                          and "char" not in tname and "wchar" not in tname):
                # Looks like a non-pointer scalar (int, etc.) — skip
                if idx == 0 and "argc" in str(getattr(p, "name", "")).lower():
                    continue
            try:
                ssa_var = SSAVariable(p, 0)
            except Exception:
                continue
            self._propagate(ssa_var, main_func, depth=0,
                            source_name="argv",
                            source_addr=int(getattr(main_func, "start", 0)))

    def _is_kernel_module(self) -> bool:
        """Detect a Linux kernel `.ko` via section markers."""
        if self.bv is None:
            return False
        sections = getattr(self.bv, "sections", None)
        if not sections:
            return False
        names = set(sections.keys() if hasattr(sections, "keys") else [])
        return bool(names & {".modinfo", "__versions",
                             ".gnu.linkonce.this_module"})

    # Linux x86_64 SysV calling convention — first six integer / pointer
    # args are passed in these registers. Win64 uses (rcx, rdx, r8, r9).
    # We taint both sets to handle either ABI; the visited-set
    # deduplication and position-aware sink check filter the noise.
    _KERNEL_ARG_REGISTER_PREFIXES = (
        "rdi", "rsi", "rdx", "rcx", "r8", "r9",      # SysV first 6
    )

    def _seed_kernel_module_taint(self) -> None:
        """Seed taint from argument-register SSA variables in every
        defined function of a kernel module.

        Kernel modules don't have `main()`. Their entry points are
        functions registered into kernel subsystems via struct
        templates (e.g., `struct aead_alg.decrypt = crypto_authenc_esn_decrypt`).
        Those entry-point parameters carry attacker-influenceable
        state (struct fields populated from user-supplied AF_ALG
        socket messages in the case of CVE-2026-31431).

        Stripped kernel `.ko` files don't preserve C-level parameter
        signatures (`func.parameter_vars` is empty), so we can't
        seed from typed parameters. Instead we seed from the
        argument-register SSA variables — Binja's MLIL SSA exposes
        these as `rdi_N#1`, `rsi_N#1`, etc., representing the
        post-`__fentry__` versions of the arg registers, which on
        Linux x86_64 SysV hold the function arguments verbatim.

        Per-function we:
        1. Scan `func.mlil.ssa_form.ssa_vars` for SSA variables whose
           underlying register name matches an arg-register prefix.
        2. Pick the lowest-version of each (the function-entry value).
        3. Propagate taint forward from each.

        Skips Binja-generated padding stubs (`__pfx_*`) and module
        init / exit boilerplate.
        """
        if not self._is_kernel_module():
            return
        for func in self.bv.functions:
            fname = getattr(func, "name", "") or ""
            if fname.startswith("__pfx_"):
                continue
            if fname in ("init_module", "cleanup_module"):
                continue
            if fname.endswith("_module_init") or fname.endswith("_module_exit"):
                continue

            mlil = getattr(func, "mlil", None)
            if mlil is None:
                continue
            ssa_form = getattr(mlil, "ssa_form", None)
            if ssa_form is None:
                continue

            # Collect lowest-version SSA var per arg-register prefix.
            seeds: dict[str, object] = {}
            for v in getattr(ssa_form, "ssa_vars", []) or []:
                vname = str(getattr(getattr(v, "var", None), "name", ""))
                # Strip Binja's `_N` rename suffix (rdi_9 -> rdi)
                base = vname.split("_")[0] if "_" in vname else vname
                if base not in self._KERNEL_ARG_REGISTER_PREFIXES:
                    continue
                version = int(getattr(v, "version", 0) or 0)
                key = vname        # keep distinct rdi_9 vs rdi (different storage)
                cur = seeds.get(key)
                if cur is None or int(getattr(cur, "version", 0) or 0) > version:
                    seeds[key] = v

            for key, ssa_var in seeds.items():
                self._propagate(
                    ssa_var, func, depth=0,
                    source_name=f"kernel_arg:{fname}:{key}",
                    source_addr=int(getattr(func, "start", 0)),
                )

    # Win64 ABI: first four integer/pointer args are rcx/rdx/r8/r9.
    # IOCTL handler prototype is NTSTATUS H(PDEVICE_OBJECT, PIRP), so
    # rcx=DeviceObject and rdx=PIRP. The IRP is the user-controlled
    # input — every field-load chain through it carries attacker data.
    # rcx (DeviceObject) is driver-owned so we don't seed it; rdx is
    # the seed. r8/r9 aren't part of the IOCTL prototype but we seed
    # them too in case Binja's ABI recovery missed parameters and they
    # carry stack-spilled values.
    _WIN64_IRP_REGISTER_PREFIXES = ("rdx", "r8", "r9")

    def _seed_windows_ioctl_taint(self) -> None:
        """Seed taint from IRP-bearing argument(s) in every IOCTL handler
        discovered by `analysis/windows_drivers`.

        Why this is its own seeder vs. `_seed_kernel_module_taint`:
        - Windows kernel drivers don't match the Linux .ko section
          discriminator (no `.modinfo`, no `__versions`).
        - The attacker-reachable functions are a tightly-bounded set
          (those registered via `DriverObject->MajorFunction[N]`),
          not "every defined function". Seeding the bounded set
          gives a much cleaner signal-to-noise ratio than the
          shotgun approach used for stripped .ko files.
        - The Win64 ABI uses different arg registers from SysV.

        Seeding strategy:

        1. Prefer typed parameters when Binja recovered them. The
           IOCTL handler prototype is `NTSTATUS H(PDEVICE_OBJECT, PIRP)`,
           so the second parameter is the IRP. On
           `windows-kernel-x86_64` Binja typically recovers this from
           the `MajorFunction[]` slot's pointer type — `parameter_vars`
           on the handler then contains `[arg1: PDEVICE_OBJECT, arg2: PIRP]`
           and we seed `arg2`.

        2. Fall back to register-prefix seeding (`rdx`/`r8`/`r9`) when
           parameter recovery failed (stripped, missing platform module,
           obfuscated prototype). Same shape as the Linux .ko fallback,
           just with the Win64 register set.

        Either path lets the existing field-load propagator carry taint
        through `IRP.AssociatedIrp.SystemBuffer`, `IRP.UserBuffer`, and
        the `IO_STACK_LOCATION.Parameters.DeviceIoControl.*` fields
        without further bookkeeping.
        """
        # Lazy import — avoids a heuristics ↔ analysis cycle at import time.
        from . import windows_drivers as wd

        if not wd._is_windows_kernel_driver(self.bv):
            return
        ioctl_handlers = wd.discover_ioctl_handlers(self.bv)
        if not ioctl_handlers:
            return

        try:
            from binaryninja import SSAVariable      # type: ignore
        except Exception:
            SSAVariable = None                       # type: ignore

        for handler_addr in ioctl_handlers:
            func = self.bv.get_function_at(handler_addr)
            if func is None:
                continue
            fname = getattr(func, "name", "") or f"sub_{handler_addr:x}"
            mlil = getattr(func, "mlil", None)
            if mlil is None:
                continue
            ssa_form = getattr(mlil, "ssa_form", None)
            if ssa_form is None:
                continue

            # 1. Typed-parameter path. IOCTL handler prototype is
            #    H(PDEVICE_OBJECT, PIRP), so PIRP is at index 1. If we
            #    have at least two parameters, seed index 1.
            params = list(getattr(func, "parameter_vars", []) or [])
            seeded_typed = False
            if len(params) >= 2 and SSAVariable is not None:
                irp_param = params[1]
                try:
                    ssa_var = SSAVariable(irp_param, 0)
                    self._propagate(
                        ssa_var, func, depth=0,
                        source_name=f"win64_ioctl_irp:{fname}:{getattr(irp_param, 'name', 'arg2')}",
                        source_addr=int(getattr(func, "start", 0)),
                    )
                    seeded_typed = True
                except Exception:
                    pass

            # 2. Register-prefix fallback. Always also runs to catch
            #    handlers whose prototype recovery missed the IRP arg
            #    or where additional argument-bearing registers carry
            #    state worth tainting (e.g., r8/r9 if Binja split a
            #    struct argument across registers).
            seeds: dict[str, object] = {}
            for v in getattr(ssa_form, "ssa_vars", []) or []:
                vname = str(getattr(getattr(v, "var", None), "name", ""))
                base = vname.split("_")[0] if "_" in vname else vname
                if base not in self._WIN64_IRP_REGISTER_PREFIXES:
                    continue
                version = int(getattr(v, "version", 0) or 0)
                cur = seeds.get(vname)
                if cur is None or int(getattr(cur, "version", 0) or 0) > version:
                    seeds[vname] = v

            for key, ssa_var in seeds.items():
                self._propagate(
                    ssa_var, func, depth=0,
                    source_name=f"win64_ioctl_reg:{fname}:{key}",
                    source_addr=int(getattr(func, "start", 0)),
                )

            # 3. Direct callees of the IOCTL handler. The handler is
            #    typically a switch dispatcher that fans out to per-
            #    IOCTL-code worker functions, passing pointers
            #    (`DeviceExtension`, scratch buffers) that carry
            #    user-controlled state via memory stores the dispatcher
            #    performed. Pure SSA def-use can't cross that
            #    memory-store boundary — but seeding the workers'
            #    parameters at function entry directly captures the
            #    same flow on the receiving side. The position-aware
            #    sink check filters out workers whose param happens to
            #    not carry user data; cost is over-tainting, not FPs.
            for callee in getattr(func, "callees", []) or []:
                if callee is None:
                    continue
                callee_addr = int(getattr(callee, "start", 0) or 0)
                if callee_addr == handler_addr:
                    continue
                # Skip seeding into inlined-memcpy implementations —
                # their internal copy loops aren't analysis targets,
                # and seeding them produces dozens of E4 FPs (every
                # internal *(rdi+i) = *(rsi+i) load/store in the
                # unrolled loop fires the deref check). The
                # PROPAGATORS entry registered by E5 already carries
                # taint through the call site; that's the correct
                # treatment.
                if callee_addr in self._inlined_memcpy_addrs:
                    continue
                cmlil = getattr(callee, "mlil", None)
                if cmlil is None:
                    continue
                cssa = getattr(cmlil, "ssa_form", None)
                if cssa is None:
                    continue
                cname = getattr(callee, "name", f"sub_{callee_addr:x}")
                cparams = list(getattr(callee, "parameter_vars", []) or [])
                if cparams and SSAVariable is not None:
                    for idx, p in enumerate(cparams):
                        try:
                            cssa_var = SSAVariable(p, 0)
                        except Exception:
                            continue
                        self._propagate(
                            cssa_var, callee, depth=0,
                            source_name=f"win64_ioctl_callee:{fname}->{cname}:arg{idx}",
                            source_addr=int(getattr(callee, "start", 0)),
                        )

    # ── E5 — Inlined-memcpy structural detection ─────────────────

    def _detect_inlined_memcpy_functions(self) -> None:
        """Identify in-binary functions that are unrolled / inlined
        memcpy implementations and register them in PROPAGATORS so
        taint flows through them without name resolution.

        Why this matters for BYOVD detection. MSVC kernel drivers
        commonly inline `memcpy` / `RtlCopyMemory` at link time —
        the resulting function has the memcpy signature
        (`char* dst, void* src, size_t n` returning dst) but is
        named `sub_<addr>`. Without recognising it, `PROPAGATORS` is
        name-keyed and silently drops taint at every call.

        Detector heuristic. A function is identified as memcpy when
        ALL of these hold:

        1. Exactly 3 typed parameters whose effective sizes are
           pointer / pointer / size-t (any of int/size/long are fine).
        2. Function entry stores `result = arg1` (return value =
           destination).
        3. Body contains at least one MEMORY STORE whose value is
           a load from arg2-derived memory and whose destination is
           an arg1-derived address.

        This catches MSVC's inlined memcpy (`sub_11790` in dbutil),
        Linux kernel `__memcpy` / `memcpy_orig` variants, and many
        custom open-coded copy loops. The check is intentionally
        loose — false-positive registration only adds aliasing-aware
        propagation, not a sink emission, so the cost is low.
        """
        if self.bv is None:
            return
        for func in self.bv.functions:
            try:
                if self._function_looks_like_memcpy(func):
                    addr = int(getattr(func, "start", 0) or 0)
                    name = getattr(func, "name", "") or f"sub_{addr:x}"
                    self._inlined_memcpy_addrs.add(addr)
                    self._inlined_memcpy_names.add(name)
                    # Register propagator entry: arg 1 (src) → arg 0 (dst)
                    PROPAGATORS.setdefault(name, [(1, 0)])
            except Exception:
                continue

    def _function_looks_like_memcpy(self, func) -> bool:
        params = list(getattr(func, "parameter_vars", []) or [])
        if len(params) != 3:
            return False
        mlil = getattr(func, "mlil", None)
        if mlil is None:
            return False
        try:
            instrs = list(mlil.instructions)
        except Exception:
            return False
        # Length bounds — memcpy implementations are nontrivial (the
        # unrolled+SIMD ucrtbase variant is ~150 MLIL nodes) but never
        # huge.
        if len(instrs) < 8 or len(instrs) > 800:
            return False

        try:
            arg1_name = str(getattr(params[0], "name", "")) or "arg1"
        except Exception:
            return False

        seen_return_assign_arg1 = False
        store_count = 0
        load_count = 0
        for inst in instrs:
            tn = type(inst).__name__
            txt = str(inst)
            if not seen_return_assign_arg1:
                # Common shapes: `result = arg1`, `return arg1`,
                # `return arg1 __tailcall`. Tolerant string match.
                if "Set" in tn and arg1_name in txt and "result" in txt:
                    seen_return_assign_arg1 = True
                elif "Ret" in tn and arg1_name in txt:
                    seen_return_assign_arg1 = True
            if "Store" in tn:
                store_count += 1
            if "Load" in tn:
                load_count += 1
            # Some loads appear as `SetVarSsa: x = [...]` — count
            # those bracketed tokens too.
            elif "[" in txt and "]" in txt:
                load_count += 1

        # Memcpy is store-and-load-heavy; demand at least three of
        # each. Real memcpy bodies have far more (byte/word/qword/
        # cacheline branches each emit several stores) but three
        # is a safe floor that filters out short utility helpers.
        if not seen_return_assign_arg1:
            return False
        if store_count < 3 or load_count < 3:
            return False
        return True

    def run(self) -> list[Finding]:
        if self.bv is None:
            return []

        # 0. Pre-pass: identify inlined-memcpy implementations and add
        #    them to PROPAGATORS so name-keyed propagation finds them.
        self._detect_inlined_memcpy_functions()

        # 1a. Synthetic argv source (userspace main parameters)
        self._seed_argv_taint()

        # 1b. Synthetic kernel-module sources (entry-point pointer params)
        self._seed_kernel_module_taint()

        # 1c. Synthetic Windows IOCTL-handler sources (IRP via Win64 ABI)
        self._seed_windows_ioctl_taint()

        # 2. Import-driven sources
        for source_name, addr, mlil_inst in self._enumerate_source_calls():
            output_var = ilh.call_output_ssa(mlil_inst)
            if output_var is None:
                continue
            func = getattr(mlil_inst, "function", None)
            if func is None:
                continue
            self._propagate(output_var, func, depth=0,
                            source_name=source_name, source_addr=addr)

        # Cross-seed deduplication. With per-seed visited tracking
        # multiple seeds may reach the same sink and emit identical
        # Findings. `Finding.compute_id()` hashes
        # (category, binary, address, detector, knowledge_refs) — so
        # duplicates from different seeds collide on id. Deduplicate
        # by id, keeping first-arrived (its `source_name` is the one
        # that wins in evidence; analytically equivalent to second-
        # arrived since the bug shape and location are identical).
        deduped: dict[str, Finding] = {}
        for f in self.findings:
            if f.id not in deduped:
                deduped[f.id] = f
        return list(deduped.values())


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
