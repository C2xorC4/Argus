"""Shared CFG primitives for analysis modules.

Three load-bearing primitives, each used by multiple Tier-2 detectors
and / or Tier-1 leftover plans:

1. **`instruction_dominates`** — basic-block-level dominator check
   between two MLIL instructions. Used by every detector whose
   emission depends on whether a defensive pattern dominates a
   sink site (integer-OF, type-confusion, TOCTOU).

2. **`has_dominating_comparison_on`** — does a comparison on
   `target_ssa_var` dominate the given site? Drives the integer-OF
   missing-guard signal: per `ec_undefined_behavior_taxonomy`,
   compilers can dead-code-eliminate present-but-redundant guards
   under signed-OF UB; the load-bearing signal is the *absence* of
   the dominating comparison, not the presence of the overflow
   expression.

3. **`allocate_before_read_pattern`** — does the dominant path from
   `alloc_addr` to `sink_addr` lack source reads into the allocation?
   Shared between heap-OF FP suppression (Tier 2 #4) and Plan B
   write-then-verify (Tier 1 leftover). The "untrusted-size
   allocation followed by sink with no data reads in between" CFG
   shape is the canonical FP for naive size-mismatch detectors and
   the canonical TP for the write-then-verify class.

The module is tolerant of Binja API quirks — when CFG / dominator
information is missing, primitives return conservative defaults
(False / None) rather than raising. Detectors should treat None as
"could not determine" and decide whether to emit anyway.
"""

from __future__ import annotations

from typing import Optional

from . import _il_helpers as ilh


# ─────────────────────────────────────────────────────────────────
# Function normalisation
# ─────────────────────────────────────────────────────────────────


def _as_mlil_function(function):
    """Normalise either a `Function` or `MediumLevelILFunction` to
    the MLIL function form (the one with `.basic_blocks`).

    Binja exposes both: `Function.mlil` is the MLIL function,
    `MediumLevelILFunction.basic_blocks` is direct. Detectors call
    these primitives with whichever they have on hand — most
    `analysis/` modules carry `function = call_inst.function`, which
    is already MLIL. The Tier-1 path traversed by
    `analysis/heap.py` carries `function = bv.get_function_at(addr)`,
    the regular `Function`. Accept either.

    Returns None if the input is None or doesn't yield basic blocks
    via either route.
    """
    if function is None:
        return None
    # MediumLevelILFunction has both .basic_blocks AND .source_function
    if hasattr(function, "source_function") and hasattr(function, "basic_blocks"):
        return function
    # Regular Function — pull .mlil
    mlil = getattr(function, "mlil", None)
    if mlil is not None and hasattr(mlil, "basic_blocks"):
        return mlil
    # Generic fallback (some Binja versions expose .basic_blocks elsewhere)
    if hasattr(function, "basic_blocks"):
        return function
    return None


# ─────────────────────────────────────────────────────────────────
# Basic-block lookup
# ─────────────────────────────────────────────────────────────────


def mlil_basic_block_at(function, addr: int):
    """Return the MLIL basic block whose instructions include `addr`,
    or None.

    Walks each block's instructions and returns the block containing
    an instruction whose address equals `addr`. Tolerant of either
    `Function` or `MediumLevelILFunction` inputs.

    Earlier revisions used `block.instruction_range` to compute an
    [inst_start_addr, inst_end_addr] span and short-circuit on
    range membership. That fast-path is unsafe: MLIL instructions
    within a basic block need not be address-monotonic (compilers
    can interleave bytecode addresses across blocks for hot/cold
    splitting, exception unwinders, or COMDAT-folded calls), so the
    range check can either (a) falsely match an addr that's
    physically inside one block's [first_addr, last_addr] span but
    actually belongs to a different block whose instructions weave
    through that range, or (b) miss an addr that's outside the
    [first_addr, last_addr] span but is genuinely an instruction in
    that block. The instruction walk avoids both classes — exact
    address match is unambiguous.
    """
    mlil = _as_mlil_function(function)
    if mlil is None:
        return None
    blocks = getattr(mlil, "basic_blocks", None)
    if blocks is None:
        return None
    for block in blocks:
        try:
            for inst in block:
                if int(getattr(inst, "address", -1)) == addr:
                    return block
        except Exception:
            continue
    return None


# ─────────────────────────────────────────────────────────────────
# Dominator queries
# ─────────────────────────────────────────────────────────────────


def _block_dominators(block) -> list:
    """Return the dominator chain for `block` (block + ancestors).

    Tolerant of API differences across Binja versions. Returns an
    empty list if dominator info is unavailable — caller should treat
    that as "cannot determine dominance."
    """
    if block is None:
        return []
    chain: list = []
    seen: set[int] = set()
    cur = block
    while cur is not None:
        bid = id(cur)
        if bid in seen:
            break
        seen.add(bid)
        chain.append(cur)
        # `dominator` (singular, immediate dominator) or fall back to
        # walking `dominators` set
        idom = getattr(cur, "immediate_dominator", None)
        if idom is None or idom is cur:
            break
        cur = idom
    return chain


def block_dominates(dom_block, sub_block) -> bool:
    """True if `dom_block` dominates `sub_block` in its function CFG.

    Self-dominance is True. If the dominator chain is unavailable
    (e.g., MLIL CFG construction failed), returns False
    conservatively.
    """
    if dom_block is None or sub_block is None:
        return False
    if dom_block is sub_block:
        return True
    # Prefer the precomputed `dominators` set if available
    dominators = getattr(sub_block, "dominators", None)
    if dominators is not None:
        try:
            return dom_block in dominators
        except Exception:
            pass
    # Fallback: walk immediate-dominator chain
    chain = _block_dominators(sub_block)
    return any(b is dom_block for b in chain)


def instruction_dominates(function, dom_addr: int, sub_addr: int) -> bool:
    """True if the instruction at `dom_addr` dominates the instruction
    at `sub_addr` in `function`'s MLIL CFG.

    Same-block: linear order — `dom_addr <= sub_addr` ⇒ True.
    Cross-block: block-level dominator check.

    Returns False conservatively when the CFG / dominator information
    can't be queried.
    """
    if function is None:
        return False
    if dom_addr == sub_addr:
        return True
    dom_block = mlil_basic_block_at(function, dom_addr)
    sub_block = mlil_basic_block_at(function, sub_addr)
    if dom_block is None or sub_block is None:
        return False
    if dom_block is sub_block:
        # Linear order within the same block
        return dom_addr <= sub_addr
    return block_dominates(dom_block, sub_block)


# ─────────────────────────────────────────────────────────────────
# Comparison-on-var dominator query
# ─────────────────────────────────────────────────────────────────


def _expr_uses_ssa_var(expr, target_ssa_var) -> bool:
    """Recursive: does any leaf of `expr` reference `target_ssa_var`?"""
    if expr is None:
        return False
    target_str = str(target_ssa_var)
    # Direct SSA-var reference at this node
    src = getattr(expr, "src", None)
    if src is not None and hasattr(src, "var") and hasattr(src, "version"):
        if str(src) == target_str:
            return True
    operands = getattr(expr, "operands", None)
    if operands is None:
        return False
    for op in operands:
        if _expr_uses_ssa_var(op, target_ssa_var):
            return True
    return False


def _is_comparison_op(inst) -> bool:
    """True iff `inst` is (or contains) a CMP-class MLIL operation.

    Includes `IF` (whose condition is implicitly a comparison), direct
    `CMP_*` nodes, and `SET_FLAG` patterns that classify as compares.
    """
    if inst is None:
        return False
    op = getattr(inst, "operation", None)
    op_name = getattr(op, "name", "") if op is not None else ""
    if not op_name:
        op_name = type(inst).__name__
    return ("CMP" in op_name
            or "IF" in op_name
            or "TEST" in op_name
            or "SET_FLAG" in op_name)


def has_dominating_comparison_on(function,
                                 sub_addr: int,
                                 target_ssa_var) -> bool:
    """True iff some comparison instruction in `function` references
    `target_ssa_var` and dominates the instruction at `sub_addr`.

    Used by the integer-OF missing-guard signal: detectors invert
    this — a sink at `sub_addr` with `target_ssa_var` carrying
    attacker-controlled allocation size and `has_dominating_comparison_on(...)
    == False` is the Finding.
    """
    if function is None or target_ssa_var is None:
        return False
    mlil = _as_mlil_function(function)
    if mlil is None:
        return False

    # Iterate every MLIL instruction; cheap on small functions, the
    # hot path is bounded by function size. Detectors can short-circuit
    # by walking only basic blocks that dominate sub_block.
    sub_block = mlil_basic_block_at(function, sub_addr)
    if sub_block is None:
        return False

    for block in getattr(mlil, "basic_blocks", []) or []:
        if not block_dominates(block, sub_block):
            continue
        for inst in block:
            inst_addr = int(getattr(inst, "address", 0))
            # Same-block, instruction must precede sub_addr
            if block is sub_block and inst_addr > sub_addr:
                continue
            if not _is_comparison_op(inst):
                continue
            if _expr_uses_ssa_var(inst, target_ssa_var):
                return True
            # Some comparisons embed the var in a child expression
            # (e.g., `if (var > MAX_FRAME) ...`) — descend.
            condition = getattr(inst, "condition", None)
            if condition is not None and _expr_uses_ssa_var(condition, target_ssa_var):
                return True
            for child_attr in ("left", "right", "src"):
                child = getattr(inst, child_attr, None)
                if child is not None and _expr_uses_ssa_var(child, target_ssa_var):
                    return True
    return False


# ─────────────────────────────────────────────────────────────────
# allocate-before-read pattern
# ─────────────────────────────────────────────────────────────────


def _instructions_between(function, start_addr: int, end_addr: int) -> list:
    """Return MLIL instructions on paths from start_addr to end_addr.

    Approximation: returns instructions whose addresses fall within
    `[start_addr, end_addr]` AND are in basic blocks reachable from
    start_block and that reach end_block. For the use cases here
    (alloc → sink within one function, typically same DAG region)
    this is sufficient. For multi-path / loop regions the result is
    a superset — consumers should handle that.
    """
    if function is None:
        return []
    mlil = _as_mlil_function(function)
    if mlil is None:
        return []
    start_block = mlil_basic_block_at(function, start_addr)
    end_block = mlil_basic_block_at(function, end_addr)
    if start_block is None or end_block is None:
        return []
    out: list = []
    for block in getattr(mlil, "basic_blocks", []) or []:
        # Block must be reachable from start_block (start dominates
        # block OR block is start) AND end_block reachable from block.
        if not (block_dominates(start_block, block) or block is start_block):
            continue
        if not (block_dominates(block, end_block) or block is end_block):
            continue
        for inst in block:
            inst_addr = int(getattr(inst, "address", 0))
            # In the start block, only count instructions at-or-after start_addr
            if block is start_block and inst_addr < start_addr:
                continue
            # In the end block, only count instructions at-or-before end_addr
            if block is end_block and inst_addr > end_addr:
                continue
            out.append(inst)
    return out


def _is_load_into(expr, alloc_handle_var) -> bool:
    """True iff `expr` is a load whose address is alloc_handle_var (or
    arithmetic on it) — i.e. a read FROM the allocation."""
    if expr is None:
        return False
    op_name = type(expr).__name__
    if "Load" in op_name:
        src = getattr(expr, "src", None)
        if src is not None and _expr_uses_ssa_var(src, alloc_handle_var):
            return True
    operands = getattr(expr, "operands", None)
    if operands is None:
        return False
    for op in operands:
        if _is_load_into(op, alloc_handle_var):
            return True
    return False


def _is_store_into(inst, alloc_handle_var) -> bool:
    """True iff `inst` is a store whose destination is alloc_handle_var
    (or arithmetic on it) — i.e. a write INTO the allocation."""
    op_name = type(inst).__name__
    if "Store" not in op_name:
        return False
    dest = getattr(inst, "dest", None)
    if dest is None:
        return False
    return _expr_uses_ssa_var(dest, alloc_handle_var)


def allocate_before_read_pattern(function,
                                 alloc_addr: int,
                                 sink_addr: int,
                                 alloc_handle_var) -> Optional[bool]:
    """Detect the "allocate-before-read" CFG shape.

    Returns True iff the path from `alloc_addr` to `sink_addr` lacks
    *data reads from* the allocation (writes are fine — they're
    initialising). The signal class is "untrusted-size allocation
    followed by sink with no preceding read into the allocation."

    Returns False if at least one load FROM the allocation appears
    between alloc and sink.

    Returns None if the analysis can't be completed (no CFG, etc.) —
    callers should treat None as "uncertain, do not over-suppress."

    Used by:
    - Tier 2 #4 heap-OF FP suppression: True ⇒ FP candidate (the
      allocation isn't being filled with data before the size-shaped
      sink — likely benign reservation pattern).
    - Plan B (write-then-verify): True followed by a verification
      sink ⇒ the canonical pre-verification-write pattern.
    """
    if function is None or alloc_handle_var is None:
        return None
    if alloc_addr == sink_addr:
        return True

    insts = _instructions_between(function, alloc_addr, sink_addr)
    if not insts:
        return None

    for inst in insts:
        # Direct load whose address uses alloc_handle_var
        if _is_load_into(inst, alloc_handle_var):
            return False
        # Some loads are nested in expression operands of SetVarSsa
        # (e.g., `x = [alloc_handle + 8]`). Walk operands.
        operands = getattr(inst, "operands", None)
        if operands is not None:
            for op in operands:
                if _is_load_into(op, alloc_handle_var):
                    return False
    return True


# ─────────────────────────────────────────────────────────────────
# Convenience: full-init coverage check (heuristic)
# ─────────────────────────────────────────────────────────────────


def has_full_init_writes_between(function,
                                 alloc_addr: int,
                                 sink_addr: int,
                                 alloc_handle_var,
                                 alloc_size_var=None,
                                 *,
                                 store_threshold: int = 4) -> Optional[bool]:
    """Heuristic: does the path between alloc and sink contain enough
    writes into the allocation that the buffer is plausibly fully
    initialised before the sink?

    Two acceptance shapes:

    1. A `memset` call where dest == alloc_handle_var anywhere on the
       path → return True (full fill demonstrated).
    2. Otherwise, count Store-class instructions whose dest involves
       alloc_handle_var. Return True iff count >= store_threshold.

    Returns False if no stores into the allocation are observed.
    Returns None if CFG can't be queried.

    This is intentionally a *heuristic* — precise per-byte coverage
    requires interval tracking on offset operands, which a Phase-1
    primitive shouldn't ship. The threshold is configurable so
    detectors can tune; default 4 catches simple struct-init patterns
    while tolerating partial-init cases that are real uninit-mem
    candidates.

    Used by Tier 2 #5 (uninit-mem-disclosure) for the negative
    pattern: `not has_full_init_writes_between(...)` ⇒ candidate.
    """
    if function is None or alloc_handle_var is None:
        return None
    insts = _instructions_between(function, alloc_addr, sink_addr)
    if not insts:
        return None

    store_count = 0
    for inst in insts:
        # memset call into the allocation?
        op_name_outer = type(inst).__name__
        if "Call" in op_name_outer:
            params = ilh.call_params(inst)
            if params:
                dst = params[0]
                if _expr_uses_ssa_var(dst, alloc_handle_var):
                    callee_addr = ilh.callee_address_of_call(inst)
                    if callee_addr is not None:
                        bv = getattr(function, "view", None) or getattr(function, "_view", None)
                        if bv is not None:
                            sym = bv.get_symbol_at(callee_addr)
                            cname = (getattr(sym, "short_name", None)
                                     or getattr(sym, "name", "")) if sym else ""
                            if cname in ("memset", "RtlZeroMemory",
                                         "RtlSecureZeroMemory", "ZeroMemory",
                                         "bzero", "__memset_chk"):
                                return True
        if _is_store_into(inst, alloc_handle_var):
            store_count += 1

    if store_count >= store_threshold:
        return True
    if store_count == 0:
        return False
    # Partial init: ambiguous. Conservative-true (don't over-flag uninit).
    return True
