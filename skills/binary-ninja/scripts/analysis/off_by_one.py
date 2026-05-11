"""Off-by-one bounds-check detector.

Pattern: a function contains a loop whose exit condition is
`CmpUle` or `CmpSle` (`<=`), and the loop body writes to a buffer
indexed by the loop-counter SSA variable. The `<=` instead of `<`
on a loop iterating up to `len` writes one byte past the buffer
(canonical off-by-one).

v1 heuristic — fires when:
  1. The function has at least one `CmpUle`/`CmpSle` instruction
  2. The function has at least one indexed Store
     (`[base + offset]` style addressing)
  3. The comparison's left operand and the Store's address share
     a common ancestor in the SSA def chain (same induction
     variable family).

Knowledge: `[[Memory/Knowledge/ue5_fstring_allocation_amplification]]`
CWE-193.
"""

from __future__ import annotations

from typing import Optional

from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh


CATEGORY_META = {
    "off_by_one": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-193"],
        "mitre": ["T1203"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ue5_fstring_allocation_amplification]]",
            "[[Memory/Knowledge/argus_detector_design_principles]]",
        ],
    },
}


def _walk_ssa_ancestors(function, ssa_var, *, max_hops: int = 8) -> set:
    """Return the set of SSA-var string identities reachable from
    `ssa_var` by walking its def chain. Used to test whether two
    SSA vars share a common ancestor (the same source value).
    """
    out: set = set()
    if ssa_var is None or function is None:
        return out
    frontier = [(ssa_var, max_hops)]
    seen: set = set()
    while frontier:
        cur, depth = frontier.pop()
        if cur is None or depth <= 0:
            continue
        key = str(cur)
        if key in seen:
            continue
        seen.add(key)
        out.add(key)
        defn = ilh.ssa_def_of(function, cur)
        if defn is None:
            continue
        src = getattr(defn, "src", None)
        if src is None:
            # Phi
            op_name = type(defn).__name__
            if "Phi" in op_name:
                for v in (getattr(defn, "src", None) or []):
                    pv = ilh.expr_to_ssa_var(v)
                    if pv is not None:
                        frontier.append((pv, depth - 1))
            continue
        sv = ilh.expr_to_ssa_var(src)
        if sv is not None:
            frontier.append((sv, depth - 1))
        # Walk operands recursively for cases like Add(a, b) — both are ancestors
        for op in (getattr(src, "operands", None) or []):
            sub = ilh.expr_to_ssa_var(op)
            if sub is not None:
                frontier.append((sub, depth - 1))
    return out


def _expr_indexed_load_components(expr):
    """If `expr` is an Add operation between an SSA var and another
    expression (a constant, a multiply, an SSA var), return
    (base_var, index_var). Else (None, None).
    """
    if expr is None:
        return None, None
    op_name = type(expr).__name__
    if "Add" not in op_name:
        return None, None
    left = getattr(expr, "left", None)
    right = getattr(expr, "right", None)
    if left is None or right is None:
        return None, None
    lv = ilh.expr_to_ssa_var(left)
    rv = ilh.expr_to_ssa_var(right)
    # Either side can be base / index; try both arrangements.
    return (lv, rv)


def find_off_by_one(bv, *, binary: str, arch: str, platform: str,
                    detector: str = "analysis.off_by_one"
                    ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings

    for func in (bv.functions or []):
        mlil = getattr(func, "mlil", None)
        if mlil is None:
            continue
        ssa = getattr(mlil, "ssa_form", None) or mlil
        if ssa is None:
            continue

        # Collect comparison sites, indexed-store sites, and
        # indexed-call sites (C++ std::array/std::vector access
        # goes through `operator[]` which surfaces as a Call rather
        # than a direct Store).
        cmp_sites: list[tuple[int, object, object, str]] = []  # (addr, left, right, op_name)
        store_sites: list[tuple[int, object]] = []             # (addr, dest_expr)
        call_index_sites: list[tuple[int, list]] = []          # (addr, params)
        for inst in getattr(ssa, "instructions", []) or []:
            op_name = type(inst).__name__
            addr = int(getattr(inst, "address", 0) or 0)
            if "If" in op_name:
                cond = getattr(inst, "condition", None)
                if cond is None:
                    continue
                cop = type(cond).__name__
                if "CmpUle" in cop or "CmpSle" in cop:
                    left = getattr(cond, "left", None)
                    right = getattr(cond, "right", None)
                    cmp_sites.append((addr, left, right, cop))
            elif "Store" in op_name:
                dest = getattr(inst, "dest", None)
                if dest is None:
                    continue
                store_sites.append((addr, dest))
            elif "Call" in op_name:
                params = ilh.call_params(inst)
                if params:
                    call_index_sites.append((addr, params))

        if not cmp_sites or (not store_sites and not call_index_sites):
            continue

        # Pair: comparison's left operand and store's address share an SSA ancestor.
        for cmp_addr, cleft, cright, cop_name in cmp_sites:
            left_var = ilh.expr_to_ssa_var(cleft)
            if left_var is None:
                continue
            left_ancestors = _walk_ssa_ancestors(ssa, left_var)
            if not left_ancestors:
                continue
            for store_addr, store_dest in store_sites:
                # Indexed dest: dst = base + index_expr
                base_var, idx_var = _expr_indexed_load_components(store_dest)
                # Either operand might carry the loop-counter identity.
                candidates = [v for v in (base_var, idx_var) if v is not None]
                # Also try direct SSA-var resolution on the dest itself.
                direct = ilh.expr_to_ssa_var(store_dest)
                if direct is not None:
                    candidates.append(direct)
                if not candidates:
                    continue
                matched = False
                for cv in candidates:
                    ancestors = _walk_ssa_ancestors(ssa, cv)
                    if ancestors & left_ancestors:
                        matched = True
                        break
                if not matched:
                    continue
                # Emission — anchored at the comparison address.
                sf = getattr(func, "source_function", None) or func
                fname = getattr(sf, "name", "") or f"sub_{getattr(sf, 'start', 0):x}"
                meta = CATEGORY_META["off_by_one"]
                findings.append(Finding(
                    id="",
                    category="off_by_one",
                    severity=meta["severity"],
                    address=int(cmp_addr),
                    function=fname,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=(
                        f"{fname}: loop exit-condition uses "
                        f"{cop_name.replace('MediumLevelILCmp', '').lower()} "
                        f"comparison `{cleft} <= {cright}` and the loop body "
                        f"stores via an SSA-ancestor of the inductor "
                        f"({cleft}). Inclusive loop bound on an array index "
                        f"writes one element past the buffer — canonical "
                        f"off-by-one shape."
                    ),
                    evidence=[Evidence(
                        kind="loop_bound_inclusive_with_buffer_size",
                        source=detector,
                        payload=(f"cmp_op={cop_name} "
                                 f"left={cleft} right={cright} "
                                 f"cmp_addr=0x{cmp_addr:x} "
                                 f"store_addr=0x{store_addr:x}"),
                        address=int(cmp_addr),
                        function=fname,
                    )],
                    details={
                        "comparison_op": cop_name,
                        "operator": "le",
                        "comparison_addr": hex(int(cmp_addr)),
                        "store_addr": hex(int(store_addr)),
                    },
                ))
                # One finding per function is enough.
                break
            else:
                # Try C++-shape: indexed CALL (operator[] / at()) on the
                # inductor SSA.
                emitted_via_call = False
                for call_addr, call_params in call_index_sites:
                    for cp in call_params:
                        cp_var = ilh.expr_to_ssa_var(cp)
                        if cp_var is None:
                            continue
                        ancestors = _walk_ssa_ancestors(ssa, cp_var)
                        if not (ancestors & left_ancestors):
                            continue
                        sf = getattr(func, "source_function", None) or func
                        fname = getattr(sf, "name", "") or f"sub_{getattr(sf, 'start', 0):x}"
                        meta = CATEGORY_META["off_by_one"]
                        findings.append(Finding(
                            id="",
                            category="off_by_one",
                            severity=meta["severity"],
                            address=int(cmp_addr),
                            function=fname,
                            binary=binary, arch=arch, platform=platform,
                            detector=detector,
                            knowledge_refs=list(meta["knowledge_refs"]),
                            cwe=list(meta["cwe"]),
                            mitre_attack=list(meta["mitre"]),
                            description=(
                                f"{fname}: loop exit-condition uses "
                                f"{cop_name.replace('MediumLevelILCmp', '').lower()} "
                                f"and the loop body invokes a callee whose "
                                f"argument shares an SSA ancestor with the "
                                f"inductor — canonical C++ "
                                f"`for (i=0; i<=len; ++i) container[i] = ...` "
                                f"shape via std::array / std::vector "
                                f"operator[]."
                            ),
                            evidence=[Evidence(
                                kind="loop_bound_inclusive_with_buffer_size",
                                source=detector,
                                payload=(f"cmp_op={cop_name} "
                                         f"cmp_addr=0x{cmp_addr:x} "
                                         f"indexed_call_addr=0x{call_addr:x}"),
                                address=int(cmp_addr),
                                function=fname,
                            )],
                            details={
                                "comparison_op": cop_name,
                                "operator": "le",
                                "comparison_addr": hex(int(cmp_addr)),
                                "indexed_call_addr": hex(int(call_addr)),
                            },
                        ))
                        emitted_via_call = True
                        break
                    if emitted_via_call:
                        break
                if emitted_via_call:
                    break
                continue
            break

    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.off_by_one"
            ) -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    return find_off_by_one(bv, binary=binary, arch=arch,
                           platform=platform, detector=detector)
