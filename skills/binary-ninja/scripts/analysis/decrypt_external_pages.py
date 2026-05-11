"""Decrypt-into-externally-owned-pages detector.

Generic bug-class detector: a Linux kernel module that imports
BOTH a scatterlist-from-SKB constructor AND a crypto decrypt sink
AND does NOT import any privately-own gate contains the shape of
in-place decryption over SKB fragments that may be externally
owned (pipe pages from splice / vmsplice / MSG_SPLICE_PAGES).
When the fragments aren't privately owned, the decrypt writes
plaintext into attacker-readable memory.

This detector targets the bug-class shape — not a specific CVE.
Real-world examples in the same class include CVE-2026-43284
(IPsec ESP) and CVE-2026-43500 (rxrpc), which the same detector
emits against organically without per-CVE tuning.

v1 — binary-scope: import co-presence triggers emission. High-
recall, low-precision; useful first-pass triage.
v2 — per-function CFG-aware: constructor → sink dominance edge
not guarded by `skb_cow_data` / `skb_unclone` /
`pskb_expand_head` etc. Lower-recall but per-callsite precision.

Knowledge anchors:
- `[[Memory/Knowledge/dirty_frag_decrypt_into_external_pages]]`
- `[[Memory/Knowledge/argus_kernel_module_taint_via_arg_registers]]`
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh
from . import _cfg_primitives as cfg


# Scatterlist constructors that build a scatterlist from an SKB
# (or from arbitrary buffers — `sg_set_buf`/`sg_init_table` are
# generic, but their presence alongside the SKB-specific ones
# strengthens the case).
_SCATTERLIST_CONSTRUCTORS: frozenset[str] = frozenset({
    "skb_to_sgvec",
    "skb_to_sgvec_nomark",
    "sg_set_buf",
    "sg_set_page",
    "sg_init_table",
    "sg_init_one",
})


# Crypto decrypt sinks that consume a scatterlist. Any of these
# co-present with a constructor and no privately-own gate is the
# v1 trigger.
_CRYPTO_DECRYPT_SINKS: frozenset[str] = frozenset({
    "crypto_aead_decrypt",
    "crypto_skcipher_decrypt",
    "aead_request_set_crypt",
    "skcipher_request_set_crypt",
    "ahash_request_set_crypt",
})


# Privately-own gates: APIs that ensure the SKB's pages are owned
# by the kernel (copying out of external/shared/pipe pages first).
# Presence of any one of these is enough to suggest the binary
# defends against the dirty-frag class.
_PRIVATELY_OWN_GATES: frozenset[str] = frozenset({
    "skb_cow_data",
    "skb_unclone",
    "skb_unclone_keeptruesize",
    "pskb_expand_head",
    "skb_share_check",
    "skb_copy_expand",
    "skb_copy",
})


CATEGORY_META = {
    "decrypt_into_external_pages_candidate": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-119", "CWE-787", "CWE-345"],
        "mitre": ["T1068"],
        "knowledge_refs": [
            "[[Memory/Knowledge/dirty_frag_decrypt_into_external_pages]]",
            "[[Memory/Knowledge/argus_kernel_module_taint_via_arg_registers]]",
        ],
    },
    "decrypt_into_external_pages": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-119", "CWE-787", "CWE-345"],
        "mitre": ["T1068"],
        "knowledge_refs": [
            "[[Memory/Knowledge/dirty_frag_decrypt_into_external_pages]]",
            "[[Memory/Knowledge/argus_kernel_module_taint_via_arg_registers]]",
        ],
    },
}


def _function_call_sites(bv, func, names: frozenset[str]) -> list[tuple[int, str]]:
    """Return [(call_addr, callee_name), ...] for every call inside
    `func` whose callee name is in `names`. Used to locate per-
    function instances of scatterlist constructors / decrypt sinks /
    privately-own gates without re-running ilh.call_sites_of_import
    per call (that scans the whole binary)."""
    out: list[tuple[int, str]] = []
    if func is None:
        return out
    mlil = getattr(func, "mlil", None)
    if mlil is None:
        return out
    ssa = getattr(mlil, "ssa_form", None) or mlil
    try:
        for inst in getattr(ssa, "instructions", []) or []:
            op_name = type(inst).__name__
            if "Call" not in op_name:
                continue
            dest = getattr(inst, "dest", None)
            cval = getattr(dest, "constant", None) if dest else None
            if cval is None:
                continue
            sym = bv.get_symbol_at(int(cval))
            if sym is None:
                continue
            sname = (getattr(sym, "short_name", None)
                     or getattr(sym, "name", "") or "")
            bare = sname[len("__imp_"):] if sname.startswith("__imp_") else sname
            if bare in names:
                out.append((int(getattr(inst, "address", 0)), bare))
    except Exception:
        return out
    return out


def _gate_dominates_decrypt(func, gate_addrs: list[int],
                            decrypt_addr: int) -> bool:
    """True if at least one gate call dominates the decrypt call."""
    for g in gate_addrs:
        try:
            if cfg.instruction_dominates(func, g, decrypt_addr):
                return True
        except Exception:
            continue
    return False


def find_decrypt_external_pages(bv, *, binary: str, arch: str, platform: str,
                                detector: str = "analysis.decrypt_external_pages"
                                ) -> list[Finding]:
    """Binary-scope import co-presence detector for the dirty-frag
    class. Emits one INFO/MEDIUM finding per binary that meets all
    three trigger conditions.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)

    constructors_present = sorted(imports & _SCATTERLIST_CONSTRUCTORS)
    sinks_present = sorted(imports & _CRYPTO_DECRYPT_SINKS)
    gates_present = sorted(imports & _PRIVATELY_OWN_GATES)

    if not constructors_present or not sinks_present:
        return findings
    if gates_present:
        # Privately-own gate is imported; assume the module defends
        # against the dirty-frag class. Could still be a per-callsite
        # FN — the v2 CFG check is needed to confirm. v1 suppresses
        # to keep precision reasonable.
        return findings

    meta = CATEGORY_META["decrypt_into_external_pages_candidate"]
    findings.append(Finding(
        id="",
        category="decrypt_into_external_pages_candidate",
        severity=meta["severity"],
        # Anchor at first scatterlist-constructor call site if
        # locatable, else binary-scope (address 0 + function "<binary>").
        address=0,
        function="<binary>",
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta["knowledge_refs"]),
        cwe=list(meta["cwe"]),
        mitre_attack=list(meta["mitre"]),
        description=(
            f"binary imports scatterlist-from-SKB constructor(s) "
            f"({constructors_present}) and crypto-decrypt sink(s) "
            f"({sinks_present}) but does NOT import any privately-"
            f"own gate (skb_cow_data / skb_unclone / "
            f"pskb_expand_head / skb_share_check / skb_copy_expand). "
            f"This is the structural shape of the Dirty Frag "
            f"(CVE-2026-43284 / CVE-2026-43500) decrypt-into-"
            f"externally-owned-pages bug class. Confirm via per-"
            f"function CFG review (v2 detector pending)."
        ),
        evidence=[Evidence(
            kind="dirty_frag_import_co_presence",
            source=detector,
            payload=(f"constructors={constructors_present} "
                     f"sinks={sinks_present} "
                     f"gates_absent=True"),
            address=0,
            function="<binary>",
        )],
        details={
            "constructors_present": constructors_present,
            "sinks_present": sinks_present,
            "gates_absent": True,
        },
    ))
    return findings


def find_decrypt_external_pages_per_function(
        bv, *, binary: str, arch: str, platform: str,
        detector: str = "analysis.decrypt_external_pages"
) -> list[Finding]:
    """v2 CFG-aware per-function detector.

    For each function: locate scatterlist constructor calls and
    crypto decrypt sink calls IN THE SAME FUNCTION. For each
    constructor → sink edge where the constructor dominates the
    sink, check whether a privately-own gate (skb_cow_data etc.)
    dominates the sink. If not, emit `decrypt_into_external_pages`.

    Closes the v1 gap where the binary-scope check suppresses on
    any global gate import — but the SPECIFIC function carrying
    the bug doesn't actually call the gate. This is the canonical
    Dirty Frag shape: `esp_input` calls `skb_to_sgvec` →
    `crypto_aead_decrypt` without an in-function `skb_cow_data`,
    even though the module imports skb_cow_data for other paths.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    if not (imports & _SCATTERLIST_CONSTRUCTORS):
        return findings
    if not (imports & _CRYPTO_DECRYPT_SINKS):
        return findings

    meta = CATEGORY_META["decrypt_into_external_pages"]
    seen_function_keys: set[int] = set()

    for func in getattr(bv, "functions", []) or []:
        constructor_sites = _function_call_sites(
            bv, func, _SCATTERLIST_CONSTRUCTORS,
        )
        if not constructor_sites:
            continue
        decrypt_sites = _function_call_sites(
            bv, func, _CRYPTO_DECRYPT_SINKS,
        )
        if not decrypt_sites:
            continue
        gate_sites = _function_call_sites(bv, func, _PRIVATELY_OWN_GATES)
        gate_addrs = [a for a, _ in gate_sites]

        fkey = id(func)
        if fkey in seen_function_keys:
            continue

        for c_addr, c_name in constructor_sites:
            for d_addr, d_name in decrypt_sites:
                # Constructor must dominate the decrypt (the
                # scatterlist must be built before being consumed).
                try:
                    constructor_dominates = cfg.instruction_dominates(
                        func, c_addr, d_addr,
                    )
                except Exception:
                    constructor_dominates = False
                if not constructor_dominates:
                    continue
                # Gate must dominate the decrypt to suppress.
                if _gate_dominates_decrypt(func, gate_addrs, d_addr):
                    continue
                seen_function_keys.add(fkey)
                src_func = (getattr(func, "source_function", None) or func)
                func_name = getattr(src_func, "name", "") or f"sub_{func.start:x}"
                findings.append(Finding(
                    id="",
                    category="decrypt_into_external_pages",
                    severity=meta["severity"],
                    address=d_addr,
                    function=func_name,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=(
                        f"{func_name}: scatterlist constructor "
                        f"{c_name}@0x{c_addr:x} dominates crypto "
                        f"decrypt {d_name}@0x{d_addr:x} with no "
                        f"privately-own gate (skb_cow_data / "
                        f"skb_unclone / pskb_expand_head) dominating "
                        f"the decrypt — Dirty Frag class shape."
                    ),
                    evidence=[Evidence(
                        kind="dirty_frag_unguarded_decrypt_edge",
                        source=detector,
                        payload=(f"constructor={c_name}@0x{c_addr:x} "
                                 f"decrypt={d_name}@0x{d_addr:x} "
                                 f"gates_in_fn={len(gate_addrs)} "
                                 f"none_dominate=True"),
                        address=d_addr,
                        function=func_name,
                    )],
                    details={
                        "constructor_name": c_name,
                        "constructor_addr": hex(c_addr),
                        "decrypt_name": d_name,
                        "decrypt_addr": hex(d_addr),
                        "gates_in_function": [hex(a) for a in gate_addrs],
                    },
                ))
                break  # one finding per function is sufficient
            if fkey in seen_function_keys:
                break
    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.decrypt_external_pages"
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
    out.extend(find_decrypt_external_pages(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    out.extend(find_decrypt_external_pages_per_function(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    return out
