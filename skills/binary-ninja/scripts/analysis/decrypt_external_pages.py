"""Decrypt-into-externally-owned-pages detector (Dirty Frag class).

Detects the structural shape behind CVE-2026-43284 (IPsec ESP) and
CVE-2026-43500 (rxrpc). When a Linux kernel module imports BOTH a
scatterlist-from-SKB constructor AND a crypto decrypt sink AND
does NOT import any privately-own gate, the binary plausibly
contains the dirty-frag bug class — in-place decrypt over SKB
pages that may be externally-owned (pipe pages from splice).

v1 (this revision) is binary-scope: import co-presence triggers
emission. High-recall, low-precision — appropriate for the
"first pass" against a corpus where the analyst follows up with
manual review per finding. v2 will tighten via per-function CFG
analysis (constructor → sink edge unguarded by `skb_cow_data` /
`skb_unclone` / `pskb_expand_head` etc.).

Knowledge anchors:
- `[[Memory/Knowledge/dirty_frag_decrypt_into_external_pages]]`
- `[[Memory/Knowledge/argus_kernel_module_taint_via_arg_registers]]`
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in
from ..output.finding import Evidence, Finding, Severity


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
}


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
    return find_decrypt_external_pages(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    )
