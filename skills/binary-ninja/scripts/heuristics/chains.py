"""Chain templates — multi-primitive composition patterns.

Catalog of known chain shapes. The pattern carries metadata
(severity, Knowledge refs, ordered primitive list); the actual
recogniser lives in `analysis/chains.py`, which scans the binary
for the constituent primitives and confirms the composition.

Each chain emits one composite Finding (category="chain_pattern")
in addition to the per-primitive findings the underlying detectors
produce.

Knowledge anchors:
- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — the
  Permissive-SDDL → pre-verify-write → cleanup → cache-poison
  chain (EAC EOS).
- `[[Memory/Knowledge/ue5_server_crash_chain_prng_fstring]]` — the
  PRNG → cookie-forge → amplification chain.
- `[[Memory/Knowledge/ue5_fstring_allocation_amplification]]` — the
  amplification primitive in the UE5 chain.
"""

from __future__ import annotations

from ._base import ChainPattern, Pattern
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# EAC chain — permissive-SDDL → pre-verify-write → missing cleanup
# → cache poison
# ─────────────────────────────────────────────────────────────────


EAC_PERMISSIVE_PREWRITE_CACHE = ChainPattern(
    name="chains.eac_permissive_prewrite_cleanup_cache",
    description=(
        "Permissive-SDDL on named IPC + pre-verification write + "
        "missing cleanup on verify-fail + downstream cache load — "
        "the EAC arbitrary-write chain shape"
    ),
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-732", "CWE-471", "CWE-459", "CWE-345"],
    mitre_attack=["T1574", "T1068"],
    knowledge_refs=["[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]"],
    primitives=[
        "permissive_sddl",
        "pre_verification_write",
        # Now-implemented v1 detectors (2026-05-07):
        #  - `missing_cleanup_on_failure`: analysis/cleanup_dominance.py
        #    (coarse — fires on commit-without-rollback-import).
        #  - `trusted_path_cache_load`: analysis/trusted_path.py
        #    (binary-scope — attacker-writable path string + load API).
        # Both are minimal-v1 forms; tightening from coarse-recall to
        # precision-aware versions is future work.
        "missing_cleanup_on_failure",
        "trusted_path_cache_load",
    ],
    ordered=True,
    same_function=False,
)


# ─────────────────────────────────────────────────────────────────
# UE5 chain — PRNG → cookie-forge → amplification
# ─────────────────────────────────────────────────────────────────


UE5_PRNG_COOKIE_AMPLIFICATION = ChainPattern(
    name="chains.ue5_prng_cookie_amplification",
    description=(
        "Weak PRNG in security path + signed-token bypass + "
        "size-amplification DoS — UE5 server-crash chain shape"
    ),
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-338", "CWE-345", "CWE-770"],
    mitre_attack=["T1499"],
    knowledge_refs=[
        "[[Memory/Knowledge/ue5_server_crash_chain_prng_fstring]]",
        "[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]",
        "[[Memory/Knowledge/ue5_fstring_allocation_amplification]]",
    ],
    primitives=[
        "weak_prng_in_security_path",
        # `signed_token_with_recoverable_secret` would correlate the
        # PRNG output with HMAC / signature material. Aspirational —
        # no detector today.
        "signed_token_with_recoverable_secret",
        # `size_amplification` would detect FString-style
        # allocate-then-fill-from-untrusted-size patterns. Currently
        # the heap-OF detector covers part of this; deferred until a
        # dedicated detector lands.
        "size_amplification",
    ],
    ordered=True,
    # Only `weak_prng_in_security_path` has an implementing detector
    # as of 2026-05-07; raise this to 3 when the other two land.
    min_primitives=1,
)


# ─────────────────────────────────────────────────────────────────
# Classical info-leak → UAF → ROP
# ─────────────────────────────────────────────────────────────────


CLASSIC_INFOLEAK_UAF_ROP = ChainPattern(
    name="chains.infoleak_uaf_rop",
    description="Stack/heap address disclosure + lifetime bug + gadget chain — classical heap-OF/UAF chain",
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-416", "CWE-200"],
    mitre_attack=["T1203"],
    knowledge_refs=[
        "[[Memory/Knowledge/wnapi_heap_internals]]",
        "[[Memory/Knowledge/em_advanced_injection_variants]]",
    ],
    primitives=[
        "uninitialised_memory_disclosure",
        "use_after_free",
    ],
    ordered=False,
)


# ─────────────────────────────────────────────────────────────────
# Format-string → stack-OF → ROP
# ─────────────────────────────────────────────────────────────────


CLASSIC_FMTLEAK_STACK_ROP = ChainPattern(
    name="chains.fmtleak_stack_rop",
    description="Format-string for canary/PIE leak + stack-OF + ROP",
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-134", "CWE-121"],
    mitre_attack=["T1203"],
    knowledge_refs=[],
    primitives=[
        "format_string",
        "stack_buffer_overflow",
    ],
    ordered=False,
)


# ─────────────────────────────────────────────────────────────────
# Heap-OF → vtable hijack → ROP (C++ classical)
# ─────────────────────────────────────────────────────────────────


CLASSIC_HEAPOF_VTABLE_ROP = ChainPattern(
    name="chains.heapof_vtable_rop",
    description="Adjacent heap chunk overflow + C++ object overlap + virtual-call hijack",
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-122", "CWE-843"],
    mitre_attack=["T1203"],
    knowledge_refs=["[[Memory/Knowledge/wnapi_heap_internals]]"],
    primitives=[
        "heap_buffer_overflow",
        "type_confusion",
    ],
    ordered=True,
)


# ─────────────────────────────────────────────────────────────────
# TOCTOU → junction redirect → SYSTEM write
# ─────────────────────────────────────────────────────────────────


TOCTOU_JUNCTION_SYSTEM_WRITE = ChainPattern(
    name="chains.toctou_junction_system_write",
    description="TOCTOU race + symlink/junction redirect + privileged file op — admin → SYSTEM scenario",
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-367", "CWE-732"],
    mitre_attack=["T1574.005"],
    knowledge_refs=["[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]"],
    primitives=[
        "toctou",
        "pre_verification_write",
    ],
    ordered=True,
)


# ─────────────────────────────────────────────────────────────────
# Type confusion → arbitrary read → deref-anywhere
# ─────────────────────────────────────────────────────────────────


TYPECONF_ARBREAD_DEREF = ChainPattern(
    name="chains.typeconf_arbread_deref",
    description="Type-confusion → arbitrary-read primitive → controlled deref → RCE",
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-843", "CWE-125"],
    mitre_attack=["T1203"],
    knowledge_refs=[
        "[[Memory/Knowledge/ec_undefined_behavior_taxonomy]]",
        "[[Memory/Knowledge/bhg_unsafe_pointer_patterns]]",
    ],
    primitives=["type_confusion"],
    ordered=False,
)


# ─────────────────────────────────────────────────────────────────
# Deserialisation → gadget chain → RCE
# ─────────────────────────────────────────────────────────────────


DESERIALIZATION_GADGET_RCE = ChainPattern(
    name="chains.deserialization_gadget_rce",
    description="Unsafe deserialiser + class-graph gadgets + execution",
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-502"],
    mitre_attack=["T1190"],
    knowledge_refs=[],
    primitives=["insecure_deserialization"],
    ordered=False,
)


# ─────────────────────────────────────────────────────────────────
# Direct-syscall + TLS callback + hidden thread (malware evasion stack)
# ─────────────────────────────────────────────────────────────────


MALWARE_EVASION_STACK = ChainPattern(
    name="chains.malware_evasion_stack",
    description="Direct-syscall stub + TLS-callback first-stage + hidden-from-debugger thread — full evasion stack",
    severity=Severity.HIGH,
    category="chain_pattern",
    cwe=[],
    mitre_attack=["T1106", "T1027", "T1622"],
    knowledge_refs=[
        "[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]",
        "[[Memory/Knowledge/em_covert_execution_tls_seh]]",
    ],
    primitives=[
        "direct_syscall_stub",
        "tls_callback_present",
        "hidden_from_debugger_thread",
    ],
    ordered=False,
)


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = [
    EAC_PERMISSIVE_PREWRITE_CACHE,
    UE5_PRNG_COOKIE_AMPLIFICATION,
    CLASSIC_INFOLEAK_UAF_ROP,
    CLASSIC_FMTLEAK_STACK_ROP,
    CLASSIC_HEAPOF_VTABLE_ROP,
    TOCTOU_JUNCTION_SYSTEM_WRITE,
    TYPECONF_ARBREAD_DEREF,
    DESERIALIZATION_GADGET_RCE,
    MALWARE_EVASION_STACK,
]


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.chains",
          existing_findings: list = None) -> list:
    """Compose chain findings from per-primitive findings already emitted.

    `existing_findings` is the list returned by upstream heuristics
    + analysis modules. We don't re-scan the binary here; we look
    for the listed primitives in the existing findings list and emit
    a chain Finding when all required primitives are present.

    The orchestrator typically calls this after every other analysis
    has run.
    """
    if existing_findings is None:
        return []
    seen_categories = {f.category for f in existing_findings}
    out = []
    for chain in PATTERNS:
        if not isinstance(chain, ChainPattern):
            continue
        matched_prims = [p for p in chain.primitives if p in seen_categories]
        required = (chain.min_primitives if chain.min_primitives is not None
                    else len(chain.primitives))
        if len(matched_prims) < required:
            continue
        # Anchor the chain finding at the first matching primitive
        anchor = next(
            (f for f in existing_findings if f.category in chain.primitives),
            None,
        )
        if anchor is None:
            continue
        from ._base import emit_finding
        out.append(emit_finding(
            chain,
            address=anchor.address,
            function=anchor.function,
            binary=anchor.binary or binary,
            arch=anchor.arch or arch,
            platform=anchor.platform or platform,
            detector=detector,
            description_extra=f"primitives present: {', '.join(chain.primitives)}",
            details={
                "chain_name": chain.name,
                "primitive_findings": [
                    f.id for f in existing_findings if f.category in chain.primitives
                ],
            },
        ))
    return out
