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
        # Either v1 (binary-scope) or v2 (xref-resolved) trusted-path
        # primitive satisfies this slot. v2 is the precision-grade
        # signal; v1 is the high-recall fallback. The chain shape
        # cares about presence, not which detector layer fired.
        ("trusted_path_cache_load", "trusted_path_xref_to_load"),
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
# Egg-hunting setup — RWX shellcode exec + PRNG-hidden target address
# ─────────────────────────────────────────────────────────────────


EGG_HUNTING_SETUP = ChainPattern(
    name="chains.egg_hunting_setup",
    description=(
        "RWX shellcode exec primitive + PRNG-hidden target address — "
        "canonical egg-hunting setup; attacker must scan memory for the "
        "egg constant (e.g. 'HTB{') using access() page probing; "
        "alarm(0xFF) required at shellcode start if binary has scan timer"
    ),
    severity=Severity.HIGH,
    category="chain_pattern",
    cwe=["CWE-94", "CWE-338"],
    mitre_attack=["T1203"],
    knowledge_refs=[
        "[[Memory/Knowledge/linux_egghunting_shellcode]]",
        "[[Memory/Knowledge/linux_seccomp_filter]]",
    ],
    primitives=[
        "rwx_shellcode_exec",
        "weak_prng_in_security_path",
    ],
    ordered=False,
    min_primitives=2,
)


# ─────────────────────────────────────────────────────────────────
# ret2win ROP chain — stack BOF + unreachable win function
# ─────────────────────────────────────────────────────────────────


RET2WIN_ROP_CHAIN = ChainPattern(
    name="chains.ret2win_rop_chain",
    description=(
        "Stack buffer overflow + unreachable win function with file I/O — "
        "complete ret2win chain; may require pop gadgets for argument setup "
        "and a ret gadget for SSE stack alignment if win function calls libc"
    ),
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-121", "CWE-94"],
    mitre_attack=["T1203"],
    knowledge_refs=[
        "[[Memory/Knowledge/linux_ret2win_pattern]]",
    ],
    primitives=[
        "stack_buffer_overflow",
        "ret2win_win_function",
    ],
    ordered=False,
    min_primitives=2,
)


# ─────────────────────────────────────────────────────────────────
# Scan-resistant egg-hunt — defensive timer + RWX shellcode exec
# ─────────────────────────────────────────────────────────────────


SCAN_RESISTANT_EGG_HUNT = ChainPattern(
    name="chains.scan_resistant_egg_hunt",
    description=(
        "Defensive alarm timer + RWX shellcode exec — scan-resistant binary "
        "requiring alarm(0xFF) reset at start of any iterative exploit "
        "primitive (egg-hunt, format-string oracle, brute-force) before "
        "the SIGALRM countdown kills the process"
    ),
    severity=Severity.HIGH,
    category="chain_pattern",
    cwe=["CWE-94"],
    mitre_attack=["T1203"],
    knowledge_refs=[
        "[[Memory/Knowledge/linux_egghunting_shellcode]]",
    ],
    primitives=[
        "defensive_alarm_timer",
        "rwx_shellcode_exec",
    ],
    ordered=False,
    min_primitives=2,
)


# ─────────────────────────────────────────────────────────────────
# ret2shellcode — read into stack buffer → direct fn-ptr call
# ─────────────────────────────────────────────────────────────────


RET2SHELLCODE_CHAIN = ChainPattern(
    name="chains.ret2shellcode_exec",
    description=(
        "Stack buffer read directly as executable shellcode — "
        "read() fills stack buffer, program calls that buffer as function pointer; "
        "NX must be disabled; attacker sends raw shellcode as input payload"
    ),
    severity=Severity.CRITICAL,
    category="chain_pattern",
    cwe=["CWE-94", "CWE-121"],
    mitre_attack=["T1203"],
    knowledge_refs=["[[Memory/Knowledge/linux_ret2shellcode_pattern]]"],
    primitives=["ret2shellcode_exec"],
    ordered=False,
    min_primitives=1,
)


# ─────────────────────────────────────────────────────────────────
# Variable overwrite — oversized read() into adjacent guard variable
# ─────────────────────────────────────────────────────────────────


VARIABLE_OVERWRITE_CHAIN = ChainPattern(
    name="chains.variable_overwrite",
    description=(
        "Oversized read() overflows into an adjacent stack variable that gates "
        "a privileged call — attacker writes target_expected_value at "
        "overwrite_offset to satisfy the guard condition and trigger the "
        "privileged branch; no RIP control required"
    ),
    severity=Severity.HIGH,
    category="chain_pattern",
    cwe=["CWE-121"],
    mitre_attack=["T1203"],
    knowledge_refs=[],
    primitives=["adjacent_variable_overwrite"],
    ordered=False,
    min_primitives=1,
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
    EGG_HUNTING_SETUP,
    RET2WIN_ROP_CHAIN,
    SCAN_RESISTANT_EGG_HUNT,
    RET2SHELLCODE_CHAIN,
    VARIABLE_OVERWRITE_CHAIN,
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

    def _slot_categories(slot):
        """A slot is either a str or a tuple/list of strs (any-of)."""
        if isinstance(slot, (tuple, list, set, frozenset)):
            return tuple(slot)
        return (slot,)

    def _slot_present(slot) -> bool:
        return any(c in seen_categories for c in _slot_categories(slot))

    def _slot_label(slot) -> str:
        cats = _slot_categories(slot)
        return cats[0] if len(cats) == 1 else "(" + "|".join(cats) + ")"

    def _slot_match_categories(slot) -> set:
        return {c for c in _slot_categories(slot) if c in seen_categories}

    for chain in PATTERNS:
        if not isinstance(chain, ChainPattern):
            continue
        matched_prims = [s for s in chain.primitives if _slot_present(s)]
        required = (chain.min_primitives if chain.min_primitives is not None
                    else len(chain.primitives))
        if len(matched_prims) < required:
            continue
        # Flatten all categories from all slots for anchor / detail lookup.
        all_chain_cats: set[str] = set()
        for s in chain.primitives:
            all_chain_cats.update(_slot_categories(s))
        anchor = next(
            (f for f in existing_findings if f.category in all_chain_cats),
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
            description_extra=(
                "primitives present: "
                + ", ".join(_slot_label(s) for s in chain.primitives)
            ),
            details={
                "chain_name": chain.name,
                "primitive_findings": [
                    f.id for f in existing_findings if f.category in all_chain_cats
                ],
            },
        ))
    return out
