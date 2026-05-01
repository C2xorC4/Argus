"""Knowledge-derived pattern tables.

Each module exports:

- A `PATTERNS` list of typed Pattern dataclass instances (data;
  curated from LJM Knowledge entries).
- A `match(bv, *, binary, arch, platform, detector=...) -> list[Finding]`
  function that scans a Binja BinaryView and emits Finding objects
  for matched patterns.

Pattern shape lives in `_base.py`. Each Finding carries:

- `category` — unified taxonomy across all detectors.
- `severity` — per-pattern (not per-module).
- `knowledge_refs` — `[[Memory/Knowledge/...]]` wiki-link citation.
- `cwe` / `mitre_attack` — cross-framework mapping.

Detector modules in `../analysis/` consume these tables and emit
the same Finding objects, possibly with structural evidence the
heuristics layer can't produce on its own.

The Knowledge-to-module mapping (Phase 1.1):

    imports.py     — legacy DANGEROUS_FUNCTIONS extended;
                     SOURCES + SINKS + BANNED + FORTIFY pairs
    syscalls.py    — em_direct_syscall_ssn_resolution,
                     wnapi_syscall_mechanics,
                     hw_cross_arch_syscall_conventions,
                     em_hook_evasion_three_approaches
    injection.py   — em_advanced_injection_variants,
                     bhg_process_injection_fundamentals,
                     bhg_windows_type_mapping
    evasion.py     — em_covert_execution_tls_seh,
                     em_peb_antidebug_fields,
                     em_veh_hwbp_hook_evasion,
                     em_hook_evasion_three_approaches,
                     gh_anti_cheat_evasion
    rootkit.py     — em_rootkit_irp_minifilter_callbacks,
                     rb_secure_boot_bypass
    crypto.py      — ue5_prng_handshake_secret_recovery,
                     gameguard_research_22_findings (LCG-XOR)
    mitigations.py — hw_stack_overflow_mechanics,
                     gameguard_research_22_findings (mitigation-absence)
    obfuscation.py — gb_obfuscated_code_analysis,
                     gameguard_research_22_findings (string cipher)
    chains.py      — eac_eos_arbitrary_write_chain,
                     ue5_server_crash_chain_prng_fstring,
                     ue5_fstring_allocation_amplification
    arch.py        — a64_*, wnapi_segment_register_teb_bootstrap,
                     wnapi_peb_teb_structures, em_peb_antidebug_fields
    hooking.py     — gh_hooking_techniques_d3d_iat_vft,
                     gh_anti_cheat_evasion
"""

from . import (
    arch,
    byovd_primitives,
    chains,
    crypto,
    evasion,
    hooking,
    imports,
    injection,
    mitigations,
    obfuscation,
    rootkit,
    syscalls,
)
from ._base import (
    BytePattern,
    ChainPattern,
    ConstantPattern,
    ImportPattern,
    Pattern,
    StringPattern,
    StructuralPattern,
    emit_finding,
    find_byte_pattern,
    find_constant,
    function_at,
    imports_in,
    passes_negative_context,
    section_at,
    strings_in,
)

# All non-chain modules in run order.
ALL_MODULES = (
    imports,
    syscalls,
    injection,
    evasion,
    rootkit,
    byovd_primitives,
    crypto,
    mitigations,
    obfuscation,
    arch,
    hooking,
)


def match_all(bv, *, binary: str, arch: str, platform: str) -> list:
    """Run every heuristics module and return the aggregated Findings.

    Chain detection runs last and consumes the upstream Findings to
    compose chain emissions.
    """
    findings: list = []
    for mod in ALL_MODULES:
        findings.extend(mod.match(bv, binary=binary, arch=arch, platform=platform))
    findings.extend(chains.match(
        bv, binary=binary, arch=arch, platform=platform,
        existing_findings=findings,
    ))
    return findings


__all__ = [
    # Pattern dataclasses + helpers
    "Pattern", "ImportPattern", "StringPattern", "ConstantPattern",
    "BytePattern", "StructuralPattern", "ChainPattern",
    "emit_finding", "find_byte_pattern", "find_constant",
    "function_at", "imports_in", "passes_negative_context",
    "section_at", "strings_in",
    # Modules
    "imports", "syscalls", "injection", "evasion",
    "rootkit", "crypto", "mitigations", "obfuscation",
    "arch", "hooking", "chains",
    "ALL_MODULES", "match_all",
]
