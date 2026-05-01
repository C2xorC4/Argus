"""Obfuscation heuristics — packers, control-flow flattening, opaque
predicates, dummy-code injection markers, string-cipher signatures.

Knowledge anchors:
- `[[Memory/Knowledge/gb_obfuscated_code_analysis]]` — Ghidra Book
  obfuscated-code analysis patterns.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — LCG-XOR
  string cipher in production.
- `[[Memory/Knowledge/em_hook_evasion_three_approaches]]` — overlap
  with hash-resolution / NTDLL re-mapping (those live in
  syscalls.py / evasion.py).
"""

from __future__ import annotations

from ._base import (
    BytePattern, ConstantPattern, Pattern, StringPattern, StructuralPattern,
    emit_finding, find_byte_pattern, function_at, section_at, strings_in,
)
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Packer signatures — section names + entry-point heuristics
# ─────────────────────────────────────────────────────────────────


UPX_SECTION_STRINGS = StringPattern(
    name="obfuscation.upx_sections",
    description="UPX section markers (`UPX0`, `UPX1`, `UPX!`) — UPX-packed binary",
    severity=Severity.MEDIUM,
    category="packer_upx",
    mitre_attack=["T1027.002"],
    knowledge_refs=["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
    string_literals=["UPX0", "UPX1", "UPX2", "UPX!", "$Info: This file is packed with the UPX"],
)

THEMIDA_STRINGS = StringPattern(
    name="obfuscation.themida_markers",
    description="Themida / WinLicense markers — protector engagement",
    severity=Severity.MEDIUM,
    category="packer_themida_winlicense",
    mitre_attack=["T1027.002"],
    knowledge_refs=["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
    string_literals=[
        ".themida", ".winlice", "WLLicenseGen",
        "Themida", "WinLicense",
    ],
)

VMPROTECT_STRINGS = StringPattern(
    name="obfuscation.vmprotect_markers",
    description="VMProtect markers — VM-based protector engagement",
    severity=Severity.MEDIUM,
    category="packer_vmprotect",
    mitre_attack=["T1027.002"],
    knowledge_refs=["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
    string_literals=[
        ".vmp0", ".vmp1", ".vmp2",
        "VMProtect",
    ],
)

ASPACK_STRINGS = StringPattern(
    name="obfuscation.aspack_markers",
    description="ASPack section names",
    severity=Severity.LOW,
    category="packer_aspack",
    mitre_attack=["T1027.002"],
    knowledge_refs=[],
    string_literals=[".aspack", ".adata"],
)

PETITE_STRINGS = StringPattern(
    name="obfuscation.petite_markers",
    description="Petite packer section names",
    severity=Severity.LOW,
    category="packer_petite",
    mitre_attack=["T1027.002"],
    knowledge_refs=[],
    string_literals=[".petite"],
)


# ─────────────────────────────────────────────────────────────────
# String-cipher signatures
# ─────────────────────────────────────────────────────────────────


# (LCG constants are also in heuristics/crypto.py; re-cited here in
# obfuscation context.)
LCG_XOR_CIPHER = ConstantPattern(
    name="obfuscation.lcg_xor_cipher",
    description="LCG state-multiplier constants in code — runtime string-decrypt stub",
    severity=Severity.MEDIUM,
    category="lcg_xor_cipher",
    cwe=[],
    mitre_attack=["T1027.013", "T1140"],
    knowledge_refs=["[[Memory/Knowledge/gameguard_research_22_findings]]"],
    constants=[1103515245, 12345, 214013, 2531011],
    bit_widths=[32],
)


# ─────────────────────────────────────────────────────────────────
# Section-entropy — high entropy in non-data sections suggests
# encrypted / packed content. Structural; analysis/obfuscation.py
# owns the calculation.
# ─────────────────────────────────────────────────────────────────


HIGH_ENTROPY_SECTION = StructuralPattern(
    name="obfuscation.high_entropy_section",
    description="Section entropy > 7.0 in `.text` / `.code` — encrypted or packed code",
    severity=Severity.MEDIUM,
    category="high_entropy_section",
    mitre_attack=["T1027.002"],
    knowledge_refs=["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
    shape={"kind": "shannon_entropy", "threshold": 7.0,
           "sections": [".text", ".code"]},
)


# ─────────────────────────────────────────────────────────────────
# Control-flow flattening / opaque predicate
# ─────────────────────────────────────────────────────────────────


CFF_DISPATCHER = StructuralPattern(
    name="obfuscation.cff_dispatcher",
    description="Control-flow-flattening dispatcher loop — single-block switch on a state variable",
    severity=Severity.HIGH,
    category="control_flow_flattening",
    mitre_attack=["T1027"],
    knowledge_refs=["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
    shape={"kind": "cff_dispatcher",
           "min_basic_blocks": 10,
           "switch_state_variable": True},
)

OPAQUE_PREDICATE = StructuralPattern(
    name="obfuscation.opaque_predicate",
    description="Branch whose conditional always evaluates the same way (opaque predicate)",
    severity=Severity.LOW,
    category="opaque_predicate",
    mitre_attack=["T1027"],
    knowledge_refs=["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
    shape={"kind": "always_true_or_false_branch"},
)


# ─────────────────────────────────────────────────────────────────
# RWX section — runtime-decoded payload
# ─────────────────────────────────────────────────────────────────


RWX_SECTION = StructuralPattern(
    name="obfuscation.rwx_section",
    description="Section with READ + WRITE + EXECUTE permissions — runtime-decoded payload candidate",
    severity=Severity.HIGH,
    category="rwx_section",
    mitre_attack=["T1027", "T1620"],
    knowledge_refs=["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
    shape={"kind": "section_perm_check"},
)


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = [
    UPX_SECTION_STRINGS, THEMIDA_STRINGS, VMPROTECT_STRINGS,
    ASPACK_STRINGS, PETITE_STRINGS,
    LCG_XOR_CIPHER,
    HIGH_ENTROPY_SECTION, CFF_DISPATCHER, OPAQUE_PREDICATE,
    RWX_SECTION,
]


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.obfuscation") -> list:
    findings = []
    string_table = strings_in(bv)
    string_values = [s for s, _ in string_table]

    # Section-name strings
    for pat in (UPX_SECTION_STRINGS, THEMIDA_STRINGS, VMPROTECT_STRINGS,
                ASPACK_STRINGS, PETITE_STRINGS):
        hits = [s for s in pat.string_literals if any(s in v for v in string_values)]
        if not hits:
            continue
        first_addr = next(
            (a for v, a in string_table if any(needle in v for needle in pat.string_literals)),
            0,
        )
        findings.append(emit_finding(
            pat,
            address=first_addr, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"strings: {', '.join(hits)}",
            details={"matched_strings": hits},
        ))

    # LCG cipher constants — emit per hit (caller can dedupe)
    from ._base import find_constant
    for c in LCG_XOR_CIPHER.constants:
        for w in LCG_XOR_CIPHER.bit_widths:
            for addr in find_constant(bv, c, w):
                func = function_at(bv, addr)
                findings.append(emit_finding(
                    LCG_XOR_CIPHER,
                    address=addr,
                    function=getattr(func, "name", "") if func else "",
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    description_extra=f"constant 0x{c:x}",
                ))

    # Structural patterns are emitted by analysis/obfuscation.py;
    # here we only emit those that the heuristics layer can detect
    # statically (packer markers, LCG constants).

    return findings
