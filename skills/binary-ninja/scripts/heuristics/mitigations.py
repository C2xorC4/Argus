"""Mitigation matrix heuristics — hardening-flag detection metadata.

Most patterns here are *structural* — the actual extraction of
hardening flags from PE / ELF headers happens in
`analysis/mitigations.py`. This module catalogs:

- Which fields of which header indicate which mitigation.
- The FORTIFY-checked-vs-unchecked import pairs (for FORTIFY
  presence detection).
- The mitigation-weight table that drives mitigation-weighted
  exploitability scoring.

Knowledge anchors:
- `[[Memory/Knowledge/hw_stack_overflow_mechanics]]` — canary mechanics.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — the
  mitigation-absence-as-finding case (zero /GS, no CFG, ASLR partial
  → any memory-corruption bug deterministically exploitable).
"""

from __future__ import annotations

from ._base import (
    ImportPattern, Pattern, StructuralPattern,
    emit_finding, imports_in,
)
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Hardening-flag detection map
# Each entry: (name, source_format, field_path, present_value, absence_severity)
#
# `source_format`: "pe" or "elf"
# `field_path`: dotted descriptor of where in the header the flag lives
# `absence_severity`: severity of a Finding emitted when this is *missing*
# ─────────────────────────────────────────────────────────────────


PE_HARDENING_MAP: list[tuple[str, str, str, str]] = [
    # (mitigation, descriptor, present_when, absence_severity)
    ("ASLR",           "OptionalHeader.DllCharacteristics & DYNAMIC_BASE", "set",     "high"),
    ("DEP",            "OptionalHeader.DllCharacteristics & NX_COMPAT",     "set",     "critical"),
    ("CFG",            "OptionalHeader.DllCharacteristics & GUARD_CF",      "set",     "medium"),
    ("CET",            "OptionalHeader.DllCharacteristics & CET_COMPAT",    "set",     "medium"),
    ("HighEntropyVA",  "OptionalHeader.DllCharacteristics & HIGH_ENTROPY",  "set",     "low"),
    ("ForceIntegrity", "OptionalHeader.DllCharacteristics & FORCE_INTEGRITY", "set",   "low"),
    ("SafeSEH",        "LoadConfig.SEHandlerTable",                          "non-zero", "medium"),
    ("GS",             "LoadConfig.SecurityCookie",                          "non-zero", "high"),
]

ELF_HARDENING_MAP: list[tuple[str, str, str, str]] = [
    ("PIE",            "ELF.e_type",                            "ET_DYN",   "high"),
    ("NX",             "PT_GNU_STACK.p_flags",                  "no PF_X",  "critical"),
    ("RELRO_FULL",     "DYNAMIC.DT_BIND_NOW + PT_GNU_RELRO",    "both",     "medium"),
    ("RELRO_PARTIAL",  "PT_GNU_RELRO",                          "present",  "low"),
    ("CANARY",         "DYNSYM contains __stack_chk_fail",       "present",  "high"),
    ("FORTIFY",        "DYNSYM contains __*_chk variants",       "present",  "low"),
]


# ─────────────────────────────────────────────────────────────────
# FORTIFY detection — pair-presence test
# When `__strcpy_chk` etc. is imported, FORTIFY is enabled.
# When only the unchecked variant is imported, FORTIFY is missing.
# ─────────────────────────────────────────────────────────────────


FORTIFY_VARIANT_PAIRS: dict[str, str] = {
    "strcpy":   "__strcpy_chk",
    "strcat":   "__strcat_chk",
    "memcpy":   "__memcpy_chk",
    "memmove":  "__memmove_chk",
    "memset":   "__memset_chk",
    "sprintf":  "__sprintf_chk",
    "snprintf": "__snprintf_chk",
    "vsprintf": "__vsprintf_chk",
    "vsnprintf": "__vsnprintf_chk",
    "fprintf":  "__fprintf_chk",
    "printf":   "__printf_chk",
    "fgets":    "__fgets_chk",
    "read":     "__read_chk",
    "stpcpy":   "__stpcpy_chk",
    "strncat":  "__strncat_chk",
    "strncpy":  "__strncpy_chk",
}


# ─────────────────────────────────────────────────────────────────
# Mitigation-weighted exploitability table
# Used by analysis/mitigations.py to compute Finding's
# `mitigation_weighted_exploitability` score.
#
# weights[bug_class][mitigation] = factor in [0.0, 1.0]
# 1.0  = mitigation has no effect on this bug class
# 0.0  = mitigation defeats the canonical exploit
# Multiplicative across mitigations present.
# ─────────────────────────────────────────────────────────────────


EXPLOITABILITY_WEIGHTS: dict[str, dict[str, float]] = {
    "stack_buffer_overflow": {
        "GS":      0.3,    # canary check defeats trivial trigger
        "ASLR":    0.5,    # mattering for ROP, not trigger
        "DEP":     0.6,    # forces ROP
        "CFG":     1.0,    # CFG guards indirect calls, not returns
        "CET":     0.1,    # shadow stack defeats RIP overwrite
        "PAC":     0.5,    # ARM analog of canary
    },
    "heap_buffer_overflow": {
        "ASLR":    0.7,
        "DEP":     0.7,
        "CFG":     0.4,    # vtable hijack typically blocked
        "CET":     0.3,
        "MTE":     0.05,   # ARM tag-mismatch detect
    },
    "use_after_free": {
        "ASLR":    0.7,
        "CFG":     0.4,
        "CET":     0.3,
        "MTE":     0.05,
    },
    "format_string": {
        "FORTIFY": 0.05,   # __printf_chk validates format
        "ASLR":    0.6,
    },
    "type_confusion": {
        "CFI":     0.05,   # vtable validation
        "CFG":     0.4,
    },
    "weak_prng_in_security_path": {
        # Mitigations don't change PRNG predictability.
    },
    "command_injection": {},
    "path_traversal": {},
    "direct_syscall_stub": {
        "ETW":     0.5,    # ETW Threat-Intel can detect
        "PT":      0.4,    # Intel PT trace can flag
    },
}


# ─────────────────────────────────────────────────────────────────
# Patterns
# ─────────────────────────────────────────────────────────────────


MITIGATION_PROFILE = StructuralPattern(
    name="mitigations.profile",
    description="Per-target hardening profile — extracted from PE/ELF headers and FORTIFY pairs",
    severity=Severity.INFO,
    category="mitigation_profile",
    knowledge_refs=[
        "[[Memory/Knowledge/hw_stack_overflow_mechanics]]",
        "[[Memory/Knowledge/gameguard_research_22_findings]]",
    ],
    shape={"kind": "header_extract", "format": "pe_or_elf"},
)


PATTERNS: list[Pattern] = [
    MITIGATION_PROFILE,
]


# ─────────────────────────────────────────────────────────────────
# Public API — mostly utility for analysis/mitigations.py to consume
# ─────────────────────────────────────────────────────────────────


def detect_fortify(bv) -> tuple[bool, list[str]]:
    """Return (fortify_enabled, list_of_unchecked_imports_present).

    `fortify_enabled` is True when at least one `__*_chk` variant is
    imported. The unchecked-list helps identify code paths the
    compiler couldn't prove safe at build time.
    """
    imports = imports_in(bv)
    chk_present = any(checked in imports for checked in FORTIFY_VARIANT_PAIRS.values())
    unchecked = [unchecked for unchecked, checked in FORTIFY_VARIANT_PAIRS.items()
                 if unchecked in imports and checked not in imports]
    return chk_present, unchecked


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.mitigations") -> list:
    """Emit a single Finding describing the binary's hardening posture
    when FORTIFY is missing on at least one banned-variant pair.

    Header-based mitigation extraction (CFG/ASLR/CFI/etc.) lives in
    `analysis/mitigations.py` because it needs raw PE/ELF parsing that
    extends beyond the heuristics-module brief.
    """
    fortify_on, unchecked = detect_fortify(bv)
    if fortify_on or not unchecked:
        return []
    return [emit_finding(
        MITIGATION_PROFILE,
        address=0, function="<binary>",
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        description_extra=(
            f"FORTIFY appears disabled — {len(unchecked)} unchecked variant(s) imported "
            f"({', '.join(unchecked[:8])})"
        ),
        details={"fortify_enabled": False, "unchecked_imports": unchecked},
    )]
