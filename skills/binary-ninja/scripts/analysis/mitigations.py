"""Mitigation-matrix analysis — extract hardening flags + score findings.

Two responsibilities:

1. **Extract** — parse PE / ELF headers + scan symbols to populate
   a `TargetMitigations` profile. PE coverage is comprehensive
   (DllCharacteristics + LoadConfig); ELF coverage is partial in
   Phase 1 (ET_DYN / GNU_STACK / canary symbol presence).

2. **Score** — compute `mitigation_weighted_exploitability` for a
   Finding, using the per-bug-class weight table from
   `heuristics/mitigations.py:EXPLOITABILITY_WEIGHTS`.

Both responsibilities are pure functions over `TargetMitigations`
and `Finding`; the orchestrator wires them in after the recon stage
finishes building the profile.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Optional

from ..heuristics import mitigations as heur_mitigations
from ..output.finding import Finding, TargetMitigations


# ─────────────────────────────────────────────────────────────────
# PE constants
# ─────────────────────────────────────────────────────────────────


# DllCharacteristics flags (winnt.h)
PE_HIGH_ENTROPY_VA   = 0x0020
PE_DYNAMIC_BASE      = 0x0040     # ASLR
PE_FORCE_INTEGRITY   = 0x0080
PE_NX_COMPAT         = 0x0100     # DEP/NX
PE_NO_SEH            = 0x0400
PE_GUARD_CF          = 0x4000     # CFG

# Magic field values
PE_MAGIC_PE32        = 0x010B
PE_MAGIC_PE32_PLUS   = 0x020B


# ─────────────────────────────────────────────────────────────────
# PE extraction — parse raw header bytes
# ─────────────────────────────────────────────────────────────────


def _read_file_bytes(path: str, max_bytes: int = 1 << 20) -> bytes:
    """Read up to `max_bytes` from `path` for header parsing."""
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except OSError:
        return b""


def _parse_pe_optional_header_offset(data: bytes) -> Optional[int]:
    """Return offset of the PE optional header within `data`, or None."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew + 0x18 > len(data):
        return None
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    return e_lfanew + 0x18    # COFF header is 0x18 bytes (sig + 20)


def _extract_pe_mitigations(data: bytes) -> TargetMitigations:
    m = TargetMitigations()
    opt_off = _parse_pe_optional_header_offset(data)
    if opt_off is None:
        return m
    if opt_off + 0x48 > len(data):
        return m

    magic = int.from_bytes(data[opt_off:opt_off + 2], "little")
    # DllCharacteristics is at offset 0x46 in both PE32 and PE32+.
    dll_chars = int.from_bytes(data[opt_off + 0x46:opt_off + 0x48], "little")

    m.ASLR = bool(dll_chars & PE_DYNAMIC_BASE)
    m.DEP  = bool(dll_chars & PE_NX_COMPAT)
    m.CFG  = bool(dll_chars & PE_GUARD_CF)
    m.SAFESEH = bool(dll_chars & PE_NO_SEH) is False    # NO_SEH set = SafeSEH disabled
    # CET shadow stack is encoded in LoadConfig.ExtendedFlags; not
    # parsed in v1. Mark unknown.
    m.CET = None
    # FORTIFY does not apply to PE; unknown.
    m.FORTIFY = None

    m.extras["pe_magic"] = "PE32+" if magic == PE_MAGIC_PE32_PLUS else "PE32"
    m.extras["pe_dll_characteristics"] = dll_chars
    m.extras["pe_high_entropy_va"] = bool(dll_chars & PE_HIGH_ENTROPY_VA)
    m.extras["pe_force_integrity"] = bool(dll_chars & PE_FORCE_INTEGRITY)

    return m


# ─────────────────────────────────────────────────────────────────
# ELF extraction — minimal in Phase 1: e_type + PT_GNU_STACK,
# plus canary / FORTIFY via symbol scan when bv is provided
# ─────────────────────────────────────────────────────────────────


# ELF constants
ET_EXEC      = 2
ET_DYN       = 3
PT_LOAD      = 1
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X         = 0x1


def _extract_elf_mitigations(data: bytes) -> TargetMitigations:
    m = TargetMitigations()
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        return m

    is_64bit = data[4] == 2
    little = data[5] == 1
    endian = "little" if little else "big"

    e_type = int.from_bytes(data[0x10:0x12], endian)
    m.PIE = (e_type == ET_DYN)

    # Program-header table
    if is_64bit:
        e_phoff = int.from_bytes(data[0x20:0x28], endian)
        e_phentsize = int.from_bytes(data[0x36:0x38], endian)
        e_phnum = int.from_bytes(data[0x38:0x3A], endian)
    else:
        e_phoff = int.from_bytes(data[0x1C:0x20], endian)
        e_phentsize = int.from_bytes(data[0x2A:0x2C], endian)
        e_phnum = int.from_bytes(data[0x2C:0x2E], endian)

    nx = None
    relro = None
    for i in range(e_phnum):
        ph_off = e_phoff + i * e_phentsize
        if ph_off + e_phentsize > len(data):
            break
        p_type = int.from_bytes(data[ph_off:ph_off + 4], endian)
        if is_64bit:
            p_flags = int.from_bytes(data[ph_off + 4:ph_off + 8], endian)
        else:
            p_flags = int.from_bytes(data[ph_off + 0x18:ph_off + 0x1C], endian)

        if p_type == PT_GNU_STACK:
            nx = (p_flags & PF_X) == 0
        elif p_type == PT_GNU_RELRO:
            relro = True

    m.DEP = nx
    if relro is not None:
        m.RELRO = relro

    m.extras["elf_class"] = "ELF64" if is_64bit else "ELF32"
    m.extras["elf_e_type"] = e_type
    return m


# ─────────────────────────────────────────────────────────────────
# Symbol-driven mitigations (canary, FORTIFY) — needs bv
# ─────────────────────────────────────────────────────────────────


def _extend_with_symbols(m: TargetMitigations, bv) -> None:
    """Augment the profile with canary / FORTIFY signals from imports."""
    if bv is None:
        return
    from ..heuristics._base import imports_in
    imports = imports_in(bv)

    # Stack canary — `__stack_chk_fail` import = canary enabled (ELF) /
    # `__security_check_cookie` = canary enabled (PE/MSVC).
    if "__stack_chk_fail" in imports or "__security_check_cookie" in imports:
        m.GS = True

    # FORTIFY — at least one __*_chk variant imported = FORTIFY on
    fortify_on, unchecked = heur_mitigations.detect_fortify(bv)
    m.FORTIFY = fortify_on
    if unchecked:
        m.extras["fortify_unchecked_imports"] = unchecked


# ─────────────────────────────────────────────────────────────────
# Public API — extraction
# ─────────────────────────────────────────────────────────────────


def extract_mitigations(binary_path: str, bv=None) -> TargetMitigations:
    """Return a `TargetMitigations` profile for the binary at `binary_path`.

    Parses PE or ELF headers and (when `bv` is provided) augments
    with symbol-driven canary / FORTIFY detection.
    """
    data = _read_file_bytes(binary_path)
    if not data:
        return TargetMitigations()

    if data[:2] == b"MZ":
        m = _extract_pe_mitigations(data)
    elif data[:4] == b"\x7fELF":
        m = _extract_elf_mitigations(data)
    else:
        m = TargetMitigations()
        m.extras["unknown_format"] = True

    _extend_with_symbols(m, bv)
    return m


# ─────────────────────────────────────────────────────────────────
# Public API — scoring
# ─────────────────────────────────────────────────────────────────


def _base_exploitability(category: str) -> float:
    """Per-bug-class baseline exploitability, before mitigation factors."""
    table = {
        "stack_buffer_overflow":      0.85,
        "heap_buffer_overflow":       0.75,
        "use_after_free":             0.80,
        "double_free":                0.65,
        "format_string":              0.70,
        "integer_overflow_to_allocation": 0.65,
        "off_by_one":                 0.40,
        "type_confusion":             0.75,
        "uninitialised_memory_disclosure": 0.45,
        "weak_prng_in_security_path": 0.85,
        "command_injection":          0.95,
        "path_traversal":             0.70,
        "toctou":                     0.60,
        "permissive_sddl":            0.70,
        "null_dacl":                  0.70,
        "pre_verification_write":     0.80,
        "direct_syscall_stub":        0.50,    # malware-leaning, not always exploitable
        "tls_callback_first_stage":   0.50,
        "veh_handler_install":        0.40,
        "hidden_from_debugger_thread": 0.30,
        "peb_antidebug_check":        0.20,
        "api_hash_resolution":        0.40,
        "process_injection_crt":      0.70,
        "apc_injection_remote":       0.70,
        "process_hollowing":          0.85,
        "chain_pattern":              0.90,
    }
    return table.get(category, 0.50)


def score_finding(finding: Finding, profile: TargetMitigations) -> float:
    """Compute mitigation-weighted exploitability for one Finding.

    Mutates `finding.target_mitigations` (copy of profile) and
    `finding.mitigation_weighted_exploitability`. Returns the score.
    """
    base = _base_exploitability(finding.category)
    weights = heur_mitigations.EXPLOITABILITY_WEIGHTS.get(finding.category, {})
    factor = 1.0
    profile_dict = profile.to_dict()
    for mitigation, weight in weights.items():
        present = profile_dict.get(mitigation)
        if present is True or present == "set" or present == "non-zero":
            factor *= weight
    score = max(0.0, min(1.0, base * factor))
    # Copy profile (shallow) into the Finding
    finding.target_mitigations = TargetMitigations.from_dict(profile_dict)
    finding.mitigation_weighted_exploitability = score
    return score


def score_findings(findings: list[Finding], profile: TargetMitigations) -> None:
    """Apply `score_finding` to each in `findings` (in place)."""
    for f in findings:
        score_finding(f, profile)


# ─────────────────────────────────────────────────────────────────
# Convenience top-level
# ─────────────────────────────────────────────────────────────────


def analyze(session=None, *, binary_path: Optional[str] = None,
            findings: Optional[list[Finding]] = None) -> dict:
    """Run mitigation extraction and (optionally) score a list of Findings.

    If `session` is a BinjaSession, uses its bv and binary_path.
    Returns a dict with `mitigations` (TargetMitigations) and
    `scored_findings_count` (int).
    """
    bv = getattr(session, "bv", None)
    if binary_path is None and session is not None:
        binary_path = getattr(session, "binary_path", None)
    if binary_path is None:
        return {"mitigations": TargetMitigations(), "scored_findings_count": 0}

    profile = extract_mitigations(binary_path, bv=bv)
    n = 0
    if findings:
        score_findings(findings, profile)
        n = len(findings)
    return {"mitigations": profile, "scored_findings_count": n}
