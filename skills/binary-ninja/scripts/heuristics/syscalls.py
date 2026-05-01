"""Direct-syscall and SSN-resolution heuristics.

Catalog of patterns that mark a binary as performing direct
syscalls (Hell's Gate / SysWhispers / TartarusGate / Hell's Hall /
Halo's Gate) or runtime SSN resolution.

Knowledge anchors:
- `[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]` — full
  taxonomy of resolution techniques and their evolution.
- `[[Memory/Knowledge/wnapi_syscall_mechanics]]` — Win64 syscall
  ABI (`mov r10, rcx; mov eax, ssn; syscall`).
- `[[Memory/Knowledge/hw_cross_arch_syscall_conventions]]` — non-x86
  syscall instructions (svc, ecall, etc.).
- `[[Memory/Knowledge/em_hook_evasion_three_approaches]]` — direct
  syscall is one of three; the other two have separate modules.

Module emits BytePattern hits (NTDLL stub bytes outside NTDLL),
ImportPattern combos (resolution-helper imports), and
StructuralPattern metadata (consumed by analysis/taint.py for the
SSN-extracts-from-NTDLL recogniser).
"""

from __future__ import annotations

from ._base import (
    BytePattern, ConstantPattern, ImportPattern, Pattern,
    StringPattern, StructuralPattern,
    emit_finding, find_byte_pattern, function_at, imports_in,
    section_at, strings_in,
)
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Stub-byte patterns — the canonical NTDLL syscall prologue.
# When these bytes appear in a non-ntdll.dll image, the binary is
# performing direct syscalls.
# ─────────────────────────────────────────────────────────────────


# Win64 prologue: 4C 8B D1                  mov r10, rcx
#                  B8 ?? ?? ?? ??            mov eax, <ssn>
#                  0F 05                     syscall
#                  C3                        ret
# Bytes for the static parts (skipping the SSN immediate):
NTDLL_STUB_PREFIX = bytes.fromhex("4C8BD1B8")          # mov r10, rcx; mov eax, ...
NTDLL_STUB_TAIL   = bytes.fromhex("0F05C3")            # syscall; ret


HELLS_GATE_STUB = BytePattern(
    name="syscalls.hells_gate_stub",
    description="NTDLL syscall-stub prologue bytes (`mov r10, rcx; mov eax, imm32; syscall; ret`) outside the NTDLL image — direct-syscall stub",
    severity=Severity.HIGH,
    category="direct_syscall_stub",
    cwe=[],
    mitre_attack=["T1106", "T1027"],
    knowledge_refs=["[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]"],
    byte_sequences=[NTDLL_STUB_PREFIX],
    negative_context={"module_name": "ntdll.dll"},   # legitimate inside NTDLL
)

NTDLL_STUB_TAIL_PATTERN = BytePattern(
    name="syscalls.ntdll_stub_tail",
    description="NTDLL syscall-tail bytes (`syscall; ret`) — combined with prefix gives the canonical stub",
    severity=Severity.LOW,
    category="syscall_instruction",
    knowledge_refs=["[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]"],
    byte_sequences=[NTDLL_STUB_TAIL],
    negative_context={"module_name": "ntdll.dll"},
)


# ─────────────────────────────────────────────────────────────────
# SSN-resolution helpers — imports that the runtime stub uses
# ─────────────────────────────────────────────────────────────────


SSN_RESOLUTION_HELPERS = ImportPattern(
    name="syscalls.ssn_resolution_helpers",
    description="GetProcAddress + GetModuleHandle + (optional) ntdll string — runtime SSN resolution from NTDLL exports (Hell's Gate / SysWhispers)",
    severity=Severity.MEDIUM,
    category="ssn_resolution_helpers",
    mitre_attack=["T1106", "T1027.007"],
    knowledge_refs=["[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]"],
    import_names=["GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
                  "LdrGetProcedureAddress"],
    all_required=False,
    notes="High false-positive rate on its own — every Win32 binary uses these. Combo with HELLS_GATE_STUB or NTDLL_FUNCTION_STRINGS for real signal.",
)


# ─────────────────────────────────────────────────────────────────
# NT* / Zw* function-name strings — runtime resolution candidates
# ─────────────────────────────────────────────────────────────────


NTDLL_FUNCTION_STRINGS = StringPattern(
    name="syscalls.ntdll_function_strings",
    description="Nt-prefixed NTDLL function name in binary's strings — runtime symbol resolution candidate",
    severity=Severity.LOW,
    category="ntdll_function_string",
    mitre_attack=["T1106", "T1027"],
    knowledge_refs=[
        "[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]",
        "[[Memory/Knowledge/wnapi_syscall_mechanics]]",
    ],
    string_literals=[
        "NtCreateThreadEx", "NtMapViewOfSection", "NtUnmapViewOfSection",
        "NtWriteVirtualMemory", "NtReadVirtualMemory", "NtProtectVirtualMemory",
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory",
        "NtCreateSection", "NtOpenSection",
        "NtSetInformationThread", "NtSetInformationProcess",
        "NtSetContextThread", "NtGetContextThread",
        "NtQueueApcThread", "NtQueueApcThreadEx",
        "NtResumeThread", "NtSuspendThread",
        "NtTerminateProcess", "NtTerminateThread",
        "NtClose", "NtOpenProcess", "NtOpenThread",
        "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile",
        "NtCreateProcess", "NtCreateProcessEx",
        "NtDuplicateObject",
        "ZwCreateThreadEx", "ZwMapViewOfSection",
    ],
)


# ─────────────────────────────────────────────────────────────────
# API hash-resolution constants — when the stub avoids strings
# ─────────────────────────────────────────────────────────────────


DJB2_INIT = ConstantPattern(
    name="syscalls.djb2_init",
    description="djb2 hash init constant 5381 — common in API hash resolution stubs (PEB-LDR walk + djb2 of export name)",
    severity=Severity.MEDIUM,
    category="api_hash_resolution",
    mitre_attack=["T1027.007"],
    knowledge_refs=["[[Memory/Knowledge/em_hook_evasion_three_approaches]]"],
    constants=[5381],
    bit_widths=[32],
)

FNV1A_CONSTS = ConstantPattern(
    name="syscalls.fnv1a_constants",
    description="FNV-1a 32-bit constants (offset basis 0x811C9DC5 + prime 0x01000193) — API hash resolution",
    severity=Severity.MEDIUM,
    category="api_hash_resolution",
    mitre_attack=["T1027.007"],
    knowledge_refs=["[[Memory/Knowledge/em_hook_evasion_three_approaches]]"],
    constants=[0x811C9DC5, 0x01000193],
    bit_widths=[32],
)

ROR13_KERNEL32_HASHES = ConstantPattern(
    name="syscalls.ror13_kernel32_hashes",
    description="ROR13-add hash constants for kernel32.dll exports — Metasploit-class shellcode marker",
    severity=Severity.MEDIUM,
    category="api_hash_resolution",
    mitre_attack=["T1027.007"],
    knowledge_refs=["[[Memory/Knowledge/em_hook_evasion_three_approaches]]"],
    # Famous Metasploit ROR13 hashes:
    constants=[
        0x6A4ABC5B,   # KERNEL32.DLL
        0x6CFAB7AC,   # LoadLibraryA
        0x726774C,    # GetProcAddress (truncated form sometimes seen)
        0xAC4E5C8C,   # ExitProcess
        0x91AFCA54,   # VirtualAlloc
        0x528796C6,   # VirtualProtect
    ],
    bit_widths=[32],
)


# ─────────────────────────────────────────────────────────────────
# Structural pattern — recognised by analysis/taint.py
# ─────────────────────────────────────────────────────────────────


SSN_FROM_NTDLL = StructuralPattern(
    name="syscalls.ssn_extract_from_ntdll",
    description="Reads bytes from NTDLL export to recover SSN (Hell's Gate / Halo's Gate)",
    severity=Severity.HIGH,
    category="ssn_extract_from_ntdll",
    mitre_attack=["T1106"],
    knowledge_refs=["[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]"],
    shape={
        "kind": "memory_read_at_offset_after_getprocaddress",
        "offset_min": 0,
        "offset_max": 16,
        "use": "load_eax",
    },
)


# ─────────────────────────────────────────────────────────────────
# Cross-arch syscall-instruction byte signatures (informational —
# analysis modules use these to classify foreign-arch syscall use)
# ─────────────────────────────────────────────────────────────────


CROSS_ARCH_SYSCALL_BYTES: dict[str, bytes] = {
    "x86_64": bytes.fromhex("0F05"),         # syscall
    "x86":    bytes.fromhex("CD80"),         # int 0x80 (legacy)
    "x86_sysenter": bytes.fromhex("0F34"),   # sysenter
    "aarch64": bytes.fromhex("010000D4"),    # svc 0
    "armv7":   bytes.fromhex("000000EF"),    # svc 0  (ARM mode)
    "armv7_thumb": bytes.fromhex("00DF"),    # svc 0 (Thumb)
    "mips":    bytes.fromhex("0C000000"),    # syscall (big-endian)
    "riscv":   bytes.fromhex("73000000"),    # ecall
}


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = [
    HELLS_GATE_STUB,
    NTDLL_STUB_TAIL_PATTERN,
    SSN_RESOLUTION_HELPERS,
    NTDLL_FUNCTION_STRINGS,
    DJB2_INIT,
    FNV1A_CONSTS,
    ROR13_KERNEL32_HASHES,
    SSN_FROM_NTDLL,
]


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.syscalls") -> list:
    """Emit findings for direct-syscall and SSN-resolution patterns."""
    findings = []

    # 1. Stub bytes — Hell's Gate prologue outside ntdll.
    for addr in find_byte_pattern(bv, NTDLL_STUB_PREFIX):
        sec = section_at(bv, addr) or ""
        if "ntdll" in sec.lower():
            continue
        func = function_at(bv, addr)
        fname = getattr(func, "name", "") if func else ""
        findings.append(emit_finding(
            HELLS_GATE_STUB,
            address=addr, function=fname,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"section: {sec}",
        ))

    # 2. NT* function strings.
    string_table = strings_in(bv)
    nt_hits = [(s, a) for (s, a) in string_table
               if any(needle in s for needle in NTDLL_FUNCTION_STRINGS.string_literals)]
    if nt_hits:
        # Single binary-scope finding; details list the matches.
        first_addr = nt_hits[0][1]
        findings.append(emit_finding(
            NTDLL_FUNCTION_STRINGS,
            address=first_addr, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"matched: {len(nt_hits)} NT* strings",
            details={"matches": [s for s, _ in nt_hits[:32]]},
        ))

    # 3. Hash-init constants.
    for pat, hits_label in (
        (DJB2_INIT, "djb2"),
        (FNV1A_CONSTS, "fnv1a"),
        (ROR13_KERNEL32_HASHES, "ror13"),
    ):
        for c in pat.constants:
            for w in pat.bit_widths:
                from ._base import find_constant
                for addr in find_constant(bv, c, w):
                    func = function_at(bv, addr)
                    findings.append(emit_finding(
                        pat,
                        address=addr,
                        function=getattr(func, "name", "") if func else "",
                        binary=binary, arch=arch, platform=platform,
                        detector=detector,
                        description_extra=f"{hits_label} constant 0x{c:x}",
                    ))

    # 4. Resolution-helper imports — combo-gated. GetProcAddress +
    #    GetModuleHandle is in 99% of Win32 binaries; alone it's
    #    noise. Emit only when paired with NTDLL function-name
    #    strings (the resolution targets) OR with the Hell's Gate
    #    stub byte pattern.
    imps = imports_in(bv)
    matched = [n for n in SSN_RESOLUTION_HELPERS.import_names if n in imps]
    if len(matched) >= 2 and nt_hits:
        findings.append(emit_finding(
            SSN_RESOLUTION_HELPERS,
            address=0, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=(
                f"helpers: {', '.join(matched)} (combo: NTDLL strings present)"
            ),
            details={
                "matched_helpers": matched,
                "ntdll_string_hits": len(nt_hits),
            },
        ))

    return findings
