"""Architecture-specific heuristics — TEB / PEB / segment-register reads,
AArch64 PAC/MTE markers, MIPS / RISC-V conventions.

Knowledge anchors:
- `[[Memory/Knowledge/wnapi_segment_register_teb_bootstrap]]` — `gs:[0x60]`
  (x64) / `fs:[0x30]` (x86) PEB bootstrap convention.
- `[[Memory/Knowledge/wnapi_peb_teb_structures]]` — TEB / PEB layout.
- `[[Memory/Knowledge/em_peb_antidebug_fields]]` — anti-debug fields
  (also referenced from evasion.py).
- `[[Memory/Knowledge/a64_aarch64_calling_conventions]]` (and family)
  — AArch64 register conventions and PAC opcodes.

This module is mostly *structural metadata* — the analysis modules
that consume Binja IL implement the actual segment-register-read
recognition. Catalogued here for centralised provenance.
"""

from __future__ import annotations

from ._base import (
    BytePattern, ConstantPattern, Pattern, StructuralPattern,
)
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Segment-register reads (Windows TEB / PEB bootstrap)
# ─────────────────────────────────────────────────────────────────


GS_PEB_READ = StructuralPattern(
    name="arch.gs_peb_read",
    description="Reads `gs:[0x60]` (x64 PEB pointer) — TEB/PEB introspection bootstrap",
    severity=Severity.LOW,
    category="peb_bootstrap_read",
    mitre_attack=["T1106"],
    knowledge_refs=[
        "[[Memory/Knowledge/wnapi_segment_register_teb_bootstrap]]",
        "[[Memory/Knowledge/wnapi_peb_teb_structures]]",
    ],
    shape={"kind": "segment_register_read", "register": "gs", "offset": 0x60},
    notes="Common in legitimate Win32 startup code; combine with downstream offset reads (BeingDebugged 0x02, NtGlobalFlag 0xBC) for anti-debug classification.",
)

FS_PEB_READ_X86 = StructuralPattern(
    name="arch.fs_peb_read_x86",
    description="Reads `fs:[0x30]` (x86 PEB pointer)",
    severity=Severity.LOW,
    category="peb_bootstrap_read",
    mitre_attack=["T1106"],
    knowledge_refs=[
        "[[Memory/Knowledge/wnapi_segment_register_teb_bootstrap]]",
    ],
    shape={"kind": "segment_register_read", "register": "fs", "offset": 0x30},
)


# ─────────────────────────────────────────────────────────────────
# PEB / TEB field offsets (used by analysis/taint.py + arch detector
# to classify follow-on reads after a PEB load)
# ─────────────────────────────────────────────────────────────────


# {field: (offset_x64, offset_x86, knowledge_anchor)}
PEB_FIELDS: dict[str, tuple[int, int, str]] = {
    "BeingDebugged":   (0x02, 0x02, "[[Memory/Knowledge/em_peb_antidebug_fields]]"),
    "Ldr":             (0x18, 0x0c, "[[Memory/Knowledge/wnapi_peb_teb_structures]]"),
    "ProcessParameters": (0x20, 0x10, "[[Memory/Knowledge/wnapi_peb_teb_structures]]"),
    "FastPebLock":     (0x110, 0x1a4, "[[Memory/Knowledge/wnapi_peb_teb_structures]]"),
    "NtGlobalFlag":    (0xBC, 0x68, "[[Memory/Knowledge/em_peb_antidebug_fields]]"),
    "ProcessHeap":     (0x30, 0x18, "[[Memory/Knowledge/wnapi_heap_internals]]"),
}

TEB_FIELDS: dict[str, tuple[int, int, str]] = {
    "Self":            (0x30, 0x18, "[[Memory/Knowledge/wnapi_segment_register_teb_bootstrap]]"),
    "Peb":             (0x60, 0x30, "[[Memory/Knowledge/wnapi_segment_register_teb_bootstrap]]"),
    "EnvironmentPointer": (0x38, 0x1c, "[[Memory/Knowledge/wnapi_peb_teb_structures]]"),
    "ClientId.UniqueProcess":  (0x40, 0x20, "[[Memory/Knowledge/wnapi_peb_teb_structures]]"),
    "TlsSlots":        (0x1480, 0xe10, "[[Memory/Knowledge/wnapi_peb_teb_structures]]"),
}


# ─────────────────────────────────────────────────────────────────
# AArch64 PAC / MTE markers
# ─────────────────────────────────────────────────────────────────


AARCH64_PAC_BYTES = BytePattern(
    name="arch.aarch64_pac_opcodes",
    description="AArch64 PAC opcodes (paciasp / autiasp / pacibsp / autibsp / blraa / braa)",
    severity=Severity.INFO,
    category="aarch64_pac_use",
    knowledge_refs=[],
    byte_sequences=[
        bytes.fromhex("3F2303D5"),     # paciasp
        bytes.fromhex("BF2303D5"),     # autiasp
        bytes.fromhex("7F2303D5"),     # pacibsp
        bytes.fromhex("FF2303D5"),     # autibsp
    ],
)


# ─────────────────────────────────────────────────────────────────
# Cross-arch syscall instruction bytes (also in syscalls.py)
# ─────────────────────────────────────────────────────────────────


# Catalogued here for arch-classification ergonomics.
ARCH_SYSCALL_BYTES: dict[str, bytes] = {
    "x86_64-syscall":    bytes.fromhex("0F05"),
    "x86_64-sysenter":   bytes.fromhex("0F34"),
    "x86_int80":         bytes.fromhex("CD80"),
    "aarch64-svc0":      bytes.fromhex("010000D4"),
    "armv7-svc0":        bytes.fromhex("000000EF"),
    "armv7-thumb-svc0":  bytes.fromhex("00DF"),
    "mips-syscall":      bytes.fromhex("0C000000"),
    "riscv-ecall":       bytes.fromhex("73000000"),
}


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = [
    GS_PEB_READ, FS_PEB_READ_X86,
    AARCH64_PAC_BYTES,
]


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.arch") -> list:
    """Currently emits only PAC-opcode hits when found.

    Segment-register / PEB / TEB structural patterns are recognised
    by `analysis/surface.py` and `analysis/taint.py`; they consume
    the PEB_FIELDS / TEB_FIELDS tables defined here.
    """
    from ._base import find_byte_pattern, function_at, emit_finding
    findings = []
    for seq in AARCH64_PAC_BYTES.byte_sequences:
        for addr in find_byte_pattern(bv, seq):
            func = function_at(bv, addr)
            findings.append(emit_finding(
                AARCH64_PAC_BYTES,
                address=addr,
                function=getattr(func, "name", "") if func else "",
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                description_extra=f"opcode: {seq.hex()}",
            ))
    return findings
