"""Evasion heuristics — TLS callback, SEH/VEH abuse, hidden-thread,
PEB anti-debug, hook evasion, anti-cheat / anti-analysis indicators.

Knowledge anchors:
- `[[Memory/Knowledge/em_covert_execution_tls_seh]]` — TLS callback
  + SEH/VEH covert execution slots.
- `[[Memory/Knowledge/em_veh_hwbp_hook_evasion]]` — VEH + hardware-
  breakpoint hook evasion.
- `[[Memory/Knowledge/em_peb_antidebug_fields]]` — PEB anti-debug
  field catalogue.
- `[[Memory/Knowledge/em_hook_evasion_three_approaches]]` — direct
  syscall, NTDLL re-map, syscall-stub patching.
- `[[Memory/Knowledge/gh_anti_cheat_evasion]]` — anti-cheat lineage.

Pair with `heuristics/syscalls.py` (direct-syscall) and
`heuristics/arch.py` (segment-register / TEB / PEB structural reads).
"""

from __future__ import annotations

from ._base import (
    BytePattern, ImportPattern, Pattern, StringPattern, StructuralPattern,
    emit_finding, find_byte_pattern, function_at, imports_in,
    section_at, string_pattern_match, strings_in,
)
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Vectored exception handler
# ─────────────────────────────────────────────────────────────────


VEH_HANDLER = ImportPattern(
    name="evasion.veh_handler",
    description="AddVectoredExceptionHandler — covert execution slot via VEH",
    severity=Severity.MEDIUM,
    category="veh_handler_install",
    mitre_attack=["T1574"],
    knowledge_refs=[
        "[[Memory/Knowledge/em_covert_execution_tls_seh]]",
        "[[Memory/Knowledge/em_veh_hwbp_hook_evasion]]",
    ],
    import_names=[
        "AddVectoredExceptionHandler", "RtlAddVectoredExceptionHandler",
        "AddVectoredContinueHandler", "RtlAddVectoredContinueHandler",
    ],
    all_required=False,
)


# ─────────────────────────────────────────────────────────────────
# Hidden-from-debugger thread — NtSetInformationThread(0x11)
# ─────────────────────────────────────────────────────────────────


HIDDEN_THREAD = ImportPattern(
    name="evasion.hide_thread",
    description="NtSetInformationThread import — likely ThreadHideFromDebugger (class 0x11)",
    severity=Severity.MEDIUM,
    category="hidden_from_debugger_thread",
    mitre_attack=["T1622"],
    knowledge_refs=["[[Memory/Knowledge/em_covert_execution_tls_seh]]"],
    import_names=["NtSetInformationThread"],
    all_required=False,
    notes="analysis/taint.py confirms the ThreadInformationClass argument is 0x11.",
)


# ─────────────────────────────────────────────────────────────────
# PEB anti-debug
# ─────────────────────────────────────────────────────────────────


PEB_ANTIDEBUG_STRINGS = StringPattern(
    name="evasion.peb_antidebug_strings",
    description="PEB anti-debug field name in binary's strings — debug-detection logic",
    severity=Severity.LOW,
    category="peb_antidebug_check",
    mitre_attack=["T1622"],
    knowledge_refs=["[[Memory/Knowledge/em_peb_antidebug_fields]]"],
    string_literals=[
        "BeingDebugged", "NtGlobalFlag", "ProcessDebugFlags",
        "ProcessDebugObjectHandle", "ProcessDebugPort",
        "HeapValidate", "CheckRemoteDebuggerPresent",
    ],
    word_boundary=True,
)

PEB_ANTIDEBUG_IMPORTS = ImportPattern(
    name="evasion.peb_antidebug_imports",
    description="Anti-debug API imports — combine with PEB string presence",
    severity=Severity.LOW,
    category="peb_antidebug_check",
    mitre_attack=["T1622"],
    knowledge_refs=["[[Memory/Knowledge/em_peb_antidebug_fields]]"],
    import_names=[
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW",
    ],
)


# ─────────────────────────────────────────────────────────────────
# NTDLL re-map / unhook
# ─────────────────────────────────────────────────────────────────


NTDLL_UNHOOK = ImportPattern(
    name="evasion.ntdll_unhook",
    description="Manual NTDLL re-mapping — hook-evasion approach #2",
    severity=Severity.HIGH,
    category="ntdll_unhook",
    mitre_attack=["T1562.001", "T1027"],
    knowledge_refs=["[[Memory/Knowledge/em_hook_evasion_three_approaches]]"],
    import_names=[
        "CreateFileMappingA", "MapViewOfFile", "UnmapViewOfFile",
        "VirtualProtect", "GetSystemDirectoryA", "GetSystemDirectoryW",
    ],
    all_required=True,
    notes="Combo signal — pairs with `ntdll.dll` string presence in `.rdata`.",
)

NTDLL_DLL_STRING = StringPattern(
    name="evasion.ntdll_dll_string",
    description="`ntdll.dll` string in binary — combo signal with NTDLL_UNHOOK imports",
    severity=Severity.LOW,
    category="ntdll_string_marker",
    mitre_attack=["T1027"],
    knowledge_refs=["[[Memory/Knowledge/em_hook_evasion_three_approaches]]"],
    string_literals=["ntdll.dll", "NTDLL.DLL"],
    case_sensitive=False,
    notes="combo_only: only emit when NTDLL_UNHOOK combo also fires",
)


# ─────────────────────────────────────────────────────────────────
# Hardware-breakpoint hook evasion (TEB Dr0..7 writes)
# ─────────────────────────────────────────────────────────────────


HWBP_TEB_WRITE = StructuralPattern(
    name="evasion.hwbp_teb_write",
    description="Sets Dr0..Dr7 hardware breakpoint registers via SetThreadContext / TEB tampering — hook-evasion",
    severity=Severity.HIGH,
    category="hwbp_hook_evasion",
    mitre_attack=["T1574"],
    knowledge_refs=["[[Memory/Knowledge/em_veh_hwbp_hook_evasion]]"],
    shape={"kind": "context_record_dr_field_set"},
)


# ─────────────────────────────────────────────────────────────────
# Anti-cheat / anti-analysis tooling indicators
# ─────────────────────────────────────────────────────────────────


ANTI_CHEAT_STRINGS = StringPattern(
    name="evasion.anticheat_strings",
    description="Known anti-cheat / anti-analysis driver / process names",
    severity=Severity.INFO,
    category="anticheat_indicator",
    mitre_attack=["T1518.001"],
    knowledge_refs=["[[Memory/Knowledge/gh_anti_cheat_evasion]]"],
    string_literals=[
        "EasyAntiCheat", "EAC", "BattlEye", "BEService",
        "VAC", "VanguardKM", "vgk.sys",
        "GameGuard", "npggsvc", "INCA",
        "Hyperion", "PunkBuster",
    ],
    word_boundary=True,                  # short tokens (EAC, VAC, INCA) need \b\b
)

ANALYSIS_TOOL_STRINGS = StringPattern(
    name="evasion.analysis_tool_strings",
    description="Hardcoded analysis-tool names — sandbox / debugger detection logic",
    severity=Severity.LOW,
    category="analysis_tool_detection",
    mitre_attack=["T1497"],
    knowledge_refs=["[[Memory/Knowledge/em_peb_antidebug_fields]]"],
    string_literals=[
        "Wireshark", "x64dbg", "OllyDbg", "IDA64", "ida64",
        "ProcessHacker", "ProcessExplorer", "WinDbg",
        "VBoxService", "vmtoolsd", "vmware",
        "qemu-ga",
    ],
    word_boundary=True,
)


# ─────────────────────────────────────────────────────────────────
# TLS callback — structural (PE-header-driven)
# ─────────────────────────────────────────────────────────────────


TLS_CALLBACK_PRESENT = StructuralPattern(
    name="evasion.tls_callback_present",
    description="PE has IMAGE_TLS_DIRECTORY with non-empty AddressOfCallBacks — TLS callback executes before entry point",
    severity=Severity.MEDIUM,
    category="tls_callback_present",
    mitre_attack=["T1106"],
    knowledge_refs=["[[Memory/Knowledge/em_covert_execution_tls_seh]]"],
    shape={"kind": "pe_directory_present", "directory": "IMAGE_DIRECTORY_ENTRY_TLS"},
)


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = [
    VEH_HANDLER, HIDDEN_THREAD,
    PEB_ANTIDEBUG_STRINGS, PEB_ANTIDEBUG_IMPORTS,
    NTDLL_UNHOOK, NTDLL_DLL_STRING,
    HWBP_TEB_WRITE,
    ANTI_CHEAT_STRINGS, ANALYSIS_TOOL_STRINGS,
    TLS_CALLBACK_PRESENT,
]


def _string_hits(pat: StringPattern, string_table) -> list[tuple[str, int]]:
    """Return [(literal, addr), ...] for every literal in `pat.string_literals`
    that matches at least one string in `string_table`, anchoring at the
    first matching string's address per literal."""
    out: list[tuple[str, int]] = []
    for needle in pat.string_literals:
        for value, addr in string_table:
            if string_pattern_match(needle, value,
                                    case_sensitive=pat.case_sensitive,
                                    word_boundary=pat.word_boundary):
                out.append((needle, addr))
                break
    return out


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.evasion") -> list:
    findings = []
    imports = imports_in(bv)
    string_table = strings_in(bv)

    ntdll_unhook_combo_present = all(n in imports for n in NTDLL_UNHOOK.import_names)

    # PEB_ANTIDEBUG_IMPORTS combo-gate: stand-alone presence of
    # `IsDebuggerPresent`/`OutputDebugString*` is in nearly every Win32
    # binary (system utilities, runtime libraries). Require co-presence
    # of PEB-field strings for emission.
    peb_string_hits = _string_hits(PEB_ANTIDEBUG_STRINGS, string_table)

    # Import-based patterns
    for pat in (VEH_HANDLER, HIDDEN_THREAD, PEB_ANTIDEBUG_IMPORTS, NTDLL_UNHOOK):
        if pat is PEB_ANTIDEBUG_IMPORTS and not peb_string_hits:
            continue       # combo_only — no PEB string co-signal -> suppress
        names = pat.import_names
        if pat.all_required:
            if not all(n in imports for n in names):
                continue
            extra = f"combo: {', '.join(names)}"
        else:
            hits = [n for n in names if n in imports]
            if not hits:
                continue
            extra = f"imports: {', '.join(hits)}"
        findings.append(emit_finding(
            pat,
            address=0, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=extra,
            details={"matched_imports": names if pat.all_required else hits},
        ))

    # String-based patterns — NTDLL_DLL_STRING is combo-gated.
    for pat in (PEB_ANTIDEBUG_STRINGS, ANTI_CHEAT_STRINGS,
                ANALYSIS_TOOL_STRINGS, NTDLL_DLL_STRING):
        if pat is NTDLL_DLL_STRING and not ntdll_unhook_combo_present:
            continue                     # combo_only — no NTDLL_UNHOOK imports → suppress

        hits = _string_hits(pat, string_table)
        if not hits:
            continue
        first_addr = hits[0][1]
        findings.append(emit_finding(
            pat,
            address=first_addr, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"strings: {', '.join(h for h, _ in hits[:8])}",
            details={"matched_strings": [h for h, _ in hits[:32]]},
        ))

    # Structural patterns — emitted by analysis modules; here we only
    # surface the metadata so callers can include the patterns in
    # downstream reasoning.

    return findings
