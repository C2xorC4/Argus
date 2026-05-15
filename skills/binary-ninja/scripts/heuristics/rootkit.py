"""Rootkit + bootkit heuristics.

Kernel-mode and pre-OS-boot patterns. Most fire only on driver
binaries (.sys) or UEFI firmware images; user-mode hits are rare
and high-confidence.

Knowledge anchors:
- `[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]`
- `[[Memory/Knowledge/rb_secure_boot_bypass]]`
"""

from __future__ import annotations

from ._base import (
    ImportPattern, Pattern, StringPattern, StructuralPattern,
    emit_finding, imports_in, strings_in,
)
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Minifilter / file-system filter driver
# ─────────────────────────────────────────────────────────────────


MINIFILTER_REGISTER = ImportPattern(
    name="rootkit.minifilter_register",
    description="FltRegisterFilter — minifilter driver registration",
    severity=Severity.MEDIUM,
    category="minifilter_registration",
    mitre_attack=["T1014"],
    knowledge_refs=["[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]"],
    import_names=["FltRegisterFilter", "FltStartFiltering", "FltUnregisterFilter"],
    all_required=False,
)

MINIFILTER_UNLOAD_RACE = StructuralPattern(
    name="rootkit.minifilter_unload_race",
    description="Minifilter unload-callback that does not cancel outstanding work — eviction race",
    severity=Severity.HIGH,
    category="minifilter_unload_race",
    mitre_attack=["T1014"],
    knowledge_refs=["[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]"],
    shape={"kind": "unload_callback_no_cancel"},
)


# ─────────────────────────────────────────────────────────────────
# IRP / dispatch table
# ─────────────────────────────────────────────────────────────────


DRIVER_DISPATCH = ImportPattern(
    name="rootkit.driver_irp_dispatch",
    description="IoCreateDevice + IoCreateSymbolicLink — kernel driver dispatch entry",
    severity=Severity.LOW,
    category="kernel_driver_irp_dispatch",
    mitre_attack=["T1014"],
    knowledge_refs=["[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]"],
    import_names=["IoCreateDevice", "IoCreateSymbolicLink"],
    all_required=False,
)


# ─────────────────────────────────────────────────────────────────
# Kernel notification callbacks
# ─────────────────────────────────────────────────────────────────


KERNEL_NOTIFY = ImportPattern(
    name="rootkit.kernel_notify_callbacks",
    description="PsSet*NotifyRoutine* / ObRegisterCallbacks — process / thread / image / handle notifications",
    severity=Severity.HIGH,
    category="kernel_callback_install",
    mitre_attack=["T1014"],
    knowledge_refs=["[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]"],
    import_names=[
        "PsSetCreateProcessNotifyRoutine",
        "PsSetCreateProcessNotifyRoutineEx",
        "PsSetCreateProcessNotifyRoutineEx2",
        "PsSetLoadImageNotifyRoutine",
        "PsSetCreateThreadNotifyRoutine",
        "ObRegisterCallbacks",
        "CmRegisterCallback", "CmRegisterCallbackEx",
    ],
    all_required=False,
    notes="EAC / BattlEye / GameGuard use these legitimately — combine with code-signing absence for malicious classification.",
)


# ─────────────────────────────────────────────────────────────────
# DKOM markers
# ─────────────────────────────────────────────────────────────────


DKOM_STRINGS = StringPattern(
    name="rootkit.dkom_struct_strings",
    description="EPROCESS / KTHREAD / ETHREAD field-name strings — DKOM unlinking marker",
    severity=Severity.HIGH,
    category="dkom_indicator",
    mitre_attack=["T1014"],
    knowledge_refs=["[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]"],
    string_literals=[
        "ActiveProcessLinks", "_EPROCESS", "_KTHREAD",
        "PsLookupProcessByProcessId", "PsActiveProcessHead",
        "EPROCESS", "KTHREAD",
    ],
)


# ─────────────────────────────────────────────────────────────────
# UEFI / bootkit
# ─────────────────────────────────────────────────────────────────


UEFI_RUNTIME_HOOK = StringPattern(
    name="rootkit.uefi_runtime_hook",
    description="EFI runtime / boot-services strings — UEFI bootkit / firmware compromise",
    severity=Severity.CRITICAL,
    category="uefi_bootkit",
    mitre_attack=["T1542.001", "T1542.003"],
    knowledge_refs=["[[Memory/Knowledge/rb_secure_boot_bypass]]"],
    string_literals=[
        "RT->GetVariable", "EFI_RUNTIME_SERVICES",
        "EFI_BOOT_SERVICES", "EFI_LOADED_IMAGE_PROTOCOL",
        # gRT / gBS / gST are 3-char C variable names from EFI headers —
        # not binary string constants; removed after confirmed FP:
        # 'gST' matched inside 'tagSTYLESTRUCT' in taskmgr.exe.
    ],
    notes="Useful only on UEFI images / pre-OS payloads. Skip on standard PE/ELF user-mode targets.",
)

SECURE_BOOT_VAR_IMPORTS = ImportPattern(
    name="rootkit.secure_boot_var_imports",
    description="EFI variable / NVRAM access — secure-boot tampering candidate",
    severity=Severity.CRITICAL,
    category="secure_boot_bypass_candidate",
    mitre_attack=["T1542.003"],
    knowledge_refs=["[[Memory/Knowledge/rb_secure_boot_bypass]]"],
    import_names=[
        "EfiGetVariable", "EfiSetVariable",
        "GetFirmwareEnvironmentVariableW", "SetFirmwareEnvironmentVariableW",
    ],
    all_required=False,
)


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = [
    MINIFILTER_REGISTER, MINIFILTER_UNLOAD_RACE,
    DRIVER_DISPATCH, KERNEL_NOTIFY,
    DKOM_STRINGS, UEFI_RUNTIME_HOOK,
    SECURE_BOOT_VAR_IMPORTS,
]


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.rootkit") -> list:
    findings = []
    imports = imports_in(bv)
    string_table = strings_in(bv)
    string_values = [s for s, _ in string_table]

    for pat in (MINIFILTER_REGISTER, DRIVER_DISPATCH, KERNEL_NOTIFY,
                SECURE_BOOT_VAR_IMPORTS):
        hits = [n for n in pat.import_names if n in imports]
        if not hits:
            continue
        findings.append(emit_finding(
            pat,
            address=0, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=f"imports: {', '.join(hits)}",
            details={"matched_imports": hits},
        ))

    for pat in (DKOM_STRINGS, UEFI_RUNTIME_HOOK):
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
            description_extra=f"strings: {', '.join(hits[:8])}",
            details={"matched_strings": hits[:32]},
        ))

    return findings
