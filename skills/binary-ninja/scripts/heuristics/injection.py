"""Process-injection heuristics — combo patterns for the canonical
Windows variants and Linux ptrace.

Each pattern is a multi-import combo (`all_required=True`) — the
trio / quartet of APIs that, present together, signal that
particular injection technique. Single-import presence rarely
discriminates (every Win32 binary imports `OpenProcess` for
something), but the combos are high-confidence.

Knowledge anchors:
- `[[Memory/Knowledge/em_advanced_injection_variants]]` — variant
  catalogue (CreateRemoteThread, APC, atom-bombing, hollowing,
  process doppelgänging, KernelCallbackTable, ListPlanting...).
- `[[Memory/Knowledge/bhg_process_injection_fundamentals]]` —
  *Black Hat Go* taxonomy.
- `[[Memory/Knowledge/bhg_windows_type_mapping]]` — type-mapping
  shellcode patterns.
"""

from __future__ import annotations

from ._base import (
    ImportPattern, Pattern, StructuralPattern,
    emit_finding, function_at, imports_in,
)
from ..output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Classical CreateRemoteThread (CRT) injection
# ─────────────────────────────────────────────────────────────────


CRT_INJECTION = ImportPattern(
    name="injection.create_remote_thread",
    description="OpenProcess + VirtualAllocEx + WriteProcessMemory + CreateRemoteThread — classic CRT injection",
    severity=Severity.HIGH,
    category="process_injection_crt",
    mitre_attack=["T1055.001", "T1055.002"],
    knowledge_refs=[
        "[[Memory/Knowledge/em_advanced_injection_variants]]",
        "[[Memory/Knowledge/bhg_process_injection_fundamentals]]",
    ],
    import_names=[
        "OpenProcess",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ],
    all_required=True,
)

CRT_INJECTION_NT = ImportPattern(
    name="injection.create_remote_thread_nt",
    description="NtOpenProcess + NtAllocateVirtualMemory + NtWriteVirtualMemory + NtCreateThreadEx — CRT via direct syscall",
    severity=Severity.HIGH,
    category="process_injection_crt_nt",
    mitre_attack=["T1055.001", "T1106"],
    knowledge_refs=[
        "[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]",
        "[[Memory/Knowledge/em_advanced_injection_variants]]",
    ],
    import_names=[
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
    ],
    all_required=True,
)


# ─────────────────────────────────────────────────────────────────
# APC injection (Early Bird, classical, NtQueueApcThread variants)
# ─────────────────────────────────────────────────────────────────


APC_INJECTION_LOCAL = ImportPattern(
    name="injection.apc_local",
    description="QueueUserAPC + alertable-wait — local-thread APC injection or callback-defer",
    severity=Severity.MEDIUM,
    category="apc_injection_local",
    mitre_attack=["T1055.004"],
    knowledge_refs=["[[Memory/Knowledge/em_advanced_injection_variants]]"],
    import_names=["QueueUserAPC", "SleepEx"],
    all_required=True,
    notes="Common in legitimate code; cross-process variant (APC_INJECTION_REMOTE) is the malware signal.",
)

APC_INJECTION_REMOTE = ImportPattern(
    name="injection.apc_remote",
    description="OpenThread + QueueUserAPC — cross-process APC injection (Early Bird)",
    severity=Severity.HIGH,
    category="apc_injection_remote",
    mitre_attack=["T1055.004"],
    knowledge_refs=["[[Memory/Knowledge/em_advanced_injection_variants]]"],
    import_names=["OpenThread", "QueueUserAPC"],
    all_required=True,
)

APC_INJECTION_NT = ImportPattern(
    name="injection.apc_nt",
    description="NtQueueApcThread / NtQueueApcThreadEx — direct-syscall APC injection",
    severity=Severity.HIGH,
    category="apc_injection_nt",
    mitre_attack=["T1055.004", "T1106"],
    knowledge_refs=["[[Memory/Knowledge/em_advanced_injection_variants]]"],
    import_names=["NtQueueApcThread", "NtQueueApcThreadEx"],
    all_required=False,
)


# ─────────────────────────────────────────────────────────────────
# Process hollowing
# ─────────────────────────────────────────────────────────────────


PROCESS_HOLLOWING = ImportPattern(
    name="injection.process_hollowing",
    description="CreateProcess(SUSPENDED) + NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext + ResumeThread",
    severity=Severity.CRITICAL,
    category="process_hollowing",
    mitre_attack=["T1055.012"],
    knowledge_refs=[
        "[[Memory/Knowledge/em_advanced_injection_variants]]",
        "[[Memory/Knowledge/bhg_process_injection_fundamentals]]",
    ],
    import_names=[
        "CreateProcessA",
        "NtUnmapViewOfSection",
        "WriteProcessMemory",
        "SetThreadContext",
        "ResumeThread",
    ],
    all_required=True,
)


# ─────────────────────────────────────────────────────────────────
# Process doppelgänging / herpaderping (TxF-based variants)
# ─────────────────────────────────────────────────────────────────


PROCESS_DOPPELGANG = ImportPattern(
    name="injection.process_doppelganging",
    description="CreateTransaction + CreateFileTransacted + RtlCreateProcessParametersEx — doppelgänging",
    severity=Severity.CRITICAL,
    category="process_doppelganging",
    mitre_attack=["T1055.013"],
    knowledge_refs=["[[Memory/Knowledge/em_advanced_injection_variants]]"],
    import_names=[
        "CreateTransaction",
        "CreateFileTransactedW",
        "RtlCreateProcessParametersEx",
        "NtCreateProcessEx",
    ],
    all_required=True,
)


# ─────────────────────────────────────────────────────────────────
# Atom-bombing
# ─────────────────────────────────────────────────────────────────


ATOM_BOMBING = ImportPattern(
    name="injection.atom_bombing",
    description="GlobalAddAtom + GlobalGetAtomName + NtQueueApcThread — atom-bombing",
    severity=Severity.HIGH,
    category="atom_bombing",
    mitre_attack=["T1055.004"],
    knowledge_refs=["[[Memory/Knowledge/em_advanced_injection_variants]]"],
    import_names=[
        "GlobalAddAtomA", "GlobalGetAtomNameA", "NtQueueApcThread",
    ],
    all_required=True,
)


# ─────────────────────────────────────────────────────────────────
# Thread execution hijack
# ─────────────────────────────────────────────────────────────────


THREAD_HIJACK = ImportPattern(
    name="injection.thread_hijack",
    description="OpenThread + Suspend + GetThreadContext + SetThreadContext + Resume",
    severity=Severity.HIGH,
    category="thread_execution_hijack",
    mitre_attack=["T1055.003"],
    knowledge_refs=["[[Memory/Knowledge/em_advanced_injection_variants]]"],
    import_names=[
        "OpenThread", "SuspendThread",
        "GetThreadContext", "SetThreadContext", "ResumeThread",
    ],
    all_required=True,
)


# ─────────────────────────────────────────────────────────────────
# KernelCallbackTable hijack (Windows-internal)
# ─────────────────────────────────────────────────────────────────


KERNEL_CALLBACK_TABLE = ImportPattern(
    name="injection.kernel_callback_table",
    description="NtQueryInformationProcess(ProcessBasicInformation) + WriteProcessMemory + PostMessage — KernelCallbackTable hijack",
    severity=Severity.HIGH,
    category="kernel_callback_table_hijack",
    mitre_attack=["T1574.013"],
    knowledge_refs=["[[Memory/Knowledge/em_advanced_injection_variants]]"],
    import_names=[
        "NtQueryInformationProcess",
        "WriteProcessMemory",
        "PostMessageA",
    ],
    all_required=True,
)


# ─────────────────────────────────────────────────────────────────
# Linux ptrace
# ─────────────────────────────────────────────────────────────────


PTRACE_INJECTION = ImportPattern(
    name="injection.ptrace",
    description="`ptrace` import — Linux process injection / debug primitive",
    severity=Severity.MEDIUM,
    category="ptrace_use",
    mitre_attack=["T1055.008"],
    knowledge_refs=["[[Memory/Knowledge/em_advanced_injection_variants]]"],
    import_names=["ptrace"],
    all_required=False,
    notes="Many legitimate uses; analysis/taint.py confirms when request enum + addr flow from external input.",
)


# ─────────────────────────────────────────────────────────────────
# Heap grooming — structural; data only here
# ─────────────────────────────────────────────────────────────────


HEAP_GROOMING = StructuralPattern(
    name="injection.heap_grooming",
    description="Repeated same-size allocations near a corruption sink — heap-feng-shui candidate",
    severity=Severity.LOW,
    category="heap_grooming",
    mitre_attack=["T1055"],
    knowledge_refs=[
        "[[Memory/Knowledge/wnapi_heap_internals]]",
        "[[Memory/Knowledge/em_advanced_injection_variants]]",
    ],
    shape={"kind": "alloc_loop_constant_size"},
    notes="analysis/heap.py owns the structural recognition.",
)


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


PATTERNS: list[Pattern] = [
    CRT_INJECTION, CRT_INJECTION_NT,
    APC_INJECTION_LOCAL, APC_INJECTION_REMOTE, APC_INJECTION_NT,
    PROCESS_HOLLOWING, PROCESS_DOPPELGANG,
    ATOM_BOMBING, THREAD_HIJACK, KERNEL_CALLBACK_TABLE,
    PTRACE_INJECTION,
    HEAP_GROOMING,
]


# Umbrella categories — when a precise variant fires, also emit the
# umbrella category so consumers that reason at the higher level
# (Tier-1 expected.json, vendor reports) match cleanly. Both
# Findings link back to the same pattern's Knowledge refs.
UMBRELLA_MAP: dict[str, str] = {
    "process_injection_crt":    "process_injection",
    "process_injection_crt_nt": "process_injection",
    "apc_injection_local":      "apc_injection",
    "apc_injection_remote":     "apc_injection",
    "apc_injection_nt":         "apc_injection",
    "process_hollowing":        "process_injection",
    "process_doppelganging":    "process_injection",
    "atom_bombing":             "apc_injection",
    "thread_execution_hijack":  "process_injection",
    "kernel_callback_table_hijack": "process_injection",
}


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.injection") -> list:
    imports = imports_in(bv)
    findings = []
    for pat in PATTERNS:
        if not isinstance(pat, ImportPattern):
            continue
        names = pat.import_names
        if pat.all_required:
            if not all(n in imports for n in names):
                continue
            description_extra = f"combo present: {', '.join(names)}"
        else:
            hits = [n for n in names if n in imports]
            if not hits:
                continue
            description_extra = f"imports: {', '.join(hits)}"
        # Precise Finding
        f_precise = emit_finding(
            pat,
            address=0, function="<binary>",
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            description_extra=description_extra,
            details={"matched_imports": names if pat.all_required else hits},
        )
        findings.append(f_precise)
        # Umbrella Finding (same evidence, broader category)
        umbrella = UMBRELLA_MAP.get(pat.category)
        if umbrella and umbrella != pat.category:
            f_umb = emit_finding(
                pat,
                address=0, function="<binary>",
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                description_extra=description_extra + f" (umbrella of {pat.category})",
                details={
                    "matched_imports": names if pat.all_required else hits,
                    "precise_category": pat.category,
                },
            )
            f_umb.category = umbrella
            f_umb.id = f_umb.compute_id()
            findings.append(f_umb)
    return findings
