"""BYOVD primitive-class fingerprinting — Phase 1 enhancement E7.

Lightweight pre-filter that checks a driver's import table for
combinations of (handle-acquiring API + destructive-operation API)
characteristic of a primitive class. The check is co-presence-based
— not a vulnerability assertion — and emits MEDIUM-severity Findings
that triage subsequent deeper analysis.

The methodology this implements is described in
`D:/Repos/Security/Known Vulnerable/BYOVD/BYOVD/README.md` "Step 0"
(BlackSnufkin 2025): before deep RE, screen imports for canonical
primitive-class fingerprints. Argus adapts that as a generic
detection-pre-filter applied at Phase 1 surface stage.

Six primitive classes encoded:

| Class | Handle API | Destructive API |
|---|---|---|
| `process_killer` | Zw/NtOpenProcess + PsLookupProcessByProcessId | Zw/NtTerminateProcess |
| `arbitrary_kernel_rw` | (intrinsic memory access; no clean API) | Mm{Map,Get}Phys + memcpy |
| `arbitrary_msr` | n/a | __readmsr / __writemsr |
| `arbitrary_file_write` | Zw/NtCreateFile | Zw/NtWriteFile |
| `arbitrary_registry_write` | Zw/NtOpenKey | Zw/NtSetValueKey |
| `module_load` | n/a | Zw/NtLoadDriver |

Each detected class emits one Finding citing the matched imports.
The point isn't "this is a vulnerability" — it's "this driver's
shape says it CAN do X; if X is reachable from an IOCTL handler
without authentication, it's a primitive class candidate".

Generalisation guarantee: this heuristic does not encode any
single driver's signatures. The classes are derived from the
**shape of the primitive**, not from any particular vulnerable
driver. dbutil_2_3.sys hits `arbitrary_kernel_rw` and
`arbitrary_msr` because that's its shape. TfSysMon will hit
`process_killer`. A clean, well-designed driver (e.g., a modern
audio driver) will hit zero classes despite legitimate kernel-API
use because it doesn't combine handle + destructive APIs on
attacker-relevant object classes.

Knowledge anchors:
- `[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]`
- BlackSnufkin BYOVD methodology (external reference)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ._base import imports_in
from ..output.finding import Evidence, Finding, Severity


# ─────────────────────────────────────────────────────────────────
# Primitive-class definitions
# ─────────────────────────────────────────────────────────────────


@dataclass
class PrimitiveClass:
    """One BYOVD-relevant primitive class."""

    name: str                                # short identifier, e.g. "process_killer"
    description: str
    handle_apis: set[str] = field(default_factory=set)
    destructive_apis: set[str] = field(default_factory=set)
    severity: Severity = Severity.MEDIUM
    cwe: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)

    def matches(self, imports: set[str]) -> tuple[set[str], set[str]]:
        """Return (matched_handle_apis, matched_destructive_apis)
        — the subset of each that's actually present in `imports`.

        For the class to fire, BOTH sets must be non-empty (or, for
        no-handle classes, the destructive set non-empty alone).
        """
        h = self.handle_apis & imports
        d = self.destructive_apis & imports
        return h, d


PRIMITIVE_CLASSES: list[PrimitiveClass] = [
    PrimitiveClass(
        name="process_killer",
        description=(
            "Driver imports both a process-handle-acquiring API "
            "(Nt/ZwOpenProcess or PsLookupProcessByProcessId) and the "
            "destructive Nt/ZwTerminateProcess. This is the canonical "
            "BYOVD EDR-killer fingerprint (EDRKillShifter, "
            "BlackSnufkin BYOVD repo, ValleyRAT and downstream)."
        ),
        handle_apis={
            "ZwOpenProcess", "NtOpenProcess",
            "PsLookupProcessByProcessId",
            "ObOpenObjectByPointer",
        },
        destructive_apis={
            "ZwTerminateProcess", "NtTerminateProcess",
            "PsTerminateSystemThread",
        },
        severity=Severity.HIGH,
        cwe=["CWE-862", "CWE-732"],
        mitre=["T1068", "T1562.001"],
    ),
    PrimitiveClass(
        name="arbitrary_kernel_rw",
        description=(
            "Driver imports physical-memory mapping APIs "
            "(MmMapIoSpace family + MmGetPhysicalAddress). Combined "
            "with an in-binary memcpy and an IOCTL handler that "
            "passes user-supplied parameters in, this is the dbutil "
            "/ RTCore64 / WinRing0 arbitrary-R/W primitive class."
        ),
        # MmGetPhysicalAddress alone is the handle-equivalent;
        # MmMapIoSpace is the destructive op. Pair-presence fires.
        handle_apis={
            "MmGetPhysicalAddress", "MmAllocateContiguousMemorySpecifyCache",
            "MmAllocateContiguousMemory",
        },
        destructive_apis={
            "MmMapIoSpace", "MmMapIoSpaceEx",
            "ZwMapViewOfSection", "NtMapViewOfSection",
        },
        severity=Severity.HIGH,
        cwe=["CWE-782", "CWE-822"],
        mitre=["T1068", "T1611"],
    ),
    PrimitiveClass(
        name="arbitrary_msr",
        description=(
            "Driver imports __readmsr / __writemsr intrinsic. "
            "Exposing this from an IOCTL with attacker-controlled "
            "MSR index is a privilege-escalation primitive (LSTAR / "
            "EFER / SMRR overwrite); WinRing0 / RTCore64 family."
        ),
        # No handle-acquiring API; just the intrinsics' presence.
        handle_apis=set(),
        destructive_apis={"__readmsr", "__writemsr"},
        severity=Severity.HIGH,
        cwe=["CWE-782"],
        mitre=["T1014", "T1068"],
    ),
    PrimitiveClass(
        name="arbitrary_file_write",
        description=(
            "Driver imports Nt/ZwCreateFile + Nt/ZwWriteFile pair. "
            "Combined with attacker-controlled path/contents this "
            "lets the driver overwrite AV signature files, drop "
            "persistence payloads, or corrupt OS files — typical "
            "ransomware loader / wiper fingerprint."
        ),
        handle_apis={"ZwCreateFile", "NtCreateFile", "IoCreateFile"},
        destructive_apis={"ZwWriteFile", "NtWriteFile"},
        severity=Severity.HIGH,
        cwe=["CWE-22", "CWE-732"],
        mitre=["T1565.001", "T1547"],
    ),
    PrimitiveClass(
        name="arbitrary_registry_write",
        description=(
            "Driver imports Nt/ZwOpenKey + Nt/ZwSetValueKey pair. "
            "Kernel-mode bypass of registry access checks; used for "
            "persistence, AV-disable registry mutation, etc."
        ),
        handle_apis={"ZwOpenKey", "NtOpenKey", "ZwCreateKey", "NtCreateKey"},
        destructive_apis={
            "ZwSetValueKey", "NtSetValueKey",
            "ZwDeleteKey", "NtDeleteKey",
            "ZwDeleteValueKey", "NtDeleteValueKey",
        },
        severity=Severity.MEDIUM,
        cwe=["CWE-732"],
        mitre=["T1547.001", "T1112"],
    ),
    PrimitiveClass(
        name="kernel_module_load",
        description=(
            "Driver imports Nt/ZwLoadDriver — kernel-mode module-"
            "loading primitive. Combined with attacker-controlled "
            "registry path setup, lets a signed driver load further "
            "(potentially-unsigned) drivers, bypassing HVCI / WDAC."
        ),
        handle_apis=set(),
        destructive_apis={"ZwLoadDriver", "NtLoadDriver"},
        severity=Severity.HIGH,
        cwe=["CWE-732"],
        mitre=["T1014", "T1547.006"],
    ),
]


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.byovd_primitives") -> list[Finding]:
    """Scan the binary's imports for primitive-class fingerprints.

    Returns one Finding per detected class. Each Finding carries:
    - the primitive class name + description
    - the matched handle / destructive imports as evidence
    - severity per the class definition

    No findings emit when the binary doesn't look like a Windows
    kernel driver. The discriminator is the platform string —
    `windows-kernel-x86_64` / `windows-kernel-x86` — supplemented
    by section-marker fallback.
    """
    findings: list[Finding] = []
    if bv is None:
        return findings

    # Restrict to Windows kernel drivers.
    plat_lower = (platform or "").lower()
    if "windows-kernel" not in plat_lower:
        # Fallback: the binary may report `windows-x86_64` despite
        # being a kernel driver. Check section markers.
        sections = getattr(bv, "sections", None)
        if not sections:
            return findings
        names = set(sections.keys() if hasattr(sections, "keys") else [])
        if not (names & {"INIT", "PAGE", ".init", ".PAGE"}):
            return findings

    imports = imports_in(bv)
    if not imports:
        return findings

    for pclass in PRIMITIVE_CLASSES:
        h_hits, d_hits = pclass.matches(imports)
        # Class fires when destructive APIs are present AND
        # (handle-class is empty OR a handle-API is also present).
        # The "handle empty" branch covers MSR / module-load classes
        # whose API doesn't have a separate handle step.
        if not d_hits:
            continue
        if pclass.handle_apis and not h_hits:
            continue

        all_matched = sorted(h_hits | d_hits)
        findings.append(Finding(
            id="",
            category=f"kernel_driver_primitive_candidate_{pclass.name}",
            severity=pclass.severity,
            address=0,
            function="<binary>",
            binary=binary,
            arch=arch,
            platform=platform,
            detector=detector,
            knowledge_refs=[
                "[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]",
            ],
            cwe=list(pclass.cwe),
            mitre_attack=list(pclass.mitre),
            description=(
                f"Driver imports a {pclass.name!r}-class primitive "
                f"fingerprint: {all_matched}. {pclass.description} "
                f"This is a triage signal (the driver SHAPE supports "
                f"this primitive); confirm via downstream taint "
                f"analysis whether the primitive is reachable from "
                f"an IOCTL handler without authentication."
            ),
            details={
                "primitive_class": pclass.name,
                "matched_handle_apis": sorted(h_hits),
                "matched_destructive_apis": sorted(d_hits),
            },
            evidence=[Evidence(
                kind="primitive_class_fingerprint",
                source=detector,
                payload=f"{pclass.name}: {all_matched}",
            )],
        ))

    return findings
