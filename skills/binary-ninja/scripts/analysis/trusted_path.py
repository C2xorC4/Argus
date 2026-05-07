"""Trusted-path cache-load detector.

Fires `trusted_path_cache_load` when the binary contains a string
literal matching an attacker-writable path pattern (`\\Temp\\`,
`\\AppData\\`, `\\ProgramData\\`, `/tmp/`, `/var/tmp/`, …) AND
imports a load-class API (LoadLibrary, CreateFile-for-read, fopen,
load_dlopen). The structural signal: a binary that loads / reads
content from a low-trust location and treats it as authoritative
is the canonical EAC chain's terminal primitive.

This v1 doesn't trace the path string to the load call — it's a
binary-scope heuristic. If any attacker-writable string is present
AND any load API is imported, the binary plausibly does this. v2
will tie the path string to a specific load call site via taint /
xref analysis.

Knowledge anchors:
- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]`
"""

from __future__ import annotations

from typing import Optional

from ..heuristics._base import imports_in, strings_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh


CATEGORY_META = {
    "trusted_path_cache_load": {
        "severity": Severity.MEDIUM,
        "cwe": ["CWE-345", "CWE-426"],
        "mitre": ["T1574"],
        "knowledge_refs": [
            "[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]",
        ],
    },
}


# Path substrings that mark "attacker-writable / low-trust"
# directories on Windows + POSIX systems. Lowercase comparisons.
_ATTACKER_WRITABLE_TOKENS: tuple[str, ...] = (
    "\\temp\\", "\\appdata\\", "\\programdata\\",
    "\\users\\public\\", "\\windows\\temp\\",
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/var/lib/", "/home/",
)


# Load-class APIs whose presence makes the trusted-path signal
# meaningful. CreateFile is dual-use (read or write) — its presence
# is a weak signal alone but combined with an attacker-writable
# string is suspicious.
_LOAD_IMPORTS: frozenset[str] = frozenset({
    "LoadLibraryA", "LoadLibraryW",
    "LoadLibraryExA", "LoadLibraryExW",
    "GetModuleHandleA", "GetModuleHandleW",
    "ReadFile", "ReadFileEx",
    "MapViewOfFile",
    "fopen", "freopen", "open", "openat",
    "dlopen", "dlmopen",
    "CreateFileA", "CreateFileW", "CreateFile2",
})


def find_trusted_path_loads(bv, *, binary: str, arch: str, platform: str,
                            detector: str = "analysis.trusted_path"
                            ) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    imports = imports_in(bv)
    load_imports_present = imports & _LOAD_IMPORTS
    if not load_imports_present:
        return findings

    # Collect attacker-writable path strings in the binary.
    matched_paths: list[tuple[str, int]] = []
    for s, addr in (strings_in(bv) or []):
        sl = s.lower()
        for tok in _ATTACKER_WRITABLE_TOKENS:
            if tok in sl:
                matched_paths.append((s, addr))
                break

    if not matched_paths:
        return findings

    meta = CATEGORY_META["trusted_path_cache_load"]
    # Anchor at the first matched string; v2 will resolve per-callsite.
    sample_path, sample_addr = matched_paths[0]
    findings.append(Finding(
        id="",
        category="trusted_path_cache_load",
        severity=meta["severity"],
        address=sample_addr,
        function="<binary>",
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta["knowledge_refs"]),
        cwe=list(meta["cwe"]),
        mitre_attack=list(meta["mitre"]),
        description=(
            f"binary references {len(matched_paths)} attacker-writable "
            f"path string(s) (e.g. {sample_path[:64]!r}) and imports "
            f"load-class APIs ({sorted(load_imports_present)[:3]}...). "
            f"Plausibly loads content from a low-trust location and "
            f"treats it as authoritative — confirm with xref / taint."
        ),
        evidence=[Evidence(
            kind="attacker_writable_path_in_binary",
            source=detector,
            payload=(f"sample={sample_path[:80]!r} "
                     f"loads={sorted(load_imports_present)[:8]}"),
            address=sample_addr,
            function="<binary>",
        )],
        details={
            "matched_path_count": len(matched_paths),
            "sample_paths": [p for p, _ in matched_paths[:8]],
            "load_imports_present": sorted(load_imports_present),
        },
    ))
    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.trusted_path"
            ) -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")
    return find_trusted_path_loads(bv, binary=binary, arch=arch,
                                   platform=platform, detector=detector)
