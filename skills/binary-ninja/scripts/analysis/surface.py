"""Recon stage — produce target profile + binary-scope Findings.

Surface scan:
- File format / arch / platform / entry point
- Hardening profile (delegates to `analysis/mitigations.py`)
- Section table + per-section Shannon entropy
- Imported function names + summary
- Strings count
- Aggregate Findings from heuristics modules at binary scope

Output: `TargetProfile` dataclass + `list[Finding]`.

Consumed by:
- The orchestrator (recon → identification stage)
- The reporter (target-profile section)
- `analysis/mitigations.py` (already used for the hardening profile)
"""

from __future__ import annotations

import math
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..heuristics._base import imports_in, strings_in
from ..lib.binja import BinjaSession, open_binary
from ..output.finding import Finding, TargetMitigations
from . import mitigations as mitigations_mod


# ─────────────────────────────────────────────────────────────────
# Profile dataclasses
# ─────────────────────────────────────────────────────────────────


@dataclass
class SectionInfo:
    name: str
    start: int
    length: int
    permissions: str          # "rwx" / "r-x" / "rw-" etc.
    entropy: float

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "start": hex(self.start),
            "length": self.length,
            "permissions": self.permissions,
            "entropy": round(self.entropy, 3),
        }


@dataclass
class TargetProfile:
    binary_path: str
    file_size: int
    arch: str
    platform: str
    file_format: str           # "PE" / "ELF" / "Mach-O" / "Raw"
    entry_point: int
    mitigations: TargetMitigations
    imports: list[str]
    sections: list[SectionInfo]
    strings_count: int
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "binary_path": self.binary_path,
            "file_size": self.file_size,
            "arch": self.arch,
            "platform": self.platform,
            "file_format": self.file_format,
            "entry_point": hex(self.entry_point) if isinstance(self.entry_point, int) else self.entry_point,
            "mitigations": self.mitigations.to_dict(),
            "imports": list(self.imports),
            "sections": [s.to_dict() for s in self.sections],
            "strings_count": self.strings_count,
            "extras": dict(self.extras),
        }


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    e = 0.0
    for c in freq:
        if c == 0:
            continue
        p = c / total
        e -= p * math.log2(p)
    return e


def _section_perms(section) -> str:
    """Return a "rwx"-style triplet for the section's permissions."""
    # Binja Section exposes .semantics or accumulates permissions on
    # the parent segment. Tolerant fallback: use Segment lookup.
    perms = ["-", "-", "-"]
    # Many Binja versions: section has .read / .write / .execute as bool
    if getattr(section, "readable", None) is True or getattr(section, "read", None) is True:
        perms[0] = "r"
    if getattr(section, "writable", None) is True or getattr(section, "write", None) is True:
        perms[1] = "w"
    if getattr(section, "executable", None) is True or getattr(section, "execute", None) is True:
        perms[2] = "x"
    return "".join(perms)


def _gather_sections(bv) -> list[SectionInfo]:
    out: list[SectionInfo] = []
    if bv is None:
        return out
    sections = getattr(bv, "sections", None)
    if sections is None:
        return out
    # bv.sections is dict-like {name: Section} on Binja 5.x
    iterable = sections.values() if hasattr(sections, "values") else sections
    for s in iterable:
        try:
            name = str(getattr(s, "name", ""))
            start = int(getattr(s, "start", 0))
            length = int(getattr(s, "length", 0) or (getattr(s, "end", 0) - start))
            perms = _section_perms(s)
            data = b""
            if length > 0 and length <= 64 * 1024 * 1024:
                try:
                    data = bytes(bv.read(start, length))
                except Exception:
                    data = b""
            entropy = _shannon_entropy(data)
            out.append(SectionInfo(name, start, length, perms, entropy))
        except Exception:
            continue
    return out


def _detect_file_format(bv, binary_path: str) -> str:
    # bv.view_type is the canonical answer when available
    vt = getattr(bv, "view_type", None) if bv is not None else None
    if vt:
        return str(vt)
    try:
        with open(binary_path, "rb") as f:
            magic = f.read(4)
        if magic[:2] == b"MZ": return "PE"
        if magic == b"\x7fELF": return "ELF"
        if magic[:4] in (b"\xCA\xFE\xBA\xBE", b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF",
                         b"\xCE\xFA\xED\xFE", b"\xCF\xFA\xED\xFE"):
            return "Mach-O"
    except OSError:
        pass
    return "Raw"


# ─────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────


def build_profile(session: Optional[BinjaSession],
                  *, binary_path: Optional[str] = None) -> TargetProfile:
    """Build the `TargetProfile` for a binary."""
    bv = getattr(session, "bv", None)
    if binary_path is None and session is not None:
        binary_path = getattr(session, "binary_path", "")

    file_size = 0
    if binary_path:
        try:
            file_size = os.path.getsize(binary_path)
        except OSError:
            pass

    arch = (str(bv.arch) if bv is not None and bv.arch else "unknown")
    platform = (str(bv.platform) if bv is not None and bv.platform else "unknown")
    entry = int(bv.entry_point) if (bv is not None and bv.entry_point is not None) else 0
    file_format = _detect_file_format(bv, binary_path or "")

    sections = _gather_sections(bv)
    imports = sorted(imports_in(bv)) if bv is not None else []
    strings_count = sum(1 for _ in strings_in(bv)) if bv is not None else 0

    profile_mitigations = mitigations_mod.extract_mitigations(binary_path or "", bv=bv)

    return TargetProfile(
        binary_path=binary_path or "",
        file_size=file_size,
        arch=arch,
        platform=platform,
        file_format=file_format,
        entry_point=entry,
        mitigations=profile_mitigations,
        imports=imports,
        sections=sections,
        strings_count=strings_count,
        extras={},
    )


def run_heuristics_at_surface_level(bv, *, binary: str, arch: str, platform: str) -> list[Finding]:
    """Run every heuristics module at binary scope; aggregate Findings."""
    from .. import heuristics as H
    return H.match_all(bv, binary=binary, arch=arch, platform=platform)


def analyze(session: Optional[BinjaSession] = None,
            *, binary_path: Optional[str] = None,
            run_heuristics: bool = True) -> tuple[TargetProfile, list[Finding]]:
    """Recon-stage entry point.

    If `session` is None, opens the binary via `open_binary(binary_path)`
    for the duration of the call.
    """
    findings: list[Finding] = []

    if session is not None:
        profile = build_profile(session, binary_path=binary_path)
        if run_heuristics:
            findings = run_heuristics_at_surface_level(
                session.bv,
                binary=profile.binary_path,
                arch=profile.arch,
                platform=profile.platform,
            )
        # Score findings against profile mitigations
        if findings:
            mitigations_mod.score_findings(findings, profile.mitigations)
        return profile, findings

    if not binary_path:
        return TargetProfile(
            binary_path="", file_size=0, arch="unknown", platform="unknown",
            file_format="Raw", entry_point=0, mitigations=TargetMitigations(),
            imports=[], sections=[], strings_count=0,
        ), []

    with open_binary(binary_path) as s:
        return analyze(s, binary_path=binary_path, run_heuristics=run_heuristics)


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────


def _cli() -> int:                              # pragma: no cover - manual use
    import argparse
    import json
    p = argparse.ArgumentParser(description="Argus recon-stage surface scan")
    p.add_argument("binary", help="path to target binary")
    p.add_argument("--no-heuristics", action="store_true",
                   help="skip heuristics; emit profile only")
    p.add_argument("--json", action="store_true",
                   help="emit JSON instead of human-readable")
    args = p.parse_args()

    profile, findings = analyze(binary_path=args.binary,
                                run_heuristics=not args.no_heuristics)

    if args.json:
        out = {
            "profile": profile.to_dict(),
            "findings": [f.to_dict() for f in findings],
        }
        print(json.dumps(out, indent=2, default=str))
        return 0

    print(f"Argus recon — {profile.binary_path}")
    print(f"  format:    {profile.file_format}")
    print(f"  arch/plat: {profile.arch} / {profile.platform}")
    print(f"  entry:     {hex(profile.entry_point)}")
    print(f"  size:      {profile.file_size} bytes")
    print(f"  sections:  {len(profile.sections)}")
    for s in profile.sections:
        print(f"    {s.name:24s}  {s.permissions}  start={hex(s.start)}  "
              f"len={s.length}  entropy={s.entropy:.2f}")
    print(f"  imports:   {len(profile.imports)} unique symbols")
    print(f"  strings:   {profile.strings_count}")
    print(f"  mitigations: {profile.mitigations.to_dict()}")
    print(f"  findings:  {len(findings)}")
    for f in findings[:32]:
        print(f"    [{f.severity.value:8s}] {f.category:32s}  {f.description[:80]}")
    if len(findings) > 32:
        print(f"    ... +{len(findings) - 32} more")
    return 0


if __name__ == "__main__":                       # pragma: no cover
    raise SystemExit(_cli())
