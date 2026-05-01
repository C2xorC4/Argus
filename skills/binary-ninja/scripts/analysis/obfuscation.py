"""Obfuscation analysis — packers, high-entropy code, RWX sections,
control-flow flattening candidates, string-cipher signatures.

Knowledge anchors:
- `[[Memory/Knowledge/gb_obfuscated_code_analysis]]` — Ghidra Book
  obfuscated-code analysis patterns; CFF, opaque predicates,
  high-entropy regions.
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — LCG-XOR
  string cipher in production.

Phase 1 detectors:

1. Heuristics passthrough — packer section names (UPX, Themida,
   VMProtect, ASPack, Petite); LCG-XOR cipher constants in code.
2. High-entropy section — `.text` / `.code` with Shannon entropy
   ≥ 7.0 → packed / encrypted code.
3. RWX section — section with all of read+write+execute permissions
   set → runtime-decoded payload candidate.
4. CFF dispatcher candidate — single basic block with very high
   successor count whose successors all converge back to it; the
   classic flattening shape.

Phase 1 limitations:
- Opaque-predicate detection requires SMT-feasibility checking;
  deferred to Phase 1+.
- CFF dispatcher detection is a structural heuristic with relatively
  high FP rate; needs operator review on hits. Phase 1+ refinement
  consumes loop-structure analysis from `lib/binja.py`.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

from ..heuristics import obfuscation as heur_obf
from ..output.finding import Evidence, Finding, Severity
from . import mitigations as mitigations_mod


# ─────────────────────────────────────────────────────────────────
# Tuning constants
# ─────────────────────────────────────────────────────────────────


# Shannon entropy threshold — packed / encrypted code typically lands
# above 7.0 bits/byte. Plain x86_64 `.text` is 5.5–6.5.
HIGH_ENTROPY_THRESHOLD = 7.0
CODE_SECTION_NAMES = {".text", ".code", "__text", "CODE"}

# CFF dispatcher heuristic: a basic block whose outdegree is at least
# this large is a candidate.
CFF_OUTDEGREE_THRESHOLD = 10

# RWX section permissions
def _section_perms(sec) -> tuple[bool, bool, bool]:
    r = bool(getattr(sec, "readable", None) is True or getattr(sec, "read", None) is True)
    w = bool(getattr(sec, "writable", None) is True or getattr(sec, "write", None) is True)
    x = bool(getattr(sec, "executable", None) is True or getattr(sec, "execute", None) is True)
    return r, w, x


# ─────────────────────────────────────────────────────────────────
# Finding metadata
# ─────────────────────────────────────────────────────────────────


HIGH_ENTROPY_META = {
    "category": "high_entropy_section",
    "severity": Severity.MEDIUM,
    "cwe": [],
    "mitre_attack": ["T1027.002"],
    "knowledge_refs": ["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
}

RWX_SECTION_META = {
    "category": "rwx_section",
    "severity": Severity.HIGH,
    "cwe": [],
    "mitre_attack": ["T1027", "T1620"],
    "knowledge_refs": ["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
}

CFF_DISPATCHER_META = {
    "category": "control_flow_flattening_candidate",
    "severity": Severity.MEDIUM,
    "cwe": [],
    "mitre_attack": ["T1027"],
    "knowledge_refs": ["[[Memory/Knowledge/gb_obfuscated_code_analysis]]"],
}


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────


def _shannon_entropy(data: bytes) -> float:
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


def _emit(meta: dict, *, address: int, function: str, binary: str,
          arch: str, platform: str, detector: str, description: str,
          evidence: list[Evidence] = None,
          details: dict = None) -> Finding:
    return Finding(
        id="",
        category=meta["category"],
        severity=meta["severity"],
        address=address,
        function=function,
        binary=binary, arch=arch, platform=platform,
        detector=detector,
        knowledge_refs=list(meta["knowledge_refs"]),
        cwe=list(meta["cwe"]),
        mitre_attack=list(meta["mitre_attack"]),
        description=description,
        evidence=evidence or [],
        details=details or {},
    )


# ─────────────────────────────────────────────────────────────────
# Detectors
# ─────────────────────────────────────────────────────────────────


def find_high_entropy_sections(bv, *, binary: str, arch: str, platform: str,
                              detector: str) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    sections = getattr(bv, "sections", None)
    if not sections:
        return findings
    iterable = sections.values() if hasattr(sections, "values") else sections
    for sec in iterable:
        try:
            name = str(getattr(sec, "name", ""))
            start = int(getattr(sec, "start", 0))
            length = int(getattr(sec, "length", 0)
                         or (getattr(sec, "end", 0) - start))
        except Exception:
            continue
        if length <= 0 or length > 64 * 1024 * 1024:
            continue
        # Only emit on code sections to avoid noise on .rdata / .data
        # which can legitimately be high-entropy for compressed
        # resources or string tables.
        if name not in CODE_SECTION_NAMES:
            # Allow common non-named code sections (Mach-O __text)
            if not (name and name.startswith("__text")):
                continue
        try:
            data = bytes(bv.read(start, length))
        except Exception:
            continue
        entropy = _shannon_entropy(data)
        if entropy < HIGH_ENTROPY_THRESHOLD:
            continue
        findings.append(_emit(
            HIGH_ENTROPY_META,
            address=start, function="<section>",
            binary=binary, arch=arch, platform=platform, detector=detector,
            description=(
                f"section {name} has Shannon entropy {entropy:.2f} bits/byte "
                f"(threshold {HIGH_ENTROPY_THRESHOLD}) — packed / encrypted"
            ),
            details={
                "section": name,
                "start": hex(start),
                "length": length,
                "entropy": round(entropy, 3),
            },
        ))
    return findings


def find_rwx_sections(bv, *, binary: str, arch: str, platform: str,
                     detector: str) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    sections = getattr(bv, "sections", None)
    if not sections:
        return findings
    iterable = sections.values() if hasattr(sections, "values") else sections
    for sec in iterable:
        r, w, x = _section_perms(sec)
        if not (r and w and x):
            continue
        name = str(getattr(sec, "name", "<unknown>"))
        start = int(getattr(sec, "start", 0))
        findings.append(_emit(
            RWX_SECTION_META,
            address=start, function="<section>",
            binary=binary, arch=arch, platform=platform, detector=detector,
            description=(
                f"section {name} at 0x{start:x} has RWX permissions — "
                f"runtime-decoded / self-modifying payload"
            ),
            details={
                "section": name,
                "start": hex(start),
                "permissions": "rwx",
            },
        ))
    return findings


def find_cff_dispatcher_candidates(bv, *, binary: str, arch: str, platform: str,
                                  detector: str,
                                  outdegree_threshold: int = CFF_OUTDEGREE_THRESHOLD,
                                  max_functions: int = 5000) -> list[Finding]:
    findings: list[Finding] = []
    if bv is None:
        return findings
    examined = 0
    for func in bv.functions:
        examined += 1
        if examined > max_functions:
            break
        try:
            blocks = list(func.basic_blocks)
        except Exception:
            continue
        if not blocks:
            continue
        # Look for a block whose outdegree exceeds threshold AND whose
        # successors mostly point back to it (the dispatcher loop).
        for bb in blocks:
            try:
                outgoing = list(getattr(bb, "outgoing_edges", []) or [])
            except Exception:
                continue
            if len(outgoing) < outdegree_threshold:
                continue
            # Successors that loop back to this BB
            back_edge_count = 0
            for edge in outgoing:
                target = getattr(edge, "target", None)
                if target is None:
                    continue
                target_outgoing = list(getattr(target, "outgoing_edges", []) or [])
                for te in target_outgoing:
                    te_target = getattr(te, "target", None)
                    if te_target is bb or getattr(te_target, "start", None) == getattr(bb, "start", None):
                        back_edge_count += 1
                        break
            if back_edge_count < outdegree_threshold // 2:
                continue
            findings.append(_emit(
                CFF_DISPATCHER_META,
                address=int(bb.start), function=func.name,
                binary=binary, arch=arch, platform=platform, detector=detector,
                description=(
                    f"function {func.name} at 0x{func.start:x} contains a basic "
                    f"block with outdegree {len(outgoing)} where ≥{back_edge_count} "
                    f"successors loop back — CFF dispatcher candidate"
                ),
                details={
                    "function_addr": hex(int(func.start)),
                    "dispatcher_block": hex(int(bb.start)),
                    "outdegree": len(outgoing),
                    "back_edge_count": back_edge_count,
                },
            ))
            break                                # one finding per function
    return findings


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            score_against_mitigations: bool = True,
            detector: str = "analysis.obfuscation") -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    findings: list[Finding] = []
    # 1. Heuristics-driven (packer markers, LCG cipher constants).
    findings.extend(heur_obf.match(
        bv, binary=binary, arch=arch, platform=platform,
    ))
    # 2. Section entropy.
    findings.extend(find_high_entropy_sections(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    # 3. RWX section permissions.
    findings.extend(find_rwx_sections(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    # 4. CFF dispatcher candidates.
    findings.extend(find_cff_dispatcher_candidates(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))

    if score_against_mitigations and findings and binary:
        try:
            profile = mitigations_mod.extract_mitigations(binary, bv=bv)
            mitigations_mod.score_findings(findings, profile)
        except Exception:
            pass

    return findings
