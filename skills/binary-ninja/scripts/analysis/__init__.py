"""Static analysis modules.

Phase 1 status:

    surface.py        — recon stage; TargetProfile + binary-scope Findings  [done]
    mitigations.py    — header-driven mitigation matrix + scoring           [done]
    taint.py          — MLIL SSA inter-procedural taint                     [done]
    heap.py           — UAF / double-free / heap-OF / unchecked alloc       [done]
    crypto.py         — PRNG choice, weak crypto, PRNG-to-sink flow         [done]
    obfuscation.py    — packers, entropy, RWX sections, CFF candidates      [done]
    chains.py         — multi-component chain pattern matching              [done]
    attack_surface.py — entry-point -> reachable-sink mapping               [done]
    linux_exploit.py  — seccomp arg check, alarm timeout, ret2win scan      [done]

Each module exposes:

    def analyze(session: BinjaSession, **kwargs) -> list[Finding]:
        ...

and consumes patterns from `..heuristics` modules where applicable.
"""

from . import (
    _il_helpers, attack_surface, chains, cloud_files, composition, crypto,
    heap, linux_exploit, mitigations, obfuscation, rpc_interface,
    source_surface, surface, taint, windows_drivers,
)
from .surface import SectionInfo, TargetProfile, analyze, build_profile

__all__ = [
    "surface", "mitigations", "taint", "heap",
    "crypto", "obfuscation", "chains", "attack_surface",
    "cloud_files", "composition", "rpc_interface",
    "windows_drivers", "source_surface", "linux_exploit",
    "_il_helpers",
    "SectionInfo", "TargetProfile",
    "analyze", "build_profile",
]
