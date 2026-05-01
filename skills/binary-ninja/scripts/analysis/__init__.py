"""Static analysis modules.

Phase 1 status:

    surface.py        — recon stage; TargetProfile + binary-scope Findings  [done]
    mitigations.py    — header-driven mitigation matrix + scoring           [done]
    taint.py          — MLIL SSA inter-procedural taint                     [done]
    heap.py           — UAF / double-free / heap-OF / unchecked alloc       [done]

Subsequent Phase 1 work (next):

    crypto.py         — PRNG choice, IV reuse, KDF, custom cipher
    obfuscation.py    — packers, control-flow flattening, string ciphers
    chains.py         — multi-component chain pattern matching
    attack_surface.py — entry → sink reachability

Each module exposes:

    def analyze(session: BinjaSession, **kwargs) -> list[Finding]:
        ...

and consumes patterns from `..heuristics` modules where applicable.
"""

from . import heap, mitigations, surface, taint
from . import _il_helpers
from .surface import SectionInfo, TargetProfile, analyze, build_profile

__all__ = [
    "surface", "mitigations", "taint", "heap",
    "_il_helpers",
    "SectionInfo", "TargetProfile",
    "analyze", "build_profile",
]
