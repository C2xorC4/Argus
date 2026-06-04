"""Chain analysis — compose Tier-2 chain Findings from Tier-1 primitives.

This module is *post-stage*: it consumes the aggregate Findings from
the upstream identification stage (surface + taint + heap + crypto +
obfuscation) and emits a composite `chain_pattern` Finding when a
known chain template matches.

Chain templates live in `heuristics/chains.py`; this analysis module
is a thin orchestrator that:

1. Optionally runs the upstream analysis modules itself (when invoked
   stand-alone) to gather primitives.
2. Passes the aggregate Findings to `heuristics.chains.match()` for
   template matching.
3. Returns the composed chain Findings.

Knowledge anchors for the chain templates:
- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]`
- `[[Memory/Knowledge/ue5_server_crash_chain_prng_fstring]]`
- `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]`
- `[[Memory/Knowledge/ue5_fstring_allocation_amplification]]`
- `[[Memory/Knowledge/wnapi_heap_internals]]` (info-leak → UAF → ROP class)
- `[[Memory/Knowledge/em_advanced_injection_variants]]`
- `[[Memory/Knowledge/em_direct_syscall_ssn_resolution]]`
- `[[Memory/Knowledge/em_covert_execution_tls_seh]]`

Phase 1 limitations:
- Chain matching is set-based: template matches when *all* primitive
  categories appear in the findings list, regardless of inter-
  procedural connection. False positives are possible when separate
  vulnerabilities of the right shapes coincidentally co-exist
  without actually forming a chain. Phase 1+ adds:
  - control-flow reachability between primitives (the EAC chain
    requires the privileged service path to actually reach all four
    primitives)
  - data-flow connection (UE5 chain requires HandshakeSecret to flow
    from the PRNG into cookie-validation into the amplifier)
"""

from __future__ import annotations

from typing import Optional

from ..heuristics import chains as heur_chains
from ..output.finding import Finding
from . import crypto as crypto_mod
from . import format_string as format_string_mod
from . import heap as heap_mod
from . import mitigations as mitigations_mod
from . import obfuscation as obfuscation_mod
from . import stack as stack_mod
from . import surface as surface_mod
from . import taint as taint_mod


def _gather_upstream(session, *, binary, arch, platform) -> list[Finding]:
    """Run every upstream module and return the aggregated Findings."""
    findings: list[Finding] = []
    profile, surf = surface_mod.analyze(
        session=session, binary_path=binary, run_heuristics=True,
    )
    findings.extend(surf)
    findings.extend(taint_mod.analyze(
        session, binary=binary, arch=arch, platform=platform,
        score_against_mitigations=False,         # we score once at end
    ))
    findings.extend(heap_mod.analyze(
        session, binary=binary, arch=arch, platform=platform,
        score_against_mitigations=False,
    ))
    findings.extend(crypto_mod.analyze(
        session, binary=binary, arch=arch, platform=platform,
        score_against_mitigations=False,
    ))
    findings.extend(obfuscation_mod.analyze(
        session, binary=binary, arch=arch, platform=platform,
        score_against_mitigations=False,
    ))
    findings.extend(stack_mod.analyze(
        session, binary=binary, arch=arch, platform=platform,
        score_against_mitigations=False,
    ))
    findings.extend(format_string_mod.analyze(
        session, binary=binary, arch=arch, platform=platform,
        score_against_mitigations=False,
    ))
    return findings


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            existing_findings: Optional[list[Finding]] = None,
            score_against_mitigations: bool = True,
            detector: str = "analysis.chains") -> list[Finding]:
    """Compose chain Findings.

    If `existing_findings` is given, use that list (typical orchestrator
    flow — the orchestrator already ran the upstream modules). Else
    invoke the upstream modules ourselves.

    Returns *only* the composed chain Findings (the upstream Findings
    are not re-emitted; the caller already has them).
    """
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    upstream = (existing_findings if existing_findings is not None
                else _gather_upstream(session, binary=binary, arch=arch,
                                      platform=platform))

    chain_findings = heur_chains.match(
        bv, binary=binary, arch=arch, platform=platform,
        detector=detector, existing_findings=upstream,
    )

    if score_against_mitigations and chain_findings and binary:
        try:
            profile = mitigations_mod.extract_mitigations(binary, bv=bv)
            mitigations_mod.score_findings(chain_findings, profile)
        except Exception:
            pass

    return chain_findings
