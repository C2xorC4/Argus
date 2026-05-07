"""Finding v2 — unified schema across all Argus skill modules.

Replaces the per-script `Finding` dataclasses scattered across the
legacy binary-ninja scripts. Every detector module emits Finding
objects via this schema; every renderer (SARIF, markdown, vendor
report) consumes this schema.

Provenance is first-class: every Finding carries `knowledge_refs`
citing the LJM Knowledge entry / entries that drove the detection.
This is the substrate-coherence check — if a Finding's category
doesn't match its knowledge_refs (per `jm associate`), the
heuristics module is mis-cited.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

from ..lib.state import FindingState, StateTransition


# ─────────────────────────────────────────────────────────────────
# Enums and value objects
# ─────────────────────────────────────────────────────────────────


class Severity(str, Enum):
    """CVSS-aligned severity bucket. Per-pattern; not per-module."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def numeric(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class DisclosureAltitude(str, Enum):
    """Per `Memory/Feedback/disclosure_altitude_capability_vs_results`.

    Filters what's emittable in public-facing artefacts. PROVEN-only
    output further filters; this controls *altitude* of the description.
    """

    CAPABILITY = "capability"        # what class of bug; safe to publish
    OBSERVATION = "observation"      # technique-level observation; safe with care
    RESULT = "result"                # specific outcome; vendor-internal only
    INSTANCE = "instance"            # named target / address / version; private only


@dataclass
class Evidence:
    """One piece of evidence backing a Finding.

    Multiple Evidence entries accumulate as a Finding traverses states
    (DETECTED static evidence -> CONFIRMED reachability proof ->
    IMPACT_VERIFIED launch-chain test result).
    """

    kind: str                        # e.g. "raw_bytes", "mlil_excerpt", "sanitizer_output", "debugger_trace"
    source: str                      # which module / tool produced this evidence
    payload: str                     # serialised evidence (hex, IL, log excerpt)
    address: Optional[int] = None
    function: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.address is not None:
            d["address"] = hex(self.address)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Evidence":
        d = dict(d)
        if isinstance(d.get("address"), str):
            d["address"] = int(d["address"], 16)
        return cls(**d)


@dataclass
class TargetMitigations:
    """Per-target hardening profile, used by `analysis/mitigations.py`
    to compute mitigation-weighted exploitability.

    Boolean fields where the absence is significant (the GameGuard
    finding case: zero /GS, zero CFG, 10/15 missing ASLR makes any
    memory-corruption bug deterministically exploitable).
    """

    GS: Optional[bool] = None        # /GS stack canary
    CFG: Optional[bool] = None       # Control Flow Guard
    ASLR: Optional[bool] = None
    DEP: Optional[bool] = None       # NX
    PIE: Optional[bool] = None
    RELRO: Optional[bool] = None     # full / partial / none → use string elsewhere; bool here = any
    FORTIFY: Optional[bool] = None
    CET: Optional[bool] = None       # Intel CET shadow stack / IBT
    PAC: Optional[bool] = None       # ARM Pointer Authentication
    MTE: Optional[bool] = None       # ARM Memory Tagging Extension
    SAFESEH: Optional[bool] = None
    SEHOP: Optional[bool] = None
    extras: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {k: v for k, v in asdict(self).items() if k != "extras" and v is not None}
        d.update(self.extras)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "TargetMitigations":
        known = {f for f in cls.__dataclass_fields__ if f != "extras"}
        kwargs = {k: v for k, v in d.items() if k in known}
        extras = {k: v for k, v in d.items() if k not in known}
        return cls(**kwargs, extras=extras)


# ─────────────────────────────────────────────────────────────────
# The Finding object
# ─────────────────────────────────────────────────────────────────


@dataclass
class Finding:
    """Argus unified finding schema, v2.

    Stable across all detector modules. Renderers (SARIF, markdown,
    vendor report) consume this schema only — they never reach into
    detector internals.
    """

    # --- Identity -----------------------------------------------------
    id: str                          # stable hash; computed by `compute_id` if blank
    category: str                    # e.g. "buffer_overflow", "direct_syscall_stub"
    severity: Severity

    # --- Localisation -------------------------------------------------
    address: int
    function: str
    binary: str                      # path or content hash of the analysed binary
    arch: str                        # "x86_64", "x86", "aarch64", "armv7", "mips32", "riscv64", ...
    platform: str                    # "linux", "windows", "macos", "freebsd", "android", "ios", "uefi", ...

    # --- Provenance ---------------------------------------------------
    detector: str                    # which Argus module produced this Finding
    knowledge_refs: list[str] = field(default_factory=list)  # ["[[Memory/Knowledge/...]]"]
    cwe: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)    # technique IDs

    # --- State machine ------------------------------------------------
    state: FindingState = FindingState.DETECTED
    state_history: list[StateTransition] = field(default_factory=list)

    # --- Mitigation context ------------------------------------------
    target_mitigations: TargetMitigations = field(default_factory=TargetMitigations)
    mitigation_weighted_exploitability: float = 0.0  # 0.0-1.0; computed by mitigations.py

    # --- Detection confidence ---------------------------------------
    # Fan-discount-aware confidence from `lib/scoring.py`. Independent
    # of `mitigation_weighted_exploitability` — that scores "how
    # exploitable assuming it's real"; this scores "how confidently
    # this is real, before exploitability is considered." Set by
    # `lib.scoring.apply_signals_to_finding(...)` at emission time;
    # default 0.5 (neutral) when a detector doesn't declare signals.
    confidence: float = 0.5

    # --- Evidence + description --------------------------------------
    evidence: list[Evidence] = field(default_factory=list)
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    # --- Reporting ----------------------------------------------------
    disclosure_altitude: DisclosureAltitude = DisclosureAltitude.INSTANCE
    vendor_program: Optional[str] = None        # "epicgames", "msrc", "bugcrowd:program-x"
    bounty_category: Optional[str] = None       # "Crash server not member of", "EAC LPE", ...

    # ─────────────────────────────────────────────────────────────
    # Construction helpers
    # ─────────────────────────────────────────────────────────────

    def __post_init__(self) -> None:
        if not self.id:
            self.id = self.compute_id()

    def compute_id(self) -> str:
        """Deterministic id from category + binary-hash + address + signature.

        Stable across runs against the same binary so finding-tracking
        across consolidations works. Collision-resistant only by SHA-256
        prefix; if you need cryptographic uniqueness use `id` as input
        rather than identity.
        """
        sig_components = [
            self.category,
            self.binary,
            f"{self.address:x}" if isinstance(self.address, int) else str(self.address),
            self.detector,
            "|".join(sorted(self.knowledge_refs)),
        ]
        material = "::".join(sig_components).encode("utf-8")
        return hashlib.sha256(material).hexdigest()[:16]

    # ─────────────────────────────────────────────────────────────
    # Serialisation
    # ─────────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category,
            "severity": self.severity.value,
            "address": hex(self.address) if isinstance(self.address, int) else self.address,
            "function": self.function,
            "binary": self.binary,
            "arch": self.arch,
            "platform": self.platform,
            "detector": self.detector,
            "knowledge_refs": list(self.knowledge_refs),
            "cwe": list(self.cwe),
            "mitre_attack": list(self.mitre_attack),
            "state": self.state.value,
            "state_history": [t.to_dict() for t in self.state_history],
            "target_mitigations": self.target_mitigations.to_dict(),
            "mitigation_weighted_exploitability": self.mitigation_weighted_exploitability,
            "confidence": self.confidence,
            "evidence": [e.to_dict() for e in self.evidence],
            "description": self.description,
            "details": self.details,
            "disclosure_altitude": self.disclosure_altitude.value,
            "vendor_program": self.vendor_program,
            "bounty_category": self.bounty_category,
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        addr = d.get("address", 0)
        if isinstance(addr, str):
            addr = int(addr, 16)
        return cls(
            id=d.get("id", ""),
            category=d["category"],
            severity=Severity(d["severity"]),
            address=addr,
            function=d.get("function", ""),
            binary=d.get("binary", ""),
            arch=d.get("arch", ""),
            platform=d.get("platform", ""),
            detector=d.get("detector", ""),
            knowledge_refs=list(d.get("knowledge_refs", [])),
            cwe=list(d.get("cwe", [])),
            mitre_attack=list(d.get("mitre_attack", [])),
            state=FindingState(d.get("state", FindingState.DETECTED.value)),
            state_history=[StateTransition.from_dict(t) for t in d.get("state_history", [])],
            target_mitigations=TargetMitigations.from_dict(d.get("target_mitigations", {})),
            mitigation_weighted_exploitability=float(d.get("mitigation_weighted_exploitability", 0.0)),
            confidence=float(d.get("confidence", 0.5)),
            evidence=[Evidence.from_dict(e) for e in d.get("evidence", [])],
            description=d.get("description", ""),
            details=dict(d.get("details", {})),
            disclosure_altitude=DisclosureAltitude(d.get("disclosure_altitude", DisclosureAltitude.INSTANCE.value)),
            vendor_program=d.get("vendor_program"),
            bounty_category=d.get("bounty_category"),
        )

    # ─────────────────────────────────────────────────────────────
    # Convenience predicates
    # ─────────────────────────────────────────────────────────────

    @property
    def is_externally_reportable(self) -> bool:
        """External output gate.

        Combines the state-machine PROVEN check with the disclosure-
        altitude filter. INSTANCE-altitude findings stay private even
        when PROVEN unless the operator explicitly elevates them.
        """
        return (
            self.state.is_external_reportable
            and self.disclosure_altitude in (
                DisclosureAltitude.CAPABILITY,
                DisclosureAltitude.OBSERVATION,
            )
        )

    def cite(self) -> str:
        """One-line citation suitable for human-readable reports."""
        refs = ", ".join(self.knowledge_refs) if self.knowledge_refs else "(no Knowledge citation)"
        return f"{self.category} @ {self.function} ({self.binary}+{hex(self.address)}) — {refs}"


# ─────────────────────────────────────────────────────────────────
# Schema export for validators
# ─────────────────────────────────────────────────────────────────


FINDING_V2_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Argus Finding v2",
    "type": "object",
    "required": [
        "id", "category", "severity", "address", "function", "binary",
        "arch", "platform", "detector", "state",
    ],
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "category": {"type": "string", "minLength": 1},
        "severity": {"enum": [s.value for s in Severity]},
        "address": {"type": ["string", "integer"]},
        "function": {"type": "string"},
        "binary": {"type": "string"},
        "arch": {"type": "string"},
        "platform": {"type": "string"},
        "detector": {"type": "string"},
        "knowledge_refs": {"type": "array", "items": {"type": "string"}},
        "cwe": {"type": "array", "items": {"type": "string"}},
        "mitre_attack": {"type": "array", "items": {"type": "string"}},
        "state": {"enum": [s.value for s in FindingState]},
        "state_history": {"type": "array"},
        "target_mitigations": {"type": "object"},
        "mitigation_weighted_exploitability": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "evidence": {"type": "array"},
        "description": {"type": "string"},
        "details": {"type": "object"},
        "disclosure_altitude": {"enum": [a.value for a in DisclosureAltitude]},
        "vendor_program": {"type": ["string", "null"]},
        "bounty_category": {"type": ["string", "null"]},
    },
}
