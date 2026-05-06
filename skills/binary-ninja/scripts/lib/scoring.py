"""Fan-discount scoring for Finding emissions.

Implements the ACT-R fan effect at the detector substrate: the more
vulnerability classes a signal participates in, the less confident any
single class's finding should be when only that signal fires. Specific
signals carry full weight; hub signals are discounted by
`1 / (1 + ln(N))` where N is the number of classes the signal
participates in.

Without this layer, a benign event touching a hub signal (e.g.,
"tainted write" — used by stack-OF, heap-OF, format-string,
integer-OF, uninit-mem, type-confusion) activates every connected
vulnerability class simultaneously, producing correlated false-positive
cascades. With it, a single hub signal is insufficient to confidently
emit a finding; combination with a class-specific signal is required.

Modelled on `graph.go:fanDiscount` in LJM, adapted to the Finding
emission path.

Key types:

- `SignalClass` — HUB (discounted) vs SPECIFIC (full weight)
- `Signal`     — named pattern with reach + base weight
- registry     — module-global map; modules register at import time

Public API for detectors:

    from ..lib.scoring import (
        Signal, SignalClass,
        register_signal, apply_signals_to_finding,
    )

    register_signal(Signal(
        name="tainted_size_arg",
        klass=SignalClass.HUB,
        participating_categories=("integer_overflow_to_allocation",
                                  "stack_buffer_overflow",
                                  "heap_buffer_overflow"),
        base_weight=0.6,
    ))

    # On Finding emission:
    apply_signals_to_finding(finding,
                             ["tainted_size_arg",
                              "missing_alloc_size_guard_dominator"])

After `apply_signals_to_finding`:

- `finding.confidence` is set to the composite score
- `finding.details["signals"]` lists the contributing signal names
- `finding.details["signal_confidence"]` mirrors `finding.confidence`
  (kept as a separate key for renderers that don't read schema fields)

Existing detectors that don't yet declare signals retain
`finding.confidence = 0.5` (neutral). Fan discount is opt-in per
detector; the foundation lands the substrate, individual detectors
adopt as they're rebuilt.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Sequence

from ..output.finding import Finding


# ─────────────────────────────────────────────────────────────────
# Signal model
# ─────────────────────────────────────────────────────────────────


class SignalClass(str, Enum):
    """Whether a signal is a hub (many classes) or specific (one or few).

    HUB     — pattern that participates in 2+ vuln classes; subject to
              fan discounting.
    SPECIFIC — pattern uniquely identifying its class; full weight.
    """

    HUB = "hub"
    SPECIFIC = "specific"


@dataclass(frozen=True)
class Signal:
    """A named detection pattern with provenance.

    Fields:

    - `name` — stable identifier; used as the registry key. Detectors
              cite this in `Finding.details["signals"]`.
    - `klass` — HUB or SPECIFIC.
    - `participating_categories` — vuln Finding categories this signal
              contributes to. The arity drives the fan factor.
    - `base_weight` — native confidence contribution of this signal
              before fan discounting (0.0-1.0). 0.6 is a sensible
              default for moderately-strong signals; raise to 0.85+
              for high-confidence specifics, drop to 0.3-0.4 for
              weak supporting signals.
    - `description` — optional human-readable note for reports.
    """

    name: str
    klass: SignalClass
    participating_categories: tuple[str, ...]
    base_weight: float = 0.6
    description: str = ""


# ─────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────


_REGISTRY: dict[str, Signal] = {}


def register_signal(signal: Signal, *, overwrite: bool = False) -> None:
    """Register a signal in the global registry.

    Modules call this at import time. Re-registration with
    `overwrite=False` is a no-op so re-imports / test re-loads don't
    multiply registrations.
    """
    if signal.name in _REGISTRY and not overwrite:
        return
    _REGISTRY[signal.name] = signal


def get_signal(name: str) -> Optional[Signal]:
    """Return the registered Signal with this name, or None."""
    return _REGISTRY.get(name)


def all_signals() -> list[Signal]:
    """Return all registered signals (sorted by name for stability)."""
    return sorted(_REGISTRY.values(), key=lambda s: s.name)


def clear_registry() -> None:
    """Test-only: drop all registered signals.

    Production code should not call this. Tests use it to isolate
    module-level registration side-effects between cases.
    """
    _REGISTRY.clear()


# ─────────────────────────────────────────────────────────────────
# Fan-factor maths
# ─────────────────────────────────────────────────────────────────


def fan_factor(signal: Signal) -> float:
    """ACT-R fan discount: 1 / (1 + ln(N)).

    Reference values:

        N=1: factor 1.00 (no discount)
        N=2: factor 0.59
        N=3: factor 0.48
        N=5: factor 0.38
        N=8: factor 0.32

    SPECIFIC signals always return 1.0 regardless of registered
    `participating_categories` length — this lets a near-specific
    signal (e.g., one that touches a parent + child class) declare
    its true reach without losing its no-discount status.
    """
    if signal.klass is SignalClass.SPECIFIC:
        return 1.0
    n = max(1, len(signal.participating_categories))
    if n == 1:
        return 1.0
    return 1.0 / (1.0 + math.log(n))


def signal_contribution(signal: Signal) -> float:
    """Effective confidence contribution of a single signal (0.0-1.0).

    Equals `base_weight × fan_factor(signal)`, clamped.
    """
    return max(0.0, min(1.0, signal.base_weight * fan_factor(signal)))


def composite_confidence(signal_names: Sequence[str]) -> float:
    """Combine multiple signals into one confidence via noisy-OR.

    `P(real | signals) = 1 − ∏ᵢ (1 − contributionᵢ)`

    Properties of this combiner:

    - Independent signals each *raise* confidence (more evidence is
      better).
    - Strong specific signals dominate (one 0.85 signal already lands
      at 0.85).
    - Hub signals contribute, but less (a 0.6 × 0.59 = 0.35 hub adds
      ~0.35 in isolation, much less when combined with specifics that
      already cover most of the probability mass).
    - Multiple independent hubs accumulate but don't easily reach 1.0
      without a specific anchor — which is the whole point.

    Empty / unknown-only inputs return 0.5 (neutral) so detectors
    that don't declare signals fall back to the existing default.
    """
    if not signal_names:
        return 0.5
    one_minus = 1.0
    saw_known = False
    for name in signal_names:
        s = _REGISTRY.get(name)
        if s is None:
            continue
        saw_known = True
        contribution = signal_contribution(s)
        one_minus *= (1.0 - contribution)
    if not saw_known:
        return 0.5
    return max(0.0, min(1.0, 1.0 - one_minus))


def apply_signals_to_finding(finding: Finding,
                             signal_names: Sequence[str]) -> float:
    """Set `finding.confidence` and `finding.details['signals']`.

    Mutates the Finding. Returns the computed composite confidence
    so detectors can branch on it (e.g., suppress emission below a
    confidence floor).

    Detectors call this immediately after constructing a Finding to
    annotate it with its driving signals. Renderers and filters can
    then read `finding.confidence` as the 0.0-1.0 confidence-it-is-
    real score, distinct from `mitigation_weighted_exploitability`
    (the assuming-it's-real exploitability score).
    """
    confidence = composite_confidence(signal_names)
    finding.confidence = confidence
    if finding.details is None:
        finding.details = {}
    finding.details["signals"] = list(signal_names)
    finding.details["signal_confidence"] = confidence
    return confidence


# ─────────────────────────────────────────────────────────────────
# Phase-1 / Tier-2 signal pre-registration
# ─────────────────────────────────────────────────────────────────
#
# Centralising the signal catalogue here (rather than in each detector
# module) gives one place to audit hub/specific assignment and
# participating-category lists. Detectors reference signals by name.
#
# Naming conventions:
#   - `tainted_*`              → input-derived state; usually HUB
#   - `missing_*`              → SPECIFIC; absence-of-defence
#   - `<class>_signature_*`    → SPECIFIC; structural pattern unique
#                                to the class
#   - `<sink>_at_<position>`   → HUB or SPECIFIC depending on reach
#
# Adding a signal: append to one of the lists below and the detector
# can immediately register it. New categories should also update any
# listed signal whose `participating_categories` they belong to.

_HUB_SIGNALS: tuple[Signal, ...] = (
    Signal(
        name="tainted_size_arg",
        klass=SignalClass.HUB,
        participating_categories=(
            "integer_overflow_to_allocation",
            "stack_buffer_overflow",
            "heap_buffer_overflow",
            "kernel_alloc_size_attacker_controlled",
        ),
        base_weight=0.55,
        description="Allocation / copy size argument carries attacker-derived taint.",
    ),
    Signal(
        name="tainted_pointer_write",
        klass=SignalClass.HUB,
        participating_categories=(
            "stack_buffer_overflow",
            "heap_buffer_overflow",
            "type_confusion",
            "format_string",
            "uninitialised_memory_disclosure",
            "tainted_pointer_dereference",
        ),
        base_weight=0.50,
        description="Memory write whose destination is reachable from attacker-controlled pointer.",
    ),
    Signal(
        name="tainted_pointer_read",
        klass=SignalClass.HUB,
        participating_categories=(
            "uninitialised_memory_disclosure",
            "type_confusion",
            "format_string",
            "tainted_pointer_dereference",
        ),
        base_weight=0.50,
        description="Memory read whose source is reachable from attacker-controlled pointer.",
    ),
    Signal(
        name="alloc_then_write_no_full_init",
        klass=SignalClass.HUB,
        participating_categories=(
            "heap_buffer_overflow",
            "uninitialised_memory_disclosure",
        ),
        base_weight=0.55,
        description="Allocation precedes a write that does not cover the full allocated extent.",
    ),
    Signal(
        name="free_then_use",
        klass=SignalClass.HUB,
        participating_categories=(
            "use_after_free",
            "double_free",
        ),
        base_weight=0.65,
        description="A pointer used after a call to a free-class function on the same SSA value.",
    ),
)


_SPECIFIC_SIGNALS: tuple[Signal, ...] = (
    Signal(
        name="tainted_format_arg",
        klass=SignalClass.SPECIFIC,
        participating_categories=("format_string",),
        base_weight=0.90,
        description="printf-family format-slot argument is tainted (attacker-controlled format).",
    ),
    Signal(
        name="missing_alloc_size_guard_dominator",
        klass=SignalClass.SPECIFIC,
        participating_categories=("integer_overflow_to_allocation",),
        base_weight=0.80,
        description="No comparison on allocation-size SSA value dominates the alloc call site "
                    "(per ec_undefined_behavior_taxonomy: signed-OF UB lets the compiler "
                    "dead-code-eliminate present-but-redundant guards; absence in the binary "
                    "is the load-bearing signal).",
    ),
    Signal(
        name="stack_write_exceeds_compile_size",
        klass=SignalClass.SPECIFIC,
        participating_categories=("stack_buffer_overflow",),
        base_weight=0.85,
        description="Stack write whose tainted length operand can exceed the compile-time "
                    "stack-allocation size of the destination buffer (canary-padding and "
                    "red-zone aware).",
    ),
    Signal(
        name="leaf_redzone_use_with_tainted_offset",
        klass=SignalClass.SPECIFIC,
        participating_categories=("stack_buffer_overflow",),
        base_weight=0.75,
        description="Leaf function uses x86_64 SysV 128-byte red zone (no `sub rsp, N`) "
                    "with attacker-controlled offset/length on a stored value — invisible "
                    "to detectors keyed on stack-frame-size signal alone.",
    ),
    Signal(
        name="two_free_paths_same_alloc",
        klass=SignalClass.SPECIFIC,
        participating_categories=("double_free",),
        base_weight=0.85,
        description="Two free-class call sites operate on the same SSA value of the freed pointer.",
    ),
    Signal(
        name="freed_ssa_subsequent_use",
        klass=SignalClass.SPECIFIC,
        participating_categories=("use_after_free",),
        base_weight=0.80,
        description="A use of the same SSA version of a pointer after a free on it — "
                    "no intervening reassignment.",
    ),
    Signal(
        name="alloc_size_lt_full_initial_fill",
        klass=SignalClass.SPECIFIC,
        participating_categories=("uninitialised_memory_disclosure",),
        base_weight=0.75,
        description="Allocation reaches an output sink (write/send/copy_to_user) without a "
                    "preceding fill that covers the full allocated extent.",
    ),
    Signal(
        name="vtable_dispatch_after_unguarded_downcast",
        klass=SignalClass.SPECIFIC,
        participating_categories=("type_confusion",),
        base_weight=0.80,
        description="Indirect call through vtable slot of a downcast pointer where the "
                    "downcast lacks a preceding type check (RTTI / explicit tag / dynamic_cast).",
    ),
    Signal(
        name="check_then_use_split_by_attacker_window",
        klass=SignalClass.SPECIFIC,
        participating_categories=("toctou",),
        base_weight=0.75,
        description="`stat`/`access`/`open` on a path is followed by a second op on the same "
                    "path with an attacker-influenceable interval between them (signal "
                    "handler / scheduling / network round-trip).",
    ),
    # Plan A — SDDL/ACE permissive-IPC analyzer signals
    Signal(
        name="permissive_sddl_grant_overbroad_principal",
        klass=SignalClass.SPECIFIC,
        participating_categories=("permissive_sddl",),
        base_weight=0.85,
        description="SDDL string contains an Allow-ACE granting broad-write rights "
                    "(GENERIC_ALL, GENERIC_WRITE, KEY_ALL_ACCESS, etc.) to an over-broad "
                    "principal (Everyone / Anonymous Logon / Guests / Authenticated Users).",
    ),
    Signal(
        name="null_dacl_set_explicit",
        klass=SignalClass.SPECIFIC,
        participating_categories=("null_dacl",),
        base_weight=0.85,
        description="SetSecurityDescriptorDacl called with DaclPresent=TRUE and Dacl=NULL — "
                    "explicit 'no access control' configuration.",
    ),
    # Plan B — write-then-verify CFG analyzer signal
    Signal(
        name="commit_without_rollback_for_resource",
        klass=SignalClass.SPECIFIC,
        participating_categories=("pre_verification_write",),
        base_weight=0.75,
        description="Function commits data to a resource (file / heap / registry) and "
                    "has a conditional failure branch but does not call any matching "
                    "rollback API for that resource type.",
    ),
    # Plan C — PRNG-in-crypto-context analyzer signal
    Signal(
        name="low_entropy_seed_to_prng",
        klass=SignalClass.SPECIFIC,
        participating_categories=("low_entropy_prng_seed",),
        base_weight=0.85,
        description="`srand` / `srandom` / `seed48` argument SSA-def chain traces back "
                    "to a low-entropy time source (`time`, `GetTickCount`, "
                    "`QueryPerformanceCounter`, `__rdtsc`). PRNG state recoverable "
                    "given approximate boot/connect time.",
    ),
    Signal(
        name="csprng_laundered_through_weak_prng",
        klass=SignalClass.SPECIFIC,
        participating_categories=("csprng_laundered_to_weak_prng",),
        base_weight=0.75,
        description="CSPRNG output (BCryptGenRandom / RAND_bytes / getrandom / etc.) "
                    "flows into `srand`/`srandom` argument. The seed is high-entropy "
                    "but the resulting weak-PRNG output is predictable from a few "
                    "observations; CSPRNG seeding does not strengthen rand-family.",
    ),
    Signal(
        name="permissive_sddl_grant_overbroad_principal_canonical_sid",
        klass=SignalClass.SPECIFIC,
        participating_categories=("permissive_sddl",),
        base_weight=0.85,
        description="Same as `permissive_sddl_grant_overbroad_principal` but the SDDL "
                    "string used the canonical SID form (S-1-1-0 / S-1-5-7 / "
                    "S-1-5-32-546) rather than the abbreviation.",
    ),
)


def _register_initial_catalogue() -> None:
    """Idempotently register the Tier-2 signal catalogue.

    Called once at module import. Detectors that emit findings driven
    by these signals look them up by name; new detectors append to
    the lists above and re-import.
    """
    for s in _HUB_SIGNALS + _SPECIFIC_SIGNALS:
        register_signal(s)


_register_initial_catalogue()


# ─────────────────────────────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────────────────────────────


def explain_finding_confidence(finding: Finding) -> dict:
    """Decompose a Finding's signal confidence for human inspection.

    Returns a dict with one entry per cited signal: registered class,
    arity, fan factor, base weight, contribution. Useful for triage
    when a confidence value seems wrong — quickly identifies a
    mis-classified signal (e.g., a real specific marked HUB).
    """
    out: dict = {
        "category": finding.category,
        "address": hex(finding.address) if isinstance(finding.address, int) else finding.address,
        "confidence": finding.confidence,
        "signals": [],
    }
    sig_names = (finding.details or {}).get("signals", [])
    for name in sig_names:
        s = _REGISTRY.get(name)
        if s is None:
            out["signals"].append({"name": name, "registered": False})
            continue
        out["signals"].append({
            "name": s.name,
            "registered": True,
            "klass": s.klass.value,
            "arity": len(s.participating_categories),
            "fan_factor": fan_factor(s),
            "base_weight": s.base_weight,
            "contribution": signal_contribution(s),
        })
    return out
