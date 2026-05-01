"""Argus binary-ninja skill — Python package root.

Layout:
    analysis/    — static analysis (surface, taint, heap, crypto, mitigations,
                   obfuscation, chains)
    heuristics/  — Knowledge-derived pattern tables consumed by analysis modules
    exploit/     — primitive construction (Phase 3)
    verify/      — dynamic verification (Phase 4)
    differ/      — binary diff (Phase 5)
    patch/       — binary patch (Phase 5)
    output/      — Finding schema + renderers (SARIF, markdown, vendor reports)
    lib/         — shared library (binja wrapper, jm integration, state machine)
    legacy/      — old scripts kept as reference during migration

See ../SKILL.md for the protocol and ../MANUAL_WORKFLOWS.md for
per-module operator companion documentation.
"""

__version__ = "0.0.1-phase0"
