"""Dynamic verification — Phase 4.

Implemented (minimal slice):
    sanitizer.py — SSH-driven verification primitive: file-hash
                   deltas + dmesg-pattern matching against a
                   configured lab target. Returns a VerificationResult
                   with verdict roll-up and Evidence rendering.
    triage.py    — verification-plan orchestrator + state-machine
                   driver. Reads Findings, runs sanitizer.py per a
                   plan, walks Findings through the legal state
                   transitions (DETECTED → CONFIRMED → IMPACT_VERIFIED),
                   persists evidence and run logs.

Deferred (see verify/README.md for the full forward-state):
    debugger.py  — GDB / WinDbg / LLDB launch-chain harness for
                   userspace exploitation verification
    asan.py      — ASan / UBSan / MSan / TSan instrumented build
                   integration
    crash_dedup.py — crash deduplication across multiple plans
"""

from .sanitizer import (
    DEFAULT_DMESG_PATTERNS,
    Evidence,
    FileDelta,
    FileSnapshot,
    VerificationResult,
    recommend_state,
    verify_remote,
)
from .local import (
    DEFAULT_CRASH_PATTERNS,
    verify_local,
    verify_finding_locally,
)
from .triage import (
    apply_verification,
    load_findings,
    load_plan,
    save_findings,
    select_findings,
    write_run_log,
)

__all__ = [
    "DEFAULT_DMESG_PATTERNS",
    "DEFAULT_CRASH_PATTERNS",
    "Evidence",
    "FileDelta",
    "FileSnapshot",
    "VerificationResult",
    "apply_verification",
    "load_findings",
    "load_plan",
    "recommend_state",
    "save_findings",
    "select_findings",
    "verify_remote",
    "verify_local",
    "verify_finding_locally",
    "write_run_log",
]
