"""Binary patching — Phase 5.

Authorised binary modification for CTF / RE / authorised testing.
Per `docs/PIPELINE.md`, the binary-patcher is a cross-cutting
agent — patching is gated behind operator confirmation regardless
of which stage invokes it.

Skeleton in this revision: data shapes + entry-point API. Real
NOP / branch / string / redirect / code-cave / metadata-fixup
operations deferred.

Public API:
- `Patch` — one bytewise modification (kind + offset + bytes)
- `PatchPlan` — collection of Patches for a single binary
- `apply_patch(bv, plan, *, dry_run=True)` — apply a plan with a
   dry-run gate by default; live application requires explicit
   `dry_run=False`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Patch:
    """One bytewise modification to a binary."""

    kind: str                          # "nop" | "branch_force" | "branch_invert"
                                       # | "string_replace" | "redirect"
                                       # | "code_cave" | "raw_bytes"
    offset: int                        # file offset (not VA)
    new_bytes: bytes
    original_bytes: bytes = b""        # for round-trip / undo
    description: str = ""
    notes: list[str] = field(default_factory=list)


@dataclass
class PatchPlan:
    """A set of `Patch` operations to apply to one binary."""

    target_binary: str
    target_sha1: str = ""              # binding to a specific build
    patches: list[Patch] = field(default_factory=list)
    description: str = ""
    operator_authorised: bool = False  # explicit authorisation gate

    def to_dict(self) -> dict:
        return {
            "target_binary": self.target_binary,
            "target_sha1": self.target_sha1,
            "description": self.description,
            "operator_authorised": self.operator_authorised,
            "patches": [
                {
                    "kind": p.kind,
                    "offset": hex(p.offset),
                    "new_bytes": p.new_bytes.hex(),
                    "original_bytes": p.original_bytes.hex(),
                    "description": p.description,
                    "notes": list(p.notes),
                }
                for p in self.patches
            ],
        }


@dataclass
class PatchResult:
    """Outcome of `apply_patch`."""

    plan: PatchPlan
    applied: bool                      # False on dry-run or refusal
    written_path: Optional[str] = None
    failures: list[str] = field(default_factory=list)


def apply_patch(bv, plan: PatchPlan, *,
                dry_run: bool = True,
                output_path: Optional[str] = None) -> PatchResult:
    """Apply a `PatchPlan` to `bv`.

    Phase 5 scaffolding: always returns a `PatchResult` with
    `applied=False`. Real implementation will write patched bytes
    via `bv.write(addr, bytes)` and emit a new file via
    `bv.create_database()` or raw-bytes export.

    The `dry_run=True` default is the operator-confirmation gate —
    callers must explicitly opt out to mutate the binary.
    """
    failures: list[str] = []
    if not plan.operator_authorised:
        failures.append("plan.operator_authorised=False — refusing to apply")
    if dry_run:
        failures.append("dry_run=True — no bytes written")
    failures.append(
        "scaffolding stub — apply_patch performs no I/O; integrate "
        "bv.write + file emission in the real implementation"
    )
    return PatchResult(plan=plan, applied=False, written_path=None,
                       failures=failures)


__all__ = ["Patch", "PatchPlan", "PatchResult", "apply_patch"]
