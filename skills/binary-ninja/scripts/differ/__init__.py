"""Binary diff — Phase 5.

1-day workflow + Patch-Tuesday analysis. Compares two BinaryViews
(typically pre-patch / post-patch of the same module) and emits a
typed diff describing what changed.

Skeleton in this revision: data shapes + entry-point API. Real
implementations of byte / HLIL / callgraph / string diff are deferred.

Knowledge anchors (future):
- 1-day analysis methodology (TODO: Knowledge entry)

Public API:
- `BinaryDiff` — dataclass holding categorised changes
- `FunctionDelta` — per-function add / remove / modify record
- `diff(bv_a, bv_b)` — top-level entry; returns BinaryDiff
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class FunctionDelta:
    """One function-level change between two binaries."""

    kind: str                          # "added" | "removed" | "modified"
    addr_a: Optional[int] = None       # address in bv_a (None if added)
    addr_b: Optional[int] = None       # address in bv_b (None if removed)
    name_a: str = ""
    name_b: str = ""
    size_a: int = 0
    size_b: int = 0
    body_hash_a: str = ""              # short hash of MLIL or bytes
    body_hash_b: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.addr_a is not None:
            d["addr_a"] = hex(self.addr_a)
        if self.addr_b is not None:
            d["addr_b"] = hex(self.addr_b)
        return d


@dataclass
class StringDelta:
    """One string-table change. Security fixes often show up here:
    new error messages, hardened-format-string introductions, removed
    debug-only strings."""

    kind: str                          # "added" | "removed"
    value: str = ""
    addr: int = 0


@dataclass
class ImportDelta:
    """One import-table change. Useful for detecting new mitigation
    APIs (e.g., a post-patch binary newly importing
    `BCryptVerifySignature`)."""

    kind: str                          # "added" | "removed"
    name: str = ""


@dataclass
class BinaryDiff:
    """Full diff between two BinaryViews."""

    binary_a: str
    binary_b: str
    function_deltas: list[FunctionDelta] = field(default_factory=list)
    string_deltas: list[StringDelta] = field(default_factory=list)
    import_deltas: list[ImportDelta] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        kinds_fn = {"added": 0, "removed": 0, "modified": 0}
        for d in self.function_deltas:
            kinds_fn[d.kind] = kinds_fn.get(d.kind, 0) + 1
        kinds_str = {"added": 0, "removed": 0}
        for d in self.string_deltas:
            kinds_str[d.kind] = kinds_str.get(d.kind, 0) + 1
        kinds_imp = {"added": 0, "removed": 0}
        for d in self.import_deltas:
            kinds_imp[d.kind] = kinds_imp.get(d.kind, 0) + 1
        return {
            "functions": kinds_fn,
            "strings": kinds_str,
            "imports": kinds_imp,
        }

    def to_dict(self) -> dict:
        return {
            "binary_a": self.binary_a,
            "binary_b": self.binary_b,
            "summary": self.summary,
            "function_deltas": [d.to_dict() for d in self.function_deltas],
            "string_deltas": [asdict(d) for d in self.string_deltas],
            "import_deltas": [asdict(d) for d in self.import_deltas],
            "notes": list(self.notes),
        }


def diff(bv_a, bv_b, *,
         binary_a: str = "", binary_b: str = "") -> BinaryDiff:
    """Produce a `BinaryDiff` between two BinaryViews.

    Phase 5 scaffolding: returns a BinaryDiff with empty delta lists.
    Real implementation will populate function / string / import
    deltas via the deferred submodules listed in this module's
    docstring (`byte_diff`, `hlil_diff`, `callgraph_diff`,
    `string_diff`, `fix_patterns`).
    """
    return BinaryDiff(
        binary_a=binary_a,
        binary_b=binary_b,
        notes=[
            "scaffolding stub — diff is empty until byte_diff / "
            "hlil_diff / callgraph_diff / string_diff submodules land",
        ],
    )


__all__ = [
    "FunctionDelta", "StringDelta", "ImportDelta", "BinaryDiff", "diff",
]
