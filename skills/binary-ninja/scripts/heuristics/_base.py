"""Heuristics base — shared pattern shapes and helpers.

A "heuristic" is a deterministic pattern derived from an LJM
Knowledge entry. Each heuristics submodule (`imports.py`,
`syscalls.py`, ...) exports:

- A `PATTERNS` list of `Pattern`-subclass instances (data; pure values).
- A `match(bv, *, binary, arch, platform, detector) -> list[Finding]`
  function that scans a Binja BinaryView and emits Finding objects for
  matched patterns.

Pattern data is encodable, deterministic, and citable. The `match()`
algorithms are where structural cleverness lives — but they consume
the pattern table; they don't bake patterns inline.

Conventions:

- Pattern `name` is dotted: `<class>.<variant>`, e.g.
  `direct_syscall_stub.hells_gate`.
- Pattern `category` is the `Finding.category` emitted on match.
  Use snake_case to match the unified category vocabulary.
- `negative_context` is a free-form dict; callers (and analysis
  modules) interpret keys to suppress FPs. Common keys:
  - `function_name_prefix`: skip if surrounding function name starts
    with this (e.g., `__scrt_` for VC++ runtime).
  - `module_name`: skip if the match is inside this module's image
    (e.g., `ntdll.dll` for syscalls — they're legitimate there).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from ..output.finding import Evidence, Finding, Severity


# ─────────────────────────────────────────────────────────────────
# Pattern shapes
# ─────────────────────────────────────────────────────────────────


@dataclass
class Pattern:
    """Base — fields every heuristic carries."""

    name: str
    description: str
    severity: Severity
    category: str
    cwe: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    knowledge_refs: list[str] = field(default_factory=list)
    negative_context: dict[str, Any] = field(default_factory=dict)
    notes: str = ""                      # operator-facing context


@dataclass
class ImportPattern(Pattern):
    """Match by import-table presence.

    `import_names`: function names whose presence constitutes the signal.
    `all_required`: True → all names must be imported (combo signal,
                    e.g., the process-injection trio);
                    False → any one is enough (banned-function list).
    """

    import_names: list[str] = field(default_factory=list)
    all_required: bool = False


@dataclass
class StringPattern(Pattern):
    """Match by literal string presence in the binary."""

    string_literals: list[str] = field(default_factory=list)
    case_sensitive: bool = True


@dataclass
class ConstantPattern(Pattern):
    """Match by integer constant in `.text` (or named sections).

    `constants`: integer values to search for as little-endian.
    `bit_widths`: which widths to encode (32, 64).
    `require_in_section`: only emit if found inside one of these
                          section names; empty = anywhere.
    """

    constants: list[int] = field(default_factory=list)
    bit_widths: list[int] = field(default_factory=lambda: [32])
    require_in_section: list[str] = field(default_factory=list)


@dataclass
class BytePattern(Pattern):
    """Match by exact byte sequence (e.g., NTDLL syscall-stub prologue)."""

    byte_sequences: list[bytes] = field(default_factory=list)
    require_in_section: list[str] = field(default_factory=list)


@dataclass
class StructuralPattern(Pattern):
    """Match by IL / call-graph shape.

    The pattern carries metadata only; the analysis module that
    consumes it implements the actual recognition algorithm. Keys in
    `shape` are convention by detector — see the consumer module's
    docstring.
    """

    shape: dict[str, Any] = field(default_factory=dict)


@dataclass
class ChainPattern(Pattern):
    """Multi-primitive composition.

    `primitives` is an ordered list of primitive Pattern.name values
    (or category names) that must all be detected in the same binary,
    optionally with ordering constraints.

    Used by `analysis/chains.py` to compose Tier-1 findings into
    Tier-2 chain emissions.
    """

    primitives: list[str] = field(default_factory=list)
    ordered: bool = True
    same_function: bool = False


# ─────────────────────────────────────────────────────────────────
# bv-introspection helpers (tolerant of partial / mock bv objects)
# ─────────────────────────────────────────────────────────────────


def imports_in(bv) -> set[str]:
    """Return the set of imported symbol names."""
    out: set[str] = set()
    if bv is None:
        return out
    # Try Binja's typed accessor first.
    get_typed = getattr(bv, "get_symbols_of_type", None)
    if callable(get_typed):
        try:
            # Avoid a hard import on binaryninja.SymbolType — pass the string.
            for sym in get_typed("ImportedFunctionSymbol"):
                name = getattr(sym, "short_name", None) or getattr(sym, "name", None)
                if name:
                    out.add(str(name))
            if out:
                return out
        except Exception:
            pass
    # Fallback: iterate all symbols and filter.
    syms = getattr(bv, "symbols", None) or []
    try:
        for sym in syms:
            type_name = str(getattr(sym, "type", ""))
            if "Imported" in type_name and ("Function" in type_name or "External" in type_name):
                name = getattr(sym, "short_name", None) or getattr(sym, "name", None)
                if name:
                    out.add(str(name))
    except Exception:
        pass
    return out


def strings_in(bv, min_length: int = 4) -> list[tuple[str, int]]:
    """Return [(string, address), ...] for strings ≥ min_length."""
    out: list[tuple[str, int]] = []
    if bv is None:
        return out
    for s in getattr(bv, "strings", []) or []:
        if getattr(s, "length", 0) < min_length:
            continue
        value = getattr(s, "value", None) or str(s)
        addr = getattr(s, "start", 0)
        out.append((str(value), int(addr)))
    return out


def find_byte_pattern(bv, pattern_bytes: bytes, start: int = 0) -> list[int]:
    """Return all addresses where `pattern_bytes` occur.

    Uses `bv.find_next_data(addr, bytes)`; iterates until exhausted.
    """
    out: list[int] = []
    if bv is None:
        return out
    finder = getattr(bv, "find_next_data", None)
    if not callable(finder):
        return out
    addr = start
    seen: set[int] = set()
    while True:
        try:
            found = finder(addr, pattern_bytes)
        except Exception:
            break
        if found is None or found == -1 or found in seen:
            break
        seen.add(found)
        out.append(int(found))
        addr = int(found) + 1
    return out


def find_constant(bv, value: int, bit_width: int = 32, start: int = 0) -> list[int]:
    """Find addresses where `value` appears as a little-endian
    `bit_width`-bit integer."""
    if bit_width == 32:
        encoded = struct.pack("<I", value & 0xFFFFFFFF)
    elif bit_width == 64:
        encoded = struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)
    elif bit_width == 16:
        encoded = struct.pack("<H", value & 0xFFFF)
    elif bit_width == 8:
        encoded = struct.pack("<B", value & 0xFF)
    else:
        raise ValueError(f"unsupported bit_width: {bit_width}")
    return find_byte_pattern(bv, encoded, start)


def section_at(bv, address: int) -> Optional[str]:
    """Return the name of the section containing `address`, or None."""
    if bv is None:
        return None
    getter = getattr(bv, "get_sections_at", None)
    if callable(getter):
        try:
            secs = getter(address)
            for s in secs:
                name = getattr(s, "name", None)
                if name:
                    return str(name)
        except Exception:
            pass
    return None


def function_at(bv, address: int):
    """Return a Function object containing `address`, or None.
    Defensive against missing bv methods."""
    if bv is None:
        return None
    getter = getattr(bv, "get_functions_containing", None)
    if callable(getter):
        try:
            funcs = list(getter(address))
            return funcs[0] if funcs else None
        except Exception:
            return None
    getter = getattr(bv, "get_function_at", None)
    if callable(getter):
        try:
            return getter(address)
        except Exception:
            return None
    return None


# ─────────────────────────────────────────────────────────────────
# Negative-context filter
# ─────────────────────────────────────────────────────────────────


def passes_negative_context(pattern: Pattern, *, function_name: str = "",
                            module_name: str = "", section_name: str = "") -> bool:
    """Return True if the match should fire (negative context not hit)."""
    nc = pattern.negative_context
    if not nc:
        return True
    prefix = nc.get("function_name_prefix")
    if prefix and function_name.startswith(prefix):
        return False
    prefixes = nc.get("function_name_prefix_any") or []
    if any(function_name.startswith(p) for p in prefixes):
        return False
    excluded_module = nc.get("module_name")
    if excluded_module and module_name == excluded_module:
        return False
    excluded_section = nc.get("section_name")
    if excluded_section and section_name == excluded_section:
        return False
    return True


# ─────────────────────────────────────────────────────────────────
# Finding constructor
# ─────────────────────────────────────────────────────────────────


def emit_finding(
    pattern: Pattern,
    *,
    address: int,
    function: str,
    binary: str,
    arch: str,
    platform: str,
    detector: str,
    evidence: Optional[list[Evidence]] = None,
    description_extra: str = "",
    details: Optional[dict[str, Any]] = None,
) -> Finding:
    """Construct a Finding from a Pattern + match site."""
    desc = pattern.description
    if description_extra:
        desc = f"{desc} — {description_extra}"
    return Finding(
        id="",
        category=pattern.category,
        severity=pattern.severity,
        address=address,
        function=function,
        binary=binary,
        arch=arch,
        platform=platform,
        detector=detector,
        knowledge_refs=list(pattern.knowledge_refs),
        cwe=list(pattern.cwe),
        mitre_attack=list(pattern.mitre_attack),
        evidence=list(evidence or []),
        description=desc,
        details=dict(details or {}),
    )
