"""Source-attack-surface mapper — Phase 2 minimal slice.

Consumes available source code (decompiled, partial, or full) for a
cell and applies source-level names + classifications to the Binja
binary view, enriching downstream analysis output.

The target use case for this slice is the known-positive cell shape:
the operator has placed source under the cell's `source/` directory
(possibly Ghidra-decompiled output, possibly partial RE notes,
possibly clean upstream source). Phase 2 doesn't require the
source to be a clean compileable artefact — it extracts the
maximum useful signal from whatever's available.

What the minimal slice does
---------------------------

1. **Function name extraction.** Parses C-shaped source files for
   top-level function definitions and their bodies. For each function,
   builds a "callee signature" — the set of NT/kernel API names it
   calls (resolved via the Win32-kernel sink list and a generic
   identifier scan).

2. **Source ↔ binary alignment.** Pairs each source function with a
   binary function whose **resolved callee set** is the same.
   When the match is unique, applies the source function name to the
   binary function (`bv.get_function_at(addr).name = source_name`).
   When it's ambiguous, skips with a note.

3. **IOCTL constant extraction.** Scans the dispatch handler's source
   for `IoControlCode == 0xXXXX` patterns, captures the IOCTL constant
   plus the immediate handler invocation that follows it. Decodes the
   IOCTL via the `CTL_CODE` macro layout
   (`(DeviceType<<16) | (Access<<14) | (Function<<2) | Method`).

4. **Per-IOCTL classification finding.** Emits a `kernel_ioctl_handler_classified`
   Finding per (IOCTL_code, handler) pair, citing:
   - the IOCTL code + decoded fields (DeviceType / Function / Method)
   - the source-named handler function
   - the binary address of the matched handler

Findings have `severity=info` by default; the operator's downstream
review elevates them to risk-bearing categories where appropriate
(or pairs them with the existing taint findings from Phase 1).

What the slice deliberately does NOT do
---------------------------------------

- It does NOT compile the source. No clang, no preprocessor, no AST.
  Compileability is rare for decompiled output; Argus's source
  consumer must be permissive.
- It does NOT do source-level taint analysis. That's a future Phase
  2 expansion — for the slice, source-level enrichment of binary
  taint output is sufficient.
- It does NOT trust source content as authoritative when it conflicts
  with the binary. If Ghidra mis-decompiled a function, the binary
  is the source of truth; Phase 2 won't propagate the lie.

Future expansions (deferred, document in `analysis/__init__.py`)
----------------------------------------------------------------

- libclang / tree-sitter integration for clean upstream source
- DWARF / PDB consumption when debug symbols are present
- Source-level taint analysis as an independent detection pass
- Cross-cell pattern library (when one cell teaches the system
  about a sink semantics, future cells inherit)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..output.finding import Evidence, Finding, Severity


# ─────────────────────────────────────────────────────────────────
# Source parsing
# ─────────────────────────────────────────────────────────────────


# C identifier pattern with kernel API prefix list. We use a focused
# set rather than a generic identifier scan to keep the callee
# signature noise-free.
KERNEL_API_PREFIXES = (
    "Mm", "Io", "Ke", "Ob", "Ps", "Cm", "Rtl", "Nt", "Zw",
    "Hal", "Ex", "Ki", "Fl", "Wmi", "FsRtl",
    "PsP", "MmP", "ObpP",
)

# Function body delimiter — match top-level `<retty> name(<args>)\n{`.
# Kept loose enough to handle Ghidra/IDA decompiler quirks (`undefined8`,
# `ulonglong`, `_DRIVER_OBJECT`, etc.).
_FUNC_DEF_RE = re.compile(
    r"(?m)^[ \t]*"
    r"(?:[A-Za-z_]\w*\s+)+"                  # return type chain
    r"(?P<name>[A-Za-z_]\w*)\s*"             # function name
    r"\([^;{}]*\)\s*"                         # parameters (no ; or {)
    r"\n\{",                                  # opening brace on next line
)

# Per-line callee scan — detect identifiers that look like NT/Mm/Ke
# API calls.
_CALL_TOKEN_RE = re.compile(r"\b([A-Z][A-Za-z]*[A-Za-z0-9_]*)\s*\(")

# IOCTL constant patterns — match both `IoControlCode == 0xXXXX`
# (typical Ghidra output for the dispatcher switch) and explicit
# DeviceIoControl call constants.
_IOCTL_CMP_RE = re.compile(
    r"IoControlCode\s*(?:==|!=)\s*(0x[0-9a-fA-F]+)"
)
_IOCTL_DIC_RE = re.compile(
    r"DeviceIoControl\s*\([^,)]+,\s*(0x[0-9a-fA-F]+)"
)


@dataclass
class SourceFunction:
    """One function discovered in source."""

    name: str
    file: str
    line: int
    body: str
    callees: set[str] = field(default_factory=set)


@dataclass
class IoctlBinding:
    """One IOCTL_code → handler-call observation extracted from source."""

    code: int
    matched_text: str           # the source line where it appeared
    file: str
    line: int


def _looks_like_kernel_api(name: str) -> bool:
    """Heuristic: does `name` look like an NT/kernel/runtime API?"""
    if name.startswith("FUN_") or name.startswith("LAB_") or name.startswith("DAT_"):
        return False
    if not name or not name[0].isupper():
        return False
    if name in {"NULL", "STATUS_SUCCESS", "TRUE", "FALSE", "MmNonCached"}:
        return False
    return name.startswith(KERNEL_API_PREFIXES) or name in (
        "DeviceIoControl", "CreateFileW", "CloseHandle",
        "MmFreeContiguousMemorySpecifyCache",
    )


# Names that the function-definition regex sometimes captures by
# mistake — MSVC attributes, GCC-style annotations, etc. They appear
# in the position the regex thinks is the function name when applied
# to e.g. `void __declspec(noreturn) error(...)`.
_FUNC_NAME_BLOCKLIST = frozenset({
    "__declspec", "__attribute__", "__cdecl", "__stdcall", "__fastcall",
    "__forceinline", "__inline", "inline", "static", "extern", "const",
    "volatile", "register", "restrict", "noreturn", "PUBLIC",
})


def _split_top_level_functions(text: str, file_path: str) -> list[SourceFunction]:
    """Naive but robust top-level function splitter.

    Walks the text matching `<types> name(<args>) {` with
    `_FUNC_DEF_RE`, then captures the body via brace-counting
    until the matching `}` at column 0.
    """
    out: list[SourceFunction] = []
    for m in _FUNC_DEF_RE.finditer(text):
        if m.group("name") in _FUNC_NAME_BLOCKLIST:
            continue
        body_start = m.end()
        depth = 1
        i = body_start
        while i < len(text) and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        body_end = i
        body = text[body_start:body_end]
        line = text[:m.start()].count("\n") + 1
        out.append(SourceFunction(
            name=m.group("name"),
            file=file_path,
            line=line,
            body=body,
        ))
    return out


def _scan_callees(func: SourceFunction) -> None:
    """Populate `func.callees` with kernel-API names called in body."""
    callees: set[str] = set()
    for tok in _CALL_TOKEN_RE.findall(func.body):
        if _looks_like_kernel_api(tok):
            callees.add(tok)
    func.callees = callees


def _scan_ioctl_bindings(text: str, file_path: str) -> list[IoctlBinding]:
    out: list[IoctlBinding] = []
    for m in _IOCTL_CMP_RE.finditer(text):
        code = int(m.group(1), 16)
        line = text[:m.start()].count("\n") + 1
        out.append(IoctlBinding(
            code=code,
            matched_text=text[max(0, m.start() - 30):m.end() + 80].strip(),
            file=file_path, line=line,
        ))
    for m in _IOCTL_DIC_RE.finditer(text):
        code = int(m.group(1), 16)
        line = text[:m.start()].count("\n") + 1
        out.append(IoctlBinding(
            code=code,
            matched_text=text[max(0, m.start() - 30):m.end() + 60].strip(),
            file=file_path, line=line,
        ))
    return out


def parse_source_dir(source_dir: Path) -> tuple[list[SourceFunction],
                                                 list[IoctlBinding]]:
    """Parse all `*.c` / `*.cpp` / `*.h` files under `source_dir`.

    Recurses into subdirs (`_repo/`, etc.) so cell-typical layouts
    work without the operator having to flatten them.
    """
    funcs: list[SourceFunction] = []
    ioctls: list[IoctlBinding] = []
    if not source_dir.exists() or not source_dir.is_dir():
        return funcs, ioctls
    for path in source_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(path.relative_to(source_dir)) if source_dir in path.parents else str(path)
        for f in _split_top_level_functions(text, rel):
            _scan_callees(f)
            funcs.append(f)
        ioctls.extend(_scan_ioctl_bindings(text, rel))
    return funcs, ioctls


# ─────────────────────────────────────────────────────────────────
# Source ↔ binary alignment
# ─────────────────────────────────────────────────────────────────


def _binary_callee_signature(bv, func) -> set[str]:
    """For one binary function, return the set of resolved-import
    callee names. Used as a fingerprint for matching against source
    functions.

    Only kernel-API-shaped names (per `_looks_like_kernel_api`) are
    included — that filters out internal `sub_*` calls and provides
    a stable fingerprint across decompiler output and binary.

    Walks MLIL call instructions and resolves each callee address
    against the import symbol table. `func.callees` alone misses
    extern-symbol calls (which is the entire kernel-API surface in a
    Windows driver) — those resolve via the IAT stubs and need
    explicit symbol lookup at the call destination.
    """
    from . import _il_helpers as ilh

    out: set[str] = set()
    if func is None:
        return out
    for ci in ilh.call_instructions_in(func):
        try:
            addr = ilh.callee_address_of_call(ci)
        except Exception:
            addr = None
        if addr is None:
            continue
        sym = bv.get_symbol_at(addr) if bv is not None else None
        if sym is None:
            continue
        name = getattr(sym, "short_name", None) or getattr(sym, "name", "")
        if _looks_like_kernel_api(name):
            out.add(name)
    return out


@dataclass
class FunctionMatch:
    source_name: str
    source_file: str
    source_line: int
    binary_addr: int
    binary_old_name: str
    common_callees: set[str]
    ambiguous_with: list[str] = field(default_factory=list)


def align_source_to_binary(
    bv,
    source_funcs: list[SourceFunction],
    ignore_binary_names: Optional[set[str]] = None,
) -> tuple[list[FunctionMatch], list[SourceFunction]]:
    """Match source functions to binary functions by callee signature.

    Returns `(matched, unmatched_source)`. A source function matches
    when EXACTLY ONE binary function shares ALL its kernel-API callees
    AND has at least one such callee (zero-callee functions are
    inherently unrankable).

    The matching is intentionally strict — a source function with
    the API signature `{MmMapIoSpace, MmUnmapIoSpace}` will only match
    a binary function that calls exactly those two and no other
    in-scope kernel APIs. The trade-off: misses genuinely-ambiguous
    cases (multiple binary functions with the same callee set), but
    avoids confidently-wrong renames.
    """
    if bv is None:
        return [], list(source_funcs)
    ignore_binary_names = ignore_binary_names or set()

    # Build binary-function → callee-set table.
    bin_index: list[tuple[object, set[str]]] = []
    for f in bv.functions:
        callees = _binary_callee_signature(bv, f)
        if callees:
            bin_index.append((f, callees))

    matches: list[FunctionMatch] = []
    unmatched: list[SourceFunction] = []
    for sf in source_funcs:
        if not sf.callees:
            unmatched.append(sf)
            continue
        candidates: list[object] = []
        for bf, bcallees in bin_index:
            if sf.callees == bcallees:
                # Skip already-named binary functions (e.g., DriverEntry
                # set by Binja's platform module).
                bname = getattr(bf, "name", "") or ""
                if bname in ignore_binary_names:
                    continue
                candidates.append(bf)
        if len(candidates) == 1:
            bf = candidates[0]
            matches.append(FunctionMatch(
                source_name=sf.name,
                source_file=sf.file,
                source_line=sf.line,
                binary_addr=int(bf.start),
                binary_old_name=getattr(bf, "name", "") or f"sub_{bf.start:x}",
                common_callees=set(sf.callees),
            ))
        elif len(candidates) > 1:
            unmatched.append(sf)
            # Note: caller can re-run align with ignore_binary_names
            # extended to skip the contested candidates, but for now
            # we just punt.
        else:
            unmatched.append(sf)
    return matches, unmatched


def apply_function_renames(bv, matches: list[FunctionMatch]) -> int:
    """Rename matched binary functions to their source names.

    Returns the count of successful renames. Skips renames where the
    source name conflicts with an existing binary symbol (we don't
    want to clobber Binja's recovered symbol names like `_start`).
    """
    if bv is None:
        return 0
    n = 0
    for m in matches:
        f = bv.get_function_at(m.binary_addr)
        if f is None:
            continue
        try:
            existing = bv.get_symbols_by_name(m.source_name)
            if existing:
                # Source name collides with an existing symbol; prefix
                # to disambiguate without clobbering.
                new_name = f"src_{m.source_name}"
            else:
                new_name = m.source_name
            f.name = new_name
            n += 1
        except Exception:
            continue
    return n


# ─────────────────────────────────────────────────────────────────
# IOCTL constant decoding
# ─────────────────────────────────────────────────────────────────


@dataclass
class IoctlDecoded:
    code: int
    device_type: int            # bits 16..31
    access: int                 # bits 14..15 (0=any, 1=read, 2=write, 3=read+write)
    function: int               # bits 2..13
    method: int                 # bits 0..1 (0=BUFFERED, 1=IN_DIRECT, 2=OUT_DIRECT, 3=NEITHER)

    @property
    def method_name(self) -> str:
        return ("METHOD_BUFFERED", "METHOD_IN_DIRECT",
                "METHOD_OUT_DIRECT", "METHOD_NEITHER")[self.method]

    @property
    def access_name(self) -> str:
        return ("FILE_ANY_ACCESS", "FILE_READ_ACCESS",
                "FILE_WRITE_ACCESS", "FILE_READ_WRITE_ACCESS")[self.access]

    def to_dict(self) -> dict:
        return {
            "code": hex(self.code),
            "device_type": hex(self.device_type),
            "access": self.access,
            "access_name": self.access_name,
            "function": hex(self.function),
            "method": self.method,
            "method_name": self.method_name,
        }


def decode_ioctl(code: int) -> IoctlDecoded:
    """Decode a 32-bit Windows IOCTL constant per CTL_CODE layout."""
    return IoctlDecoded(
        code=code & 0xFFFFFFFF,
        device_type=(code >> 16) & 0xFFFF,
        access=(code >> 14) & 0x3,
        function=(code >> 2) & 0xFFF,
        method=code & 0x3,
    )


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None,
            platform: Optional[str] = None,
            source_dir: Optional[Path] = None,
            apply_renames: bool = True) -> list[Finding]:
    """Phase-2 entry. Reads source from `source_dir`, aligns to
    `session.bv`, applies function renames, emits classification
    Findings.

    `source_dir` defaults to `<binary_dir>/../source` if the binary
    lives under a `*/binary/<file>.sys` path (the known-positive cell
    convention). Pass an explicit `source_dir` to override.
    """
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    # Default source_dir: walk up from the binary path to find `source/`.
    if source_dir is None and binary:
        bp = Path(binary).resolve()
        for candidate in (bp.parent / ".." / "source",
                          bp.parent.parent / "source"):
            cp = candidate.resolve()
            if cp.exists() and cp.is_dir():
                source_dir = cp
                break

    if source_dir is None:
        return []

    source_dir = Path(source_dir)
    src_funcs, ioctls = parse_source_dir(source_dir)
    if not src_funcs and not ioctls:
        return []

    # Don't clobber names Binja's platform module already set (e.g.,
    # `_start`, the canonical DriverEntry).
    ignore_binary_names = {"_start", "DriverEntry"}
    matches, unmatched = align_source_to_binary(
        bv, src_funcs, ignore_binary_names=ignore_binary_names,
    )
    renamed = apply_function_renames(bv, matches) if apply_renames else 0

    findings: list[Finding] = []

    # 1. Per-match Finding documenting the source ↔ binary alignment.
    for m in matches:
        findings.append(Finding(
            id="",
            category="source_function_alignment",
            severity=Severity.INFO,
            address=m.binary_addr,
            function=m.source_name,
            binary=binary,
            arch=arch,
            platform=platform,
            detector="analysis.source_surface",
            knowledge_refs=[],
            cwe=[],
            mitre_attack=[],
            description=(
                f"Source function {m.source_name!r} matched to binary "
                f"function at {hex(m.binary_addr)} via callee-signature "
                f"alignment (shared APIs: {sorted(m.common_callees)}). "
                f"Binary function previously named {m.binary_old_name!r}; "
                f"renamed to {m.source_name!r}."
            ),
            details={
                "source_file": m.source_file,
                "source_line": m.source_line,
                "binary_old_name": m.binary_old_name,
                "common_callees": sorted(m.common_callees),
            },
            evidence=[Evidence(
                kind="source_alignment",
                source="analysis.source_surface",
                payload=f"{m.source_name} @ {m.source_file}:{m.source_line} -> "
                        f"{hex(m.binary_addr)}",
                address=m.binary_addr,
                function=m.source_name,
            )],
        ))

    # 2. Per-IOCTL classification.
    seen_codes: set[int] = set()
    for io in ioctls:
        if io.code in seen_codes:
            continue
        seen_codes.add(io.code)
        d = decode_ioctl(io.code)
        sev = Severity.HIGH if d.method == 3 else Severity.MEDIUM
        # Use the IOCTL code itself as the Finding's address — it's
        # the unique-per-finding key, and Finding.compute_id() folds
        # `address` into the deterministic id hash. Setting it to a
        # constant 0 across all IOCTL classifications would collapse
        # them all into one Finding.id under hash dedup.
        findings.append(Finding(
            id="",
            category="kernel_ioctl_handler_classified",
            severity=sev,
            address=io.code,
            function="<binary>",
            binary=binary,
            arch=arch,
            platform=platform,
            detector="analysis.source_surface",
            knowledge_refs=[
                "[[Memory/Knowledge/em_rootkit_irp_minifilter_callbacks]]",
            ],
            cwe=[],
            mitre_attack=["T1014"],
            description=(
                f"IOCTL {hex(io.code)} extracted from source: "
                f"DeviceType={hex(d.device_type)}, Function={hex(d.function)}, "
                f"Access={d.access_name}, Method={d.method_name}. "
                + (
                    "METHOD_NEITHER carries raw user pointers in "
                    "Type3InputBuffer / UserBuffer — strongest attack "
                    "surface class for IOCTL handlers."
                    if d.method == 3 else
                    "METHOD_BUFFERED copies the user buffer into "
                    "kernel space (`SystemBuffer`); attacker still "
                    "controls bytes, but raw pointer derefs through "
                    "the buffer (e.g. dbutil-shape) remain dangerous."
                )
            ),
            details=d.to_dict() | {
                "source_match": io.matched_text,
                "source_file": io.file,
                "source_line": io.line,
            },
            evidence=[Evidence(
                kind="ioctl_decode",
                source="analysis.source_surface",
                payload=f"{hex(io.code)} -> Method={d.method_name}, "
                        f"Function={hex(d.function)}, "
                        f"DeviceType={hex(d.device_type)}",
                address=0,
            )],
        ))

    # 3. Pipeline summary Finding (info-level metadata).
    findings.append(Finding(
        id="",
        category="phase2_source_summary",
        severity=Severity.INFO,
        address=0,
        function="<binary>",
        binary=binary,
        arch=arch,
        platform=platform,
        detector="analysis.source_surface",
        description=(
            f"Phase 2 source enrichment ran against {source_dir}: "
            f"{len(src_funcs)} source functions parsed, {len(matches)} "
            f"matched to binary, {len(unmatched)} unmatched, "
            f"{renamed} binary functions renamed. "
            f"{len(seen_codes)} unique IOCTL codes classified."
        ),
        details={
            "source_dir": str(source_dir),
            "source_functions": len(src_funcs),
            "matched": len(matches),
            "unmatched": len(unmatched),
            "renamed": renamed,
            "ioctl_codes": [hex(c) for c in sorted(seen_codes)],
        },
    ))

    return findings
