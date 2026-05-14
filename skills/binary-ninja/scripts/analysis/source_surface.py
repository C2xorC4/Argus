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
   for IOCTL constants via three complementary patterns:
   (a) `IoControlCode == 0xXXXX` or `IoControlCode == <decimal>` comparisons;
   (b) `switch(IoControlCode) { case 0x.../decimal: ... }` dispatch blocks;
   (c) `CTL_CODE(DeviceType, Function, Method, Access)` macro invocations
   in header/source files — computes the final IOCTL code from components.
   Decodes each found code via the `CTL_CODE` macro layout
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
    r"IoControlCode\s*(?:==|!=)\s*(0x[0-9a-fA-F]+|-?\d+)"
)
_IOCTL_DIC_RE = re.compile(
    r"DeviceIoControl\s*\([^,)]+,\s*(0x[0-9a-fA-F]+|-?\d+)"
)

# switch(IoControlCode) { case X: } dispatch blocks.
_IOCTL_SWITCH_VAR_PAT = (
    r"IoControlCode|ioControlCode|dwIoControlCode|IoctlCode|ioctlCode"
    r"|dwCtlCode|IoCtrl|ioCtrl|ulIoControlCode"
)
_IOCTL_SWITCH_RE = re.compile(
    r"\bswitch\s*\(\s*(?:\w+[\.\->]+)*(?:" + _IOCTL_SWITCH_VAR_PAT + r")\s*\)"
)
_IOCTL_CASE_RE = re.compile(r"\bcase\s+(0x[0-9a-fA-F]+|-?\d+)\s*:")

# CTL_CODE(...) macro invocations in header / source files.
_CTL_CODE_RE = re.compile(
    r"\bCTL_CODE\s*\(\s*"
    r"(0x[0-9a-fA-F]+|\d+|FILE_DEVICE_\w+)\s*,\s*"
    r"(0x[0-9a-fA-F]+|\d+)\s*,\s*"
    r"(METHOD_\w+|\d+)\s*,\s*"
    r"(FILE_\w+|\d+)"
    r"\s*\)"
)
_CTL_CODE_METHOD_VALS: dict[str, int] = {
    "METHOD_BUFFERED": 0, "METHOD_IN_DIRECT": 1,
    "METHOD_OUT_DIRECT": 2, "METHOD_NEITHER": 3,
}
_CTL_CODE_ACCESS_VALS: dict[str, int] = {
    "FILE_ANY_ACCESS": 0, "FILE_SPECIAL_ACCESS": 0,
    "FILE_READ_ACCESS": 1, "FILE_WRITE_ACCESS": 2,
    "FILE_READ_WRITE_ACCESS": 3,
}
_CTL_CODE_DEVICE_VALS: dict[str, int] = {
    "FILE_DEVICE_UNKNOWN": 0x22, "FILE_DEVICE_DISK": 0x07,
    "FILE_DEVICE_KEYBOARD": 0x0B, "FILE_DEVICE_MOUSE": 0x0F,
    "FILE_DEVICE_NULL": 0x15, "FILE_DEVICE_VIRTUAL_DISK": 0x24,
    "FILE_DEVICE_KSEC": 0x39, "FILE_DEVICE_FIPS": 0x3A,
    "FILE_DEVICE_NETWORK": 0x12, "FILE_DEVICE_VIDEO": 0x23,
    "FILE_DEVICE_BATTERY": 0x29, "FILE_DEVICE_SMARTCARD": 0x31,
    "FILE_DEVICE_BEEP": 0x01, "FILE_DEVICE_CD_ROM": 0x02,
    "FILE_DEVICE_CONTROLLER": 0x04, "FILE_DEVICE_DFS": 0x06,
    "FILE_DEVICE_DISK_FILE_SYSTEM": 0x08, "FILE_DEVICE_FILE_SYSTEM": 0x09,
    "FILE_DEVICE_NAMED_PIPE": 0x11, "FILE_DEVICE_MASS_STORAGE": 0x2D,
    "FILE_DEVICE_KS": 0x2F, "FILE_DEVICE_ACPI": 0x32,
    "FILE_DEVICE_SERENUM": 0x37, "FILE_DEVICE_TERMSRV": 0x38,
}

# ─────────────────────────────────────────────────────────────────
# Python PoC patterns (2.3 — K7-style standalone-PoC parsing)
# ─────────────────────────────────────────────────────────────────

# Uppercase constant assignment: IOCTL_FOO = 0x..., SOME_CODE = decimal.
_PY_CONST_RE = re.compile(
    r"^([A-Z][A-Z0-9_]{2,})\s*=\s*(0x[0-9a-fA-F]+|-?\d+)",
    re.MULTILINE,
)

# DeviceIoControl call — second arg is the IOCTL code; optional ctypes.c_* wrapper.
_PY_DIC_RE = re.compile(
    r"DeviceIoControl\s*\([^,)]+,\s*(?:ctypes\.\w+\s*\(\s*)?(0x[0-9a-fA-F]+|-?\d+)"
)

# Win32 device path string in Python source (raw literal and escaped literal).
_PY_DEVICE_PATH_RE = re.compile(
    r"""r['"]\\{2}\.\\([A-Za-z0-9_]+)"""
    r"""|"""
    r"""['"]\\{4}\.\\{2}([A-Za-z0-9_]+)"""
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


# ─────────────────────────────────────────────────────────────────
# UE5-aware source patterns (Plan D — Run 19)
# ─────────────────────────────────────────────────────────────────


# `>` cap check that should be `>=` — the canonical FString
# off-by-one. Heuristic: `SaveNum > MaxSerializeSize` (or any
# `<numericName> > <CapitalSerializeName>`) is suspicious.
_UE5_OFFBYONE_CAP_RE = re.compile(
    r"\bif\s*\(\s*([A-Z]\w*)\s*>\s*([A-Z]\w*(?:Size|Length|Limit|Cap|Max\w*))\s*\)"
)

# `Empty(N); ... AddUninitialized(N); ... <Read|Serialize|FromBytes>(...)` —
# allocate-before-read CFG shape at source level. The reads happen
# before the buffer's contents are validated.
_UE5_ALLOC_BEFORE_READ_RE = re.compile(
    r"\.Empty\s*\(\s*([^)]{1,80}?)\s*\)\s*;\s*"
    r"[^;]*?\.AddUninitialized\s*\(\s*\1\s*\)\s*;",
    re.DOTALL,
)

# `FMath::Rand() % N` — UE5 PRNG-mod-N. When N appears in a security
# context (handshake, secret, cookie, key, token), the entropy is
# limited to `log2(N)` bits.
_UE5_RAND_MOD_RE = re.compile(
    r"\bFMath::Rand\s*\(\s*\)\s*%\s*(\d+|\w+)"
)


# UE5 source pattern findings — info-grade by default; operators
# pair with binary-side detection for high-confidence verdicts.
UE5_SOURCE_FINDING_META = {
    "ue5_offbyone_cap_check": {
        "severity": Severity.MEDIUM,
        "category": "ue5_offbyone_cap_check",
        "cwe": ["CWE-193", "CWE-787"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ue5_fstring_allocation_amplification]]",
        ],
    },
    "ue5_allocate_before_read": {
        "severity": Severity.HIGH,
        "category": "ue5_allocate_before_read",
        "cwe": ["CWE-457", "CWE-908"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ue5_fstring_allocation_amplification]]",
            "[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]",
        ],
    },
    "ue5_rand_mod_in_security_path": {
        "severity": Severity.HIGH,
        "category": "ue5_rand_mod_in_security_path",
        "cwe": ["CWE-338", "CWE-330"],
        "knowledge_refs": [
            "[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]",
        ],
    },
}


def _scan_ue5_source_patterns(text: str, file_path: str
                              ) -> list[tuple[str, int, str]]:
    """Return [(category, line_number, snippet), ...] for UE5 patterns
    matched in `text`.

    Categories: `ue5_offbyone_cap_check`, `ue5_allocate_before_read`,
    `ue5_rand_mod_in_security_path`.
    """
    out: list[tuple[str, int, str]] = []
    for m in _UE5_OFFBYONE_CAP_RE.finditer(text):
        line = text[:m.start()].count("\n") + 1
        snippet = text[max(0, m.start() - 20):m.end() + 30].strip()
        out.append(("ue5_offbyone_cap_check", line, snippet))
    for m in _UE5_ALLOC_BEFORE_READ_RE.finditer(text):
        line = text[:m.start()].count("\n") + 1
        snippet = text[max(0, m.start() - 20):m.end() + 30].strip()
        out.append(("ue5_allocate_before_read", line, snippet))
    # Rand-mod-N: only flag when N appears near a security keyword
    # in the surrounding 200 chars.
    security_keywords = ("Handshake", "Secret", "Cookie", "Token",
                         "Key", "Nonce", "AuthCode", "ChallengeBytes",
                         "Cipher", "Crypto", "HMAC")
    for m in _UE5_RAND_MOD_RE.finditer(text):
        ctx_start = max(0, m.start() - 200)
        ctx_end = min(len(text), m.end() + 100)
        context = text[ctx_start:ctx_end]
        if not any(kw in context for kw in security_keywords):
            continue
        line = text[:m.start()].count("\n") + 1
        snippet = text[max(0, m.start() - 30):m.end() + 30].strip()
        out.append(("ue5_rand_mod_in_security_path", line, snippet))
    return out


def _parse_ioctl_int(raw: str) -> int:
    r = raw.strip()
    if r.startswith(("0x", "0X")):
        return int(r, 16)
    return int(r)


def _looks_like_ioctl_constant(code: int) -> bool:
    """True when the masked-32-bit code has a non-zero device_type field."""
    return bool((code & 0xFFFF0000) and (code & 0xFFFFFFFF))


def _scan_ioctl_switch_cases(text: str, file_path: str) -> list[IoctlBinding]:
    """Extract IOCTL codes from switch(IoControlCode) { case X: } blocks."""
    out: list[IoctlBinding] = []
    for m in _IOCTL_SWITCH_RE.finditer(text):
        brace_pos = text.find("{", m.end())
        if brace_pos == -1:
            continue
        depth = 1
        i = brace_pos + 1
        while i < len(text) and depth > 0:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        switch_body = text[brace_pos + 1 : i - 1]
        body_offset = brace_pos + 1
        for cm in _IOCTL_CASE_RE.finditer(switch_body):
            try:
                code = _parse_ioctl_int(cm.group(1)) & 0xFFFFFFFF
            except (ValueError, OverflowError):
                continue
            if not _looks_like_ioctl_constant(code):
                continue
            abs_pos = body_offset + cm.start()
            line = text[:abs_pos].count("\n") + 1
            ctx = text[max(0, abs_pos - 20):abs_pos + 60].strip()
            out.append(IoctlBinding(code=code, matched_text=ctx,
                                    file=file_path, line=line))
    return out


def _scan_ctl_code_macros(text: str, file_path: str) -> list[IoctlBinding]:
    """Extract IOCTL codes from CTL_CODE(dev, fn, method, access) macros."""
    out: list[IoctlBinding] = []
    for m in _CTL_CODE_RE.finditer(text):
        dev_raw, fn_raw, meth_raw, acc_raw = (m.group(i) for i in range(1, 5))
        try:
            dev = (
                _CTL_CODE_DEVICE_VALS.get(dev_raw)
                if dev_raw.startswith("FILE_")
                else _parse_ioctl_int(dev_raw)
            )
            if dev is None:
                continue
            fn = _parse_ioctl_int(fn_raw)
            meth = (
                _CTL_CODE_METHOD_VALS.get(meth_raw)
                if meth_raw.startswith("METHOD_")
                else _parse_ioctl_int(meth_raw)
            )
            if meth is None:
                continue
            acc = (
                _CTL_CODE_ACCESS_VALS.get(acc_raw)
                if acc_raw.startswith("FILE_")
                else _parse_ioctl_int(acc_raw)
            )
            if acc is None:
                continue
        except (ValueError, KeyError):
            continue
        code = ((dev << 16) | (acc << 14) | (fn << 2) | meth) & 0xFFFFFFFF
        line = text[:m.start()].count("\n") + 1
        ctx = text[max(0, m.start() - 30):m.end() + 30].strip()
        out.append(IoctlBinding(code=code, matched_text=ctx,
                                file=file_path, line=line))
    return out


def _scan_ioctl_bindings(text: str, file_path: str) -> list[IoctlBinding]:
    out: list[IoctlBinding] = []
    for m in _IOCTL_CMP_RE.finditer(text):
        try:
            code = _parse_ioctl_int(m.group(1)) & 0xFFFFFFFF
        except (ValueError, OverflowError):
            continue
        line = text[:m.start()].count("\n") + 1
        out.append(IoctlBinding(
            code=code,
            matched_text=text[max(0, m.start() - 30):m.end() + 80].strip(),
            file=file_path, line=line,
        ))
    for m in _IOCTL_DIC_RE.finditer(text):
        try:
            code = _parse_ioctl_int(m.group(1)) & 0xFFFFFFFF
        except (ValueError, OverflowError):
            continue
        line = text[:m.start()].count("\n") + 1
        out.append(IoctlBinding(
            code=code,
            matched_text=text[max(0, m.start() - 30):m.end() + 60].strip(),
            file=file_path, line=line,
        ))
    out.extend(_scan_ioctl_switch_cases(text, file_path))
    out.extend(_scan_ctl_code_macros(text, file_path))
    return out


def _scan_py_poc_bindings(
    text: str, file_path: str
) -> tuple[list[IoctlBinding], list[str]]:
    """Extract IOCTL codes and Win32 device paths from a Python PoC file.

    Returns `(ioctls, device_names)`. IOCTL candidates are filtered
    through `_looks_like_ioctl_constant` to suppress small integers.
    """
    ioctls: list[IoctlBinding] = []
    devices: list[str] = []

    for m in _PY_DEVICE_PATH_RE.finditer(text):
        name = m.group(1) or m.group(2) or ""
        if name:
            devices.append(name)

    seen: set[int] = set()
    for m in _PY_CONST_RE.finditer(text):
        try:
            code = _parse_ioctl_int(m.group(2)) & 0xFFFFFFFF
        except (ValueError, OverflowError):
            continue
        if not _looks_like_ioctl_constant(code) or code in seen:
            continue
        seen.add(code)
        line = text[:m.start()].count("\n") + 1
        ioctls.append(IoctlBinding(code=code,
                                   matched_text=m.group(0).strip(),
                                   file=file_path, line=line))

    for m in _PY_DIC_RE.finditer(text):
        try:
            code = _parse_ioctl_int(m.group(1)) & 0xFFFFFFFF
        except (ValueError, OverflowError):
            continue
        if not _looks_like_ioctl_constant(code) or code in seen:
            continue
        seen.add(code)
        line = text[:m.start()].count("\n") + 1
        ctx = text[max(0, m.start() - 20):m.end() + 40].strip()
        ioctls.append(IoctlBinding(code=code, matched_text=ctx,
                                   file=file_path, line=line))

    return ioctls, devices


def parse_poc_files(
    source_dir: Path,
) -> tuple[list[IoctlBinding], list[str]]:
    """Scan Python PoC / exploit files under `source_dir` for IOCTL codes
    and Win32 device paths (K7-style standalone-PoC pattern).

    Returns `(ioctls, device_names)`. Only `*.py` files are consumed.
    """
    ioctls: list[IoctlBinding] = []
    devices: list[str] = []
    if not source_dir.exists() or not source_dir.is_dir():
        return ioctls, devices
    for path in source_dir.rglob("*.py"):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = (str(path.relative_to(source_dir))
               if source_dir in path.parents else str(path))
        py_ioctls, py_devs = _scan_py_poc_bindings(text, rel)
        ioctls.extend(py_ioctls)
        devices.extend(py_devs)
    return ioctls, list(dict.fromkeys(devices))


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


def parse_ue5_patterns(source_dir: Path) -> list[tuple[str, str, int, str]]:
    """Scan for UE5-specific source patterns (Plan D — Run 19).

    Returns [(category, file_rel_path, line_number, snippet), ...]
    for matches of: `ue5_offbyone_cap_check`, `ue5_allocate_before_read`,
    `ue5_rand_mod_in_security_path`.
    """
    out: list[tuple[str, str, int, str]] = []
    if not source_dir.exists() or not source_dir.is_dir():
        return out
    for path in source_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in (".c", ".cpp", ".cc", ".cxx",
                                        ".h", ".hpp", ".inl"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = str(path.relative_to(source_dir)) if source_dir in path.parents else str(path)
        for cat, line, snippet in _scan_ue5_source_patterns(text, rel):
            out.append((cat, rel, line, snippet))
    return out


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
    ue5_matches = parse_ue5_patterns(source_dir)
    poc_ioctls, poc_devices = parse_poc_files(source_dir)
    if not src_funcs and not ioctls and not ue5_matches and not poc_ioctls:
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

    # 3. PoC IOCTL findings — info-grade enrichment from standalone PoC files.
    poc_seen: set[int] = set()
    for io in poc_ioctls:
        if io.code in poc_seen:
            continue
        poc_seen.add(io.code)
        d = decode_ioctl(io.code)
        findings.append(Finding(
            id="",
            category="standalone_poc_ioctl",
            severity=Severity.INFO,
            address=io.code,
            function="<poc>",
            binary=binary,
            arch=arch,
            platform=platform,
            detector="analysis.source_surface.poc",
            knowledge_refs=[],
            cwe=[],
            mitre_attack=[],
            description=(
                f"IOCTL {hex(io.code)} extracted from standalone PoC "
                f"{io.file}:{io.line}: "
                f"DeviceType={hex(d.device_type)}, "
                f"Function={hex(d.function)}, "
                f"Access={d.access_name}, Method={d.method_name}."
                + (f" Driver target(s): {', '.join(poc_devices)}."
                   if poc_devices else "")
            ),
            details=d.to_dict() | {
                "source_match": io.matched_text,
                "source_file": io.file,
                "source_line": io.line,
                "poc_device_names": poc_devices,
            },
            evidence=[Evidence(
                kind="poc_ioctl",
                source="analysis.source_surface.poc",
                payload=f"{hex(io.code)} from PoC {io.file}:{io.line}",
                address=0,
            )],
        ))

    # 4. Pipeline summary Finding (info-level metadata).
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
            f"{len(seen_codes)} unique source IOCTL codes classified. "
            f"{len(poc_seen)} PoC IOCTL codes from "
            f"{len(poc_devices)} driver target(s)."
        ),
        details={
            "source_dir": str(source_dir),
            "source_functions": len(src_funcs),
            "matched": len(matches),
            "unmatched": len(unmatched),
            "renamed": renamed,
            "ioctl_codes": [hex(c) for c in sorted(seen_codes)],
            "poc_ioctl_codes": [hex(c) for c in sorted(poc_seen)],
            "poc_device_names": poc_devices,
        },
    ))

    # 5. UE5 source-pattern findings (Plan D — Run 19).
    for cat, file_rel, line, snippet in ue5_matches:
        meta = UE5_SOURCE_FINDING_META.get(cat)
        if meta is None:
            continue
        findings.append(Finding(
            id="",
            category=meta["category"],
            severity=meta["severity"],
            address=0,
            function=f"{file_rel}:{line}",
            binary=binary,
            arch=arch,
            platform=platform,
            detector="analysis.source_surface.ue5",
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            description=(
                f"UE5 source pattern `{cat}` matched at "
                f"{file_rel}:{line}: {snippet[:100]}"
            ),
            details={
                "ue5_pattern": cat,
                "source_file": file_rel,
                "source_line": line,
                "snippet": snippet,
            },
        ))

    return findings
