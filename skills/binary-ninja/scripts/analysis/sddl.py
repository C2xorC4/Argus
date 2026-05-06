"""SDDL / ACE permissive-IPC analyzer (Plan A from Run 15).

Two detection patterns:

1. **NULL DACL** — `SetSecurityDescriptorDacl(sd, TRUE, NULL, FALSE)`
   call. NULL DACL means "no access control" — equivalent to "Everyone
   has full access" but distinct from the explicit Everyone-ACE pattern.

2. **Permissive SDDL string** — string constant containing an SDDL
   DACL clause whose ACEs grant over-broad rights to over-broad
   principals (Anonymous Logon, NULL DACL, Guests, Everyone with
   GENERIC_ALL). Cross-referenced against IPC-creation call sites
   (`CreateNamedPipeW`, `CreateFileMappingW`, etc.) when the SDDL
   string flows into `ConvertStringSecurityDescriptorToSecurityDescriptor*`.

The detector is intentionally **structural** rather than
taint-driven: SDDL strings live in `.rdata` and are read-only at
runtime, so taint analysis adds nothing. The detection is "this
string is permissive AND it's used for a security-sensitive
purpose."

Knowledge anchors:
- `[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]` — EAC named-
  IPC SDDL pattern (component 1 of the chain)
- `[[Memory/Knowledge/gameguard_research_22_findings]]` — GameGuard
  `SmxNPGG` NULL DACL on named pipe

Generalises to: any Windows binary that creates IPC objects with
permissive ACEs — this is the universal pattern for the named-pipe
LPE class.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..heuristics._base import imports_in
from ..lib.scoring import apply_signals_to_finding
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh


# ─────────────────────────────────────────────────────────────────
# SDDL grammar — well-known principal & right abbreviations
# ─────────────────────────────────────────────────────────────────


# SDDL principal abbreviations → human-readable label
_PRINCIPAL_LABELS: dict[str, str] = {
    # Highly over-broad principals (the deny-list anchor set)
    "WD": "Everyone (World)",
    "AN": "Anonymous Logon",
    "AU": "Authenticated Users",
    "BU": "Users",
    "BG": "Guests",
    "IU": "Interactive Users",
    "NU": "Network Users",
    # Less-broad but still notable
    "WR": "World Restricted",
    "RC": "Restricted Code",
    # Reference (NOT permissive — included for parser completeness)
    "SY": "Local System",
    "BA": "Builtin Administrators",
    "LA": "Local Administrator",
    "CO": "Creator Owner",
    "LS": "Local Service",
    "NS": "Network Service",
}


# Principals that triggering the deny-list. Both the SDDL abbreviation
# and the canonical SID string forms are keyed — SDDL strings in the
# wild use either ("D:(A;;GA;;;WD)" or "D:(A;;GA;;;S-1-1-0)").
_OVERBROAD_PRINCIPALS: dict[str, str] = {
    # Abbreviated forms
    "WD":          "Everyone (World) — any local user including non-interactive accounts",
    "AN":          "Anonymous Logon (S-1-5-7) — unauthenticated remote access",
    "BG":          "Guests (S-1-5-32-546) — by-default disabled but enabled-by-policy at some sites",
    "BU":          "Users (S-1-5-32-545) — over-broad for most security boundaries",
    "AU":          "Authenticated Users — includes any logged-in account; OK only for read-only resources",
    "IU":          "Interactive Users — over-broad for SYSTEM-tier resources",
    # Canonical SID forms (Win32 SDDL accepts both)
    "S-1-1-0":     "Everyone (World) — any local user including non-interactive accounts",
    "S-1-5-7":     "Anonymous Logon — unauthenticated remote access",
    "S-1-5-32-546": "Guests — by-default disabled but enabled-by-policy at some sites",
    "S-1-5-32-545": "Users — over-broad for most security boundaries",
    "S-1-5-11":    "Authenticated Users — includes any logged-in account; OK only for read-only resources",
    "S-1-5-4":     "Interactive Users — over-broad for SYSTEM-tier resources",
}


# Rights abbreviations → set of "permissions" the right grants. The
# specific bit-meaning is object-type-dependent in Windows; the
# heuristic uses simple "broad-write" / "broad-execute" classification.
_BROAD_WRITE_RIGHTS: frozenset[str] = frozenset({
    "GA",      # GENERIC_ALL (covers everything)
    "GW",      # GENERIC_WRITE
    "WD",      # WRITE_DAC (when used as a right, not a principal)
    "WO",      # WRITE_OWNER
    "KA",      # KEY_ALL_ACCESS (registry)
    "FA",      # FILE_ALL_ACCESS
    "FW",      # FILE_GENERIC_WRITE
    "MA",      # ALL_ACCESS (mailslot)
})


_GRANT_RIGHTS_OK_FOR_AU: frozenset[str] = frozenset({
    "GR",      # GENERIC_READ
    "GX",      # GENERIC_EXECUTE
    "KR",      # KEY_READ
    "FR",      # FILE_GENERIC_READ
    "RC",      # READ_CONTROL
    "FX",      # FILE_GENERIC_EXECUTE
})


# ACE-string regex — captures `(type;flags;rights;object;inherit;sid)`
_ACE_RE = re.compile(
    r"\(\s*(?P<type>[A-Z]+)\s*;\s*(?P<flags>[A-Z]*)\s*;\s*"
    r"(?P<rights>[A-Z0-9]+)\s*;\s*(?P<object>[A-F0-9-]*)\s*;\s*"
    r"(?P<inherit>[A-F0-9-]*)\s*;\s*(?P<sid>[A-Z0-9\-]+)\s*\)"
)


_DACL_CLAUSE_RE = re.compile(r"D:(?P<flags>[A-Z]*)\((?P<aces>(\([^)]*\))*)?")


# ─────────────────────────────────────────────────────────────────
# SDDL classification
# ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AceFinding:
    """One classification result for a single ACE in an SDDL string."""

    ace_type: str          # "A" allow, "D" deny, ...
    rights: str            # raw rights string from the ACE
    sid: str               # raw SID / abbreviation
    principal_label: str   # human-readable
    severity_class: str    # "permissive" | "neutral" | "deny"
    rationale: str


def _classify_ace(ace_type: str, rights: str, sid: str) -> AceFinding:
    """Classify one ACE for permissiveness."""
    label = _PRINCIPAL_LABELS.get(sid, sid)
    rationale = ""
    severity = "neutral"

    # Only Allow ACEs are permissive concerns; Deny ACEs are protective
    if ace_type != "A":
        return AceFinding(ace_type, rights, sid, label, "deny",
                          f"deny ACE on {label}")

    # Parse rights into 2-char abbreviations
    rights_set = set()
    i = 0
    while i + 1 < len(rights) + 1:
        chunk = rights[i:i + 2]
        if len(chunk) == 2 and chunk.isalpha():
            rights_set.add(chunk)
            i += 2
        else:
            i += 1

    if sid in _OVERBROAD_PRINCIPALS:
        # Over-broad principal — almost any non-trivial right is concerning
        # Authenticated Users with read-only rights is conditionally OK
        if sid == "AU" and rights_set and rights_set.issubset(_GRANT_RIGHTS_OK_FOR_AU):
            severity = "neutral"
            rationale = f"Authenticated Users with read-only rights — OK for read-only resources"
        elif rights_set & _BROAD_WRITE_RIGHTS:
            severity = "permissive"
            rationale = (f"{_OVERBROAD_PRINCIPALS[sid]}; granted "
                         f"broad-write rights ({sorted(rights_set & _BROAD_WRITE_RIGHTS)})")
        elif rights_set:
            severity = "permissive"
            rationale = (f"{_OVERBROAD_PRINCIPALS[sid]}; granted rights "
                         f"({sorted(rights_set)})")

    return AceFinding(ace_type, rights, sid, label, severity, rationale)


def parse_sddl(sddl: str) -> list[AceFinding]:
    """Parse an SDDL string and return classified ACEs.

    Recognises:
    - `D:NO_ACCESS_CONTROL` — explicit NULL DACL.
    - `D:` followed by no ACEs (empty DACL clause) — equivalent NULL
      DACL (GameGuard `SmxNPGG` shape).
    - Allow-ACEs with abbreviated or canonical-SID principals.

    Returns empty list for non-SDDL strings.
    """
    if not sddl or not isinstance(sddl, str):
        return []
    # Quick shape check
    if "D:" not in sddl and "O:" not in sddl:
        return []
    # Explicit NULL-DACL marker
    if "D:NO_ACCESS_CONTROL" in sddl:
        return [AceFinding("NULL_DACL", "", "",
                           "NULL DACL (no access control — Everyone full access)",
                           "permissive",
                           "NULL DACL is the explicit 'I disabled the gate entirely' form")]
    findings: list[AceFinding] = []
    for m in _ACE_RE.finditer(sddl):
        f = _classify_ace(m.group("type"), m.group("rights"), m.group("sid"))
        findings.append(f)
    # Empty-DACL detection: `D:` clause present but contains no ACEs.
    # The DACL section runs from `D:` to the next top-level marker
    # (`S:`, `O:`, `G:`) or end-of-string. If that section has no
    # parens, it's an empty DACL — semantically equivalent to NULL DACL.
    if not findings:
        d_idx = sddl.find("D:")
        if d_idx >= 0:
            tail = sddl[d_idx + 2:]
            # Cut off at the next section marker
            for marker in ("S:", "O:", "G:"):
                m_idx = tail.find(marker)
                if m_idx >= 0:
                    tail = tail[:m_idx]
            tail = tail.strip()
            # Empty-DACL indicators: nothing, or only flags (uppercase
            # letters) with no ACE parens.
            if "(" not in tail and ")" not in tail:
                findings.append(AceFinding(
                    "EMPTY_DACL", "", "",
                    "Empty DACL (no ACEs — equivalent to NULL DACL)",
                    "permissive",
                    "Empty DACL clause grants no explicit access but defaults "
                    "to 'no protection' on most object types.",
                ))
    return findings


def is_sddl_string(s: str) -> bool:
    """Quick predicate: does `s` look like an SDDL string?

    Heuristic: starts with `D:`, `O:`, or `S:` (the three top-level
    SDDL section markers), and contains at least one ACE-like pattern
    or an explicit NULL-DACL marker.
    """
    if not s or len(s) < 4:
        return False
    if not (s.startswith("D:") or s.startswith("O:") or s.startswith("S:")):
        return False
    return ("(" in s and ")" in s) or "NO_ACCESS_CONTROL" in s


# ─────────────────────────────────────────────────────────────────
# Detector — pattern 1: SDDL string literals + IPC creation
# ─────────────────────────────────────────────────────────────────


CATEGORY_META = {
    "permissive_sddl": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-732"],
        "mitre": ["T1068"],
        "knowledge_refs": [
            "[[Memory/Knowledge/eac_eos_arbitrary_write_chain]]",
            "[[Memory/Knowledge/gameguard_research_22_findings]]",
        ],
    },
    "null_dacl": {
        "severity": Severity.HIGH,
        "cwe": ["CWE-732"],
        "mitre": ["T1068"],
        "knowledge_refs": [
            "[[Memory/Knowledge/gameguard_research_22_findings]]",
        ],
    },
}


# Per-category signal mapping
_CATEGORY_SIGNALS: dict[str, tuple[str, ...]] = {
    "permissive_sddl": ("permissive_sddl_grant_overbroad_principal",),
    "null_dacl":       ("null_dacl_set_explicit",),
}


def _read_string_at(bv, addr: int, max_len: int = 512) -> Optional[str]:
    """Read a wide-or-narrow C string at `addr`. Try UTF-16-LE first
    (the canonical SDDL form on Windows), fall back to ASCII/UTF-8."""
    if bv is None:
        return None
    try:
        # Read up to 2*max_len bytes (allowing for UTF-16)
        data = bv.read(addr, max_len * 2)
    except Exception:
        return None
    if not data:
        return None
    # Try UTF-16-LE — terminate on NUL-NUL pair
    try:
        end16 = len(data)
        for i in range(0, len(data) - 1, 2):
            if data[i] == 0 and data[i + 1] == 0:
                end16 = i
                break
        if end16 >= 4 and end16 % 2 == 0:
            decoded = data[:end16].decode("utf-16-le", errors="strict")
            if decoded and "D:" in decoded[:8] or "O:" in decoded[:8]:
                return decoded
            # Even if it doesn't pass the SDDL check, return decoded
            # to let caller filter.
            if decoded:
                return decoded
    except UnicodeDecodeError:
        pass
    # Fall back to ASCII
    try:
        end8 = data.find(b"\x00")
        if end8 == -1:
            end8 = len(data)
        decoded = data[:end8].decode("utf-8", errors="strict")
        return decoded
    except UnicodeDecodeError:
        return None


def _enumerate_string_constants(bv) -> list[tuple[int, str]]:
    """Return (addr, content) for each string constant in `bv`'s
    string table that looks like SDDL.

    Uses Binja's string-recovery + a quick filter; doesn't require
    expensive `read_full_string`.
    """
    if bv is None:
        return []
    candidates: list[tuple[int, str]] = []
    strings = getattr(bv, "strings", None)
    if strings is None:
        return []
    try:
        for s in strings:
            try:
                content = s.value
            except Exception:
                continue
            if is_sddl_string(content):
                candidates.append((int(s.start), content))
    except Exception:
        pass
    return candidates


# IPC-creation imports — present means the binary makes security-
# sensitive IPC objects. SDDL string flows into these directly or
# (more commonly) via `Convert*SecurityDescriptor*`.
_IPC_CREATE_IMPORTS: frozenset[str] = frozenset({
    "CreateFileMappingA", "CreateFileMappingW",
    "CreateNamedPipeA", "CreateNamedPipeW",
    "CreateMutexA", "CreateMutexW", "CreateMutexExA", "CreateMutexExW",
    "CreateEventA", "CreateEventW", "CreateEventExA", "CreateEventExW",
    "CreateSemaphoreA", "CreateSemaphoreW",
    "CreateFileA", "CreateFileW", "CreateFile2",
    "CreateMailslotA", "CreateMailslotW",
    "RegCreateKeyExA", "RegCreateKeyExW", "RegSetKeySecurity",
    "ShareCreate",
})


_SDDL_CONVERT_IMPORTS: frozenset[str] = frozenset({
    "ConvertStringSecurityDescriptorToSecurityDescriptorA",
    "ConvertStringSecurityDescriptorToSecurityDescriptorW",
})


_SET_DACL_IMPORTS: frozenset[str] = frozenset({
    "SetSecurityDescriptorDacl",
    "SetSecurityDescriptorSacl",
    "RtlSetDaclSecurityDescriptor",
})


def find_permissive_sddl(bv, *, binary: str, arch: str, platform: str,
                         detector: str = "analysis.sddl") -> list[Finding]:
    """Detect permissive SDDL strings used in security contexts.

    Strategy: find SDDL string constants, classify their ACEs,
    cross-check that the binary imports either a SDDL converter or
    an IPC-creation API (i.e., the SDDL is plausibly used). Emit
    one finding per permissive SDDL string.
    """
    findings: list[Finding] = []
    imports = imports_in(bv)
    has_sddl_use = bool(imports & (_SDDL_CONVERT_IMPORTS | _IPC_CREATE_IMPORTS))
    if not has_sddl_use:
        return findings

    # First IPC-create import for cross-reference function (the
    # finding's `function` field — anchor at `wmain` / `main` / the
    # function containing the SDDL conversion call).
    sddl_strings = _enumerate_string_constants(bv)
    if not sddl_strings:
        return findings

    # Find the function that uses each SDDL string. Walk code refs to
    # the string's address; the first ref's function is the anchor.
    code_ref_getter = getattr(bv, "get_code_refs", None)

    for addr, content in sddl_strings:
        aces = parse_sddl(content)
        permissive = [a for a in aces if a.severity_class == "permissive"]
        if not permissive:
            continue

        # Locate using function via code refs
        func_name = "<binary>"
        ref_addr = addr
        if callable(code_ref_getter):
            try:
                refs = list(code_ref_getter(addr))
                if refs:
                    f = refs[0].function
                    func_name = ilh.function_display_name(f)
                    ref_addr = int(refs[0].address)
            except Exception:
                pass

        # Build description from the most-permissive ACE
        primary = permissive[0]
        meta = CATEGORY_META["permissive_sddl"]
        finding = Finding(
            id="",
            category="permissive_sddl",
            severity=meta["severity"],
            address=ref_addr,
            function=func_name,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre"]),
            description=(
                f"SDDL string at 0x{addr:x} grants permissive ACE: "
                f"{primary.principal_label} via rights '{primary.rights}'. "
                f"{primary.rationale}. SDDL: {content[:80]!r}"
            ),
            evidence=[Evidence(
                kind="sddl_permissive_string",
                source=detector,
                payload=f"sddl_addr=0x{addr:x} content={content[:120]!r}",
                address=addr,
                function=func_name,
            )],
            details={
                "sddl_addr": hex(addr),
                "sddl_content": content,
                "permissive_aces": [
                    {"principal": a.principal_label, "rights": a.rights,
                     "rationale": a.rationale}
                    for a in permissive
                ],
            },
        )
        signals = _CATEGORY_SIGNALS.get("permissive_sddl", ())
        if signals:
            apply_signals_to_finding(finding, signals)
        findings.append(finding)

    return findings


# ─────────────────────────────────────────────────────────────────
# Detector — pattern 2: SetSecurityDescriptorDacl with NULL DACL
# ─────────────────────────────────────────────────────────────────


def _is_null_or_zero(expr) -> bool:
    """True if `expr` is the constant 0/NULL."""
    if expr is None:
        return False
    val = getattr(expr, "constant", None)
    if val is not None:
        try:
            return int(val) == 0
        except Exception:
            return False
    op_name = type(expr).__name__
    if "Const" in op_name:
        v = getattr(expr, "value", None)
        if v is not None:
            try:
                return int(v) == 0
            except Exception:
                return False
    return False


def _is_true_or_one(expr) -> bool:
    """True if `expr` is the constant 1/TRUE."""
    if expr is None:
        return False
    val = getattr(expr, "constant", None)
    if val is not None:
        try:
            return int(val) == 1
        except Exception:
            return False
    op_name = type(expr).__name__
    if "Const" in op_name:
        v = getattr(expr, "value", None)
        if v is not None:
            try:
                return int(v) == 1
            except Exception:
                return False
    return False


def find_null_dacl(bv, *, binary: str, arch: str, platform: str,
                   detector: str = "analysis.sddl") -> list[Finding]:
    """Detect `SetSecurityDescriptorDacl(sd, TRUE, NULL, FALSE)` calls.

    The exact NULL-DACL pattern: arg2 is constant 1 (DaclPresent=TRUE),
    arg3 is constant 0 (Dacl pointer = NULL).
    """
    findings: list[Finding] = []
    imports = imports_in(bv)
    if "SetSecurityDescriptorDacl" not in imports:
        return findings

    for addr, mlil in ilh.call_sites_of_import(bv, "SetSecurityDescriptorDacl"):
        if mlil is None:
            continue
        params = ilh.call_params(mlil)
        if len(params) < 3:
            continue
        if not _is_true_or_one(params[1]):
            continue
        if not _is_null_or_zero(params[2]):
            continue

        func = getattr(mlil, "function", None)
        func_name = ilh.function_display_name(func)
        meta = CATEGORY_META["null_dacl"]
        finding = Finding(
            id="",
            category="null_dacl",
            severity=meta["severity"],
            address=addr,
            function=func_name,
            binary=binary, arch=arch, platform=platform,
            detector=detector,
            knowledge_refs=list(meta["knowledge_refs"]),
            cwe=list(meta["cwe"]),
            mitre_attack=list(meta["mitre"]),
            description=(
                "SetSecurityDescriptorDacl called with DaclPresent=TRUE and "
                "Dacl=NULL — explicit NULL DACL means 'no access control'; "
                "any local user has full access to the secured object"
            ),
            evidence=[Evidence(
                kind="null_dacl_call",
                source=detector,
                payload=f"SetSecurityDescriptorDacl@0x{addr:x} args=(sd, TRUE, NULL, ...)",
                address=addr,
                function=func_name,
            )],
            details={
                "sink_name": "SetSecurityDescriptorDacl",
                "sink_addr": hex(addr),
            },
        )
        signals = _CATEGORY_SIGNALS.get("null_dacl", ())
        if signals:
            apply_signals_to_finding(finding, signals)
        findings.append(finding)

    return findings


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            detector: str = "analysis.sddl") -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    findings: list[Finding] = []
    findings.extend(find_permissive_sddl(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    findings.extend(find_null_dacl(
        bv, binary=binary, arch=arch, platform=platform, detector=detector,
    ))
    return findings
