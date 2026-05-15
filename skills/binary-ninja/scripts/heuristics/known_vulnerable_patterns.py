"""Known-vulnerable-pattern heuristic — driven by the 0patch corpus.

Loads a curated corpus of (binary, file-version, vulnerable offset,
pre-patch byte signature, CVE) records derived from the operator's
local 0patch deployment. Emits Findings for binaries the corpus
covers in two modes:

- Exact hash match: every recorded offset for the matching SHA-1 is
  flagged as a known-vulnerable code path.
- Fuzzy match: same binary name, different SHA-1 — the detector
  scans for the recorded pre-patch byte signature at (or near) the
  recorded offset. If the signature is still present, the
  vulnerability likely persists in this version; emit at lower
  confidence.

Disclosure boundary: the corpus contains only research-derivable
fields (binary + hash + offset + pre-patch bytes + CVE). It does
NOT contain 0patch's authored mitigation bytes, hook imports, or
internal flag taxonomy — those stay in the operator's private
research repo + LJM.

Knowledge anchor: see `Memory/Knowledge/0patch_corpus_overview` for
the corpus index and per-binary entries.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._base import Pattern
from ..output.finding import Finding, Severity

DATA_PATH = Path(__file__).parent / "data" / "known_vulnerable_patterns.json"


# ─────────────────────────────────────────────────────────────────
# Corpus loader
# ─────────────────────────────────────────────────────────────────


@dataclass
class _OffsetSig:
    address: int
    original_bytes: bytes


@dataclass
class _CorpusEntry:
    module: str
    module_hash: str
    offsets: list[_OffsetSig]
    cves: list[str]
    vulnerability_class: str
    description: str
    knowledge_ref: str


def _load_corpus() -> tuple[dict[str, list[_CorpusEntry]],
                            dict[str, list[_CorpusEntry]]]:
    """Returns (by_hash, by_module) views of the corpus.

    `by_hash`   — indexed by SHA-1 (40-hex), used for exact match.
    `by_module` — indexed by module file name (lowercase), used for
                  fuzzy match.
    """
    by_hash: dict[str, list[_CorpusEntry]] = {}
    by_module: dict[str, list[_CorpusEntry]] = {}

    if not DATA_PATH.exists():
        return by_hash, by_module

    raw = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    for r in raw.get("entries", []):
        if not r.get("vulnerable_offsets"):
            continue
        offsets = [
            _OffsetSig(
                address=o["address"],
                original_bytes=bytes.fromhex(o["original_bytes"]),
            )
            for o in r["vulnerable_offsets"]
        ]
        entry = _CorpusEntry(
            module=r["module"],
            module_hash=r["module_hash"].lower(),
            offsets=offsets,
            cves=r.get("cves", []),
            vulnerability_class=r.get("vulnerability_class", "unspecified"),
            description=r.get("description", ""),
            knowledge_ref=r.get("knowledge_ref", ""),
        )
        by_hash.setdefault(entry.module_hash, []).append(entry)
        by_module.setdefault(entry.module.lower(), []).append(entry)
    return by_hash, by_module


_BY_HASH, _BY_MODULE = _load_corpus()


# Exposed for test/inspection.
PATTERNS: list[Pattern] = []


# ─────────────────────────────────────────────────────────────────
# Severity selection per vulnerability_class
# ─────────────────────────────────────────────────────────────────


_CLASS_SEVERITY: dict[str, Severity] = {
    "rce": Severity.CRITICAL,
    "lpe": Severity.HIGH,
    "ntlm-attack": Severity.HIGH,
    "ntlm-coerce": Severity.HIGH,
    "kerberos-attack": Severity.HIGH,
    "credential-leak": Severity.HIGH,
    "auth-bypass": Severity.HIGH,
    "sandbox-escape": Severity.HIGH,
    "uaf": Severity.HIGH,
    "double-free": Severity.HIGH,
    "heap-overflow": Severity.HIGH,
    "stack-overflow": Severity.HIGH,
    "buffer-overflow": Severity.HIGH,
    "type-confusion": Severity.HIGH,
    "memory-corruption": Severity.HIGH,
    "integer-overflow": Severity.MEDIUM,
    "oob-access": Severity.MEDIUM,
    "info-leak": Severity.MEDIUM,
    "format-string": Severity.MEDIUM,
    "race": Severity.MEDIUM,
    "uninitialized": Severity.MEDIUM,
    "spoofing": Severity.MEDIUM,
    "motw-bypass": Severity.MEDIUM,
    "permissive-acl": Severity.MEDIUM,
    "arbitrary-file": Severity.MEDIUM,
    "arbitrary-registry": Severity.MEDIUM,
    "filesystem-redirect": Severity.MEDIUM,
    "print-spooler-write": Severity.MEDIUM,
    "crypto": Severity.MEDIUM,
    "command-injection": Severity.HIGH,
    "path-traversal": Severity.MEDIUM,
    "deserialization": Severity.HIGH,
    "sql-injection": Severity.HIGH,
    "xss": Severity.MEDIUM,
    "xxe": Severity.MEDIUM,
    "dll-hijack": Severity.MEDIUM,
    "task-scheduler-bypass": Severity.MEDIUM,
    "null-deref": Severity.LOW,
    "dos": Severity.LOW,
    "logic-flaw": Severity.LOW,
    "agent-bug": Severity.INFO,
    "agent-test": Severity.INFO,
    "unspecified": Severity.LOW,
}


def _severity_for(vuln_class: str) -> Severity:
    return _CLASS_SEVERITY.get(vuln_class, Severity.LOW)


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────


def _file_sha1(binary_path: str) -> str | None:
    try:
        with open(binary_path, "rb") as fh:
            h = hashlib.sha1()
            while chunk := fh.read(1 << 20):
                h.update(chunk)
            return h.hexdigest()
    except OSError:
        return None


def _resolve_va(bv, address: int, length: int) -> int | None:
    """Return the effective virtual address for a corpus-recorded offset.

    `address` is a module-relative offset (RVA / patchlet_address from
    the 0patch corpus). Returns the Binja VA where the bytes were found,
    or None if the address maps to no readable region.
    """
    if bv is None:
        return None
    read = getattr(bv, "read", None)
    if not callable(read):
        return None
    # Direct VA read (PE image already rebased by Binja).
    try:
        data = read(address, length)
        if data and len(data) == length:
            return address
    except Exception:
        pass
    # Fall back to image_base + offset.
    try:
        base = getattr(bv, "start", 0) or 0
        va = base + address
        data = read(va, length)
        if data and len(data) == length:
            return va
    except Exception:
        pass
    return None


def _read_bytes_at(bv, address: int, length: int) -> bytes | None:
    """Read `length` bytes from the given address in the BinaryView."""
    va = _resolve_va(bv, address, length)
    if va is None:
        return None
    try:
        data = bv.read(va, length)
        return bytes(data) if data and len(data) == length else None
    except Exception:
        return None


def _function_name_at(bv, va: int) -> str:
    """Return the name of the function containing `va`, or '<binary>'."""
    if bv is None or va == 0:
        return "<binary>"
    try:
        fns = bv.get_functions_containing(va)
        if fns:
            return fns[0].name or "<binary>"
    except Exception:
        pass
    return "<binary>"


def _emit_finding(entry: _CorpusEntry, *, address: int, resolved_va: int,
                  function: str, binary: str, arch: str, platform: str,
                  detector: str, match_kind: str, byte_match: bool) -> Finding:
    sev = _severity_for(entry.vulnerability_class)
    cve_str = ",".join(entry.cves) if entry.cves else "no-CVE"
    desc = (
        f"Known-vulnerable code path ({entry.vulnerability_class}, {cve_str}) "
        f"— {entry.description}"
    )
    if match_kind == "fuzzy":
        desc += " — version-fuzzy match (binary differs from corpus hash, "
        desc += "but pre-patch byte signature is present at recorded offset)"
        if not byte_match:
            desc += " [no byte-signature match — same name only]"
    return Finding(
        id="",
        category="known_vulnerable_pattern",
        severity=sev,
        address=resolved_va,
        function=function,
        binary=binary,
        arch=arch,
        platform=platform,
        detector=detector,
        knowledge_refs=[entry.knowledge_ref] if entry.knowledge_ref else [],
        cwe=[],
        mitre_attack=[],
        evidence=[],
        description=desc,
        details={
            "match_kind": match_kind,
            "byte_signature_present": byte_match,
            "corpus_offset": address,
            "module_hash_in_corpus": entry.module_hash,
            "vulnerability_class": entry.vulnerability_class,
            "cves": entry.cves,
        },
    )


# ─────────────────────────────────────────────────────────────────
# Main entry
# ─────────────────────────────────────────────────────────────────


def match(bv, *, binary: str, arch: str, platform: str,
          detector: str = "heuristics.known_vulnerable_patterns") -> list[Finding]:
    """Emit known-vulnerable-pattern Findings for the analyzed binary.

    Uses the operator's local 0patch corpus as ground truth. Finds are:
    - **exact match**: SHA-1 of `binary` is in the corpus → every
      recorded patch site is flagged (one finding per patchlet site,
      deduplicated per (vulnerability_key, address) so the same site
      doesn't appear twice if multiple corpus entries share a hash).
    - **fuzzy match**: SHA-1 differs but file name matches a corpus
      entry → scan recorded offsets for the pre-patch byte signature.
      Deduplicated per vulnerability_key: the same vulnerability that
      appears across many binary versions emits exactly one finding.

    No Finding is produced when nothing in the corpus references the
    binary (by name or hash).
    """
    out: list[Finding] = []
    if not _BY_HASH and not _BY_MODULE:
        return out
    if not binary:
        return out

    sha1 = _file_sha1(binary)
    if sha1:
        sha1 = sha1.lower()
    name = Path(binary).name.lower()

    def _vuln_key(entry: _CorpusEntry) -> tuple:
        return (entry.vulnerability_class, frozenset(entry.cves), entry.description)

    # Exact match — operator's binary IS one of the recorded versions.
    # Deduplicate by (vuln_key, patchlet_address): the corpus may have
    # multiple entries for the same SHA-1 × vulnerability.
    seen_entries: set[int] = set()
    seen_exact: set[tuple] = set()   # (vuln_key, address)
    if sha1 and sha1 in _BY_HASH:
        for entry in _BY_HASH[sha1]:
            seen_entries.add(id(entry))
            for offset in entry.offsets:
                site_key = (_vuln_key(entry), offset.address)
                if site_key in seen_exact:
                    continue
                seen_exact.add(site_key)
                va = _resolve_va(bv, offset.address, len(offset.original_bytes))
                actual = None
                if va is not None:
                    try:
                        data = bv.read(va, len(offset.original_bytes))
                        actual = bytes(data) if data and len(data) == len(offset.original_bytes) else None
                    except Exception:
                        pass
                byte_match = (actual == offset.original_bytes)
                fn = _function_name_at(bv, va or 0)
                out.append(_emit_finding(
                    entry,
                    address=offset.address,
                    resolved_va=va or offset.address,
                    function=fn,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    match_kind="exact",
                    byte_match=byte_match,
                ))

    # Fuzzy match — same binary name, different version.
    # Deduplicate by vuln_key: the same vulnerability in N recorded
    # versions of the binary should produce exactly one finding.
    # Within each vuln_key group, prefer the first confirmed byte-match
    # and stop scanning additional corpus versions once found.
    candidates = _BY_MODULE.get(name, [])
    seen_fuzzy: dict[tuple, Finding] = {}  # vuln_key → best finding
    for entry in candidates:
        if id(entry) in seen_entries:
            continue
        vk = _vuln_key(entry)
        if vk in seen_fuzzy:
            # Already have a confirmed byte-match for this vulnerability;
            # additional corpus versions can't improve it.
            continue
        for offset in entry.offsets:
            va = _resolve_va(bv, offset.address, len(offset.original_bytes))
            if va is None:
                continue
            try:
                data = bv.read(va, len(offset.original_bytes))
                actual = bytes(data) if data and len(data) == len(offset.original_bytes) else None
            except Exception:
                actual = None
            if actual == offset.original_bytes:
                fn = _function_name_at(bv, va)
                seen_fuzzy[vk] = _emit_finding(
                    entry,
                    address=offset.address,
                    resolved_va=va,
                    function=fn,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    match_kind="fuzzy",
                    byte_match=True,
                )
                break  # one confirmed site per vulnerability is sufficient

    out.extend(seen_fuzzy.values())
    return out
