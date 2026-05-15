"""Unit tests for heuristics/known_vulnerable_patterns.py.

Tests use synthetic corpus data injected via patch.dict; Binary Ninja is not
required. A MinimalBV stub supplies read(), get_functions_containing(), and
start.

Coverage:
  _resolve_va — direct VA hit, base+offset fallback, bv=None, unreadable
  _read_bytes_at — delegates to _resolve_va; None on miss
  _function_name_at — returns name, falls back to '<binary>', bv=None
  _severity_for — known and unknown vulnerability classes
  match() — empty corpus → []
  match() — binary not in corpus → []
  match() — exact hash match → one finding per offset site
  match() — exact match dedup: same (vuln, address) from two corpus entries
  match() — fuzzy: byte sig present → one finding
  match() — fuzzy dedup: same vulnerability in N corpus versions → exactly one finding
  match() — fuzzy: byte sig absent → no finding for that vulnerability
  match() — fuzzy skips entries already consumed by exact match
  match() — function name resolved from bv, not '<binary>'
  match() — bv=None path (no VA resolution, still emits for exact match)
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS.parent))

import scripts.heuristics.known_vulnerable_patterns as kvp
from scripts.heuristics.known_vulnerable_patterns import (
    _OffsetSig,
    _CorpusEntry,
    _resolve_va,
    _read_bytes_at,
    _function_name_at,
    _severity_for,
    match,
)
from scripts.output.finding import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_KNOWN_HASH = "a" * 40          # synthetic SHA-1 for exact-match tests
_OTHER_HASH = "b" * 40          # different hash (fuzzy-match scenario)
_BYTES_5    = bytes([0x48, 0x8B, 0xC8, 0xE8, 0xF7])


def _entry(module: str = "target.dll", hash: str = _KNOWN_HASH,
           offsets=None, cves=("CVE-2021-0001",),
           vuln_class: str = "lpe", desc: str = "test vuln",
           ref: str = "") -> _CorpusEntry:
    if offsets is None:
        offsets = [_OffsetSig(address=0x1000, original_bytes=_BYTES_5)]
    return _CorpusEntry(
        module=module,
        module_hash=hash,
        offsets=offsets,
        cves=list(cves),
        vulnerability_class=vuln_class,
        description=desc,
        knowledge_ref=ref,
    )


class _Fn:
    def __init__(self, name: str):
        self.name = name


class MinimalBV:
    """Minimal Binary Ninja BinaryView stub."""

    def __init__(self, memory: dict[int, bytes] | None = None,
                 fn_name: str = "TestFunc"):
        self._mem = memory or {}
        self._fn_name = fn_name
        self.start = 0x0

    def read(self, address: int, length: int) -> bytes | None:
        data = self._mem.get(address)
        if data and len(data) >= length:
            return data[:length]
        return None

    def get_functions_containing(self, va: int) -> list:
        if self._fn_name:
            return [_Fn(self._fn_name)]
        return []


# ---------------------------------------------------------------------------
# _resolve_va
# ---------------------------------------------------------------------------

class TestResolveVa(unittest.TestCase):

    def test_direct_va_hit(self):
        bv = MinimalBV(memory={0x1000: _BYTES_5})
        va = _resolve_va(bv, 0x1000, len(_BYTES_5))
        self.assertEqual(va, 0x1000)

    def test_base_plus_offset_fallback(self):
        # Address 0x1000 not directly readable; base=0x400000, so VA=0x401000
        bv = MinimalBV(memory={0x401000: _BYTES_5})
        bv.start = 0x400000
        va = _resolve_va(bv, 0x1000, len(_BYTES_5))
        self.assertEqual(va, 0x401000)

    def test_bv_none_returns_none(self):
        self.assertIsNone(_resolve_va(None, 0x1000, 5))

    def test_unreadable_returns_none(self):
        bv = MinimalBV(memory={})           # nothing in memory
        self.assertIsNone(_resolve_va(bv, 0x1000, 5))

    def test_short_read_falls_back(self):
        # read() returns fewer bytes than requested; should fall back and fail
        bv = MinimalBV(memory={0x1000: _BYTES_5[:2]})  # only 2 bytes
        self.assertIsNone(_resolve_va(bv, 0x1000, len(_BYTES_5)))


# ---------------------------------------------------------------------------
# _read_bytes_at
# ---------------------------------------------------------------------------

class TestReadBytesAt(unittest.TestCase):

    def test_reads_from_resolved_va(self):
        bv = MinimalBV(memory={0x1000: _BYTES_5})
        result = _read_bytes_at(bv, 0x1000, len(_BYTES_5))
        self.assertEqual(result, _BYTES_5)

    def test_returns_none_on_miss(self):
        bv = MinimalBV(memory={})
        self.assertIsNone(_read_bytes_at(bv, 0x1000, 5))

    def test_returns_none_bv_none(self):
        self.assertIsNone(_read_bytes_at(None, 0x1000, 5))


# ---------------------------------------------------------------------------
# _function_name_at
# ---------------------------------------------------------------------------

class TestFunctionNameAt(unittest.TestCase):

    def test_returns_function_name(self):
        bv = MinimalBV(fn_name="TargetFunc")
        name = _function_name_at(bv, 0x1000)
        self.assertEqual(name, "TargetFunc")

    def test_fallback_on_no_functions(self):
        bv = MinimalBV(fn_name="")
        name = _function_name_at(bv, 0x1000)
        self.assertEqual(name, "<binary>")

    def test_bv_none(self):
        self.assertEqual(_function_name_at(None, 0x1000), "<binary>")

    def test_va_zero(self):
        bv = MinimalBV(fn_name="SomeFunc")
        self.assertEqual(_function_name_at(bv, 0), "<binary>")


# ---------------------------------------------------------------------------
# _severity_for
# ---------------------------------------------------------------------------

class TestSeverityFor(unittest.TestCase):

    def test_rce_is_critical(self):
        self.assertEqual(_severity_for("rce"), Severity.CRITICAL)

    def test_lpe_is_high(self):
        self.assertEqual(_severity_for("lpe"), Severity.HIGH)

    def test_null_deref_is_low(self):
        self.assertEqual(_severity_for("null-deref"), Severity.LOW)

    def test_agent_test_is_info(self):
        self.assertEqual(_severity_for("agent-test"), Severity.INFO)

    def test_unknown_class_defaults_low(self):
        self.assertEqual(_severity_for("completely-made-up"), Severity.LOW)


# ---------------------------------------------------------------------------
# match() — empty / no-corpus cases
# ---------------------------------------------------------------------------

class TestMatchEmpty(unittest.TestCase):

    def test_empty_corpus_returns_empty(self):
        with patch.dict(kvp._BY_HASH, {}, clear=True), \
             patch.dict(kvp._BY_MODULE, {}, clear=True):
            result = match(MinimalBV(), binary="", arch="x86_64", platform="windows")
            self.assertEqual(result, [])

    def test_empty_binary_returns_empty(self):
        e = _entry()
        with patch.dict(kvp._BY_HASH, {_KNOWN_HASH: [e]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value=_KNOWN_HASH):
            result = match(MinimalBV(), binary="", arch="x86_64", platform="windows")
            self.assertEqual(result, [])

    def test_binary_not_in_corpus(self):
        e = _entry(module="other.dll", hash=_OTHER_HASH)
        with patch.dict(kvp._BY_HASH, {_OTHER_HASH: [e]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"other.dll": [e]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value="c" * 40):
            result = match(
                MinimalBV(), binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
            self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# match() — exact hash match
# ---------------------------------------------------------------------------

class TestMatchExact(unittest.TestCase):

    def _run(self, bv, corpus_hash=_KNOWN_HASH):
        e = _entry(hash=corpus_hash)
        with patch.dict(kvp._BY_HASH, {corpus_hash: [e]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value=corpus_hash):
            return match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )

    def test_exact_match_emits_finding(self):
        bv = MinimalBV(memory={0x1000: _BYTES_5})
        findings = self._run(bv)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "known_vulnerable_pattern")

    def test_exact_match_kind_label(self):
        bv = MinimalBV(memory={0x1000: _BYTES_5})
        f = self._run(bv)[0]
        self.assertEqual(f.details["match_kind"], "exact")

    def test_exact_match_two_offsets_two_findings(self):
        offsets = [
            _OffsetSig(address=0x1000, original_bytes=_BYTES_5),
            _OffsetSig(address=0x2000, original_bytes=_BYTES_5),
        ]
        mem = {0x1000: _BYTES_5, 0x2000: _BYTES_5}
        bv = MinimalBV(memory=mem)
        e = _entry(offsets=offsets)
        with patch.dict(kvp._BY_HASH, {_KNOWN_HASH: [e]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value=_KNOWN_HASH):
            findings = match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
        self.assertEqual(len(findings), 2)
        addrs = {f.details["corpus_offset"] for f in findings}
        self.assertEqual(addrs, {0x1000, 0x2000})

    def test_exact_match_bv_none(self):
        # bv=None: VA resolution fails but finding is still emitted
        e = _entry()
        with patch.dict(kvp._BY_HASH, {_KNOWN_HASH: [e]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value=_KNOWN_HASH):
            findings = match(
                None, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
        self.assertEqual(len(findings), 1)
        # Address falls back to corpus_offset when resolution fails
        self.assertEqual(findings[0].details["corpus_offset"], 0x1000)

    def test_exact_match_function_name_resolved(self):
        bv = MinimalBV(memory={0x1000: _BYTES_5}, fn_name="VulnFunc")
        findings = self._run(bv)
        self.assertEqual(findings[0].function, "VulnFunc")


# ---------------------------------------------------------------------------
# match() — exact match deduplication
# ---------------------------------------------------------------------------

class TestMatchExactDedup(unittest.TestCase):

    def test_same_vuln_same_address_deduped(self):
        """Two corpus entries with the same hash, same vuln, same offset → 1 finding."""
        offset = _OffsetSig(address=0x1000, original_bytes=_BYTES_5)
        e1 = _entry(hash=_KNOWN_HASH, offsets=[offset])
        e2 = _entry(hash=_KNOWN_HASH, offsets=[offset])   # identical

        bv = MinimalBV(memory={0x1000: _BYTES_5})
        with patch.dict(kvp._BY_HASH, {_KNOWN_HASH: [e1, e2]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e1, e2]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value=_KNOWN_HASH):
            findings = match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
        self.assertEqual(len(findings), 1)

    def test_same_vuln_different_address_not_deduped(self):
        """Same vuln but different offsets → 2 findings."""
        e1 = _entry(hash=_KNOWN_HASH,
                    offsets=[_OffsetSig(address=0x1000, original_bytes=_BYTES_5)])
        e2 = _entry(hash=_KNOWN_HASH,
                    offsets=[_OffsetSig(address=0x2000, original_bytes=_BYTES_5)])

        bv = MinimalBV(memory={0x1000: _BYTES_5, 0x2000: _BYTES_5})
        with patch.dict(kvp._BY_HASH, {_KNOWN_HASH: [e1, e2]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e1, e2]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value=_KNOWN_HASH):
            findings = match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
        self.assertEqual(len(findings), 2)

    def test_different_vulns_same_address_both_emitted(self):
        """Different vulnerabilities at the same address → 2 findings."""
        offset = _OffsetSig(address=0x1000, original_bytes=_BYTES_5)
        e1 = _entry(hash=_KNOWN_HASH, cves=("CVE-2021-0001",),
                    desc="first vuln", offsets=[offset])
        e2 = _entry(hash=_KNOWN_HASH, cves=("CVE-2022-0002",),
                    desc="second vuln", offsets=[offset])

        bv = MinimalBV(memory={0x1000: _BYTES_5})
        with patch.dict(kvp._BY_HASH, {_KNOWN_HASH: [e1, e2]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e1, e2]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value=_KNOWN_HASH):
            findings = match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
        self.assertEqual(len(findings), 2)
        cve_sets = {frozenset(f.details["cves"]) for f in findings}
        self.assertIn(frozenset(["CVE-2021-0001"]), cve_sets)
        self.assertIn(frozenset(["CVE-2022-0002"]), cve_sets)


# ---------------------------------------------------------------------------
# match() — fuzzy match
# ---------------------------------------------------------------------------

class TestMatchFuzzy(unittest.TestCase):

    def _run_fuzzy(self, bv, corpus_entries):
        module_entries = {e.module.lower(): corpus_entries for e in corpus_entries}
        with patch.dict(kvp._BY_HASH, {}, clear=True), \
             patch.dict(kvp._BY_MODULE, module_entries, clear=True), \
             patch.object(kvp, "_file_sha1", return_value="9" * 40):
            return match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )

    def test_fuzzy_byte_match_emits_finding(self):
        e = _entry(hash=_OTHER_HASH)
        bv = MinimalBV(memory={0x1000: _BYTES_5})
        findings = self._run_fuzzy(bv, [e])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].details["match_kind"], "fuzzy")
        self.assertTrue(findings[0].details["byte_signature_present"])

    def test_fuzzy_byte_mismatch_no_finding(self):
        e = _entry(hash=_OTHER_HASH)
        bv = MinimalBV(memory={0x1000: bytes(5)})   # wrong bytes
        findings = self._run_fuzzy(bv, [e])
        self.assertEqual(len(findings), 0)

    def test_fuzzy_no_readable_va_no_finding(self):
        e = _entry(hash=_OTHER_HASH)
        bv = MinimalBV(memory={})
        findings = self._run_fuzzy(bv, [e])
        self.assertEqual(len(findings), 0)

    def test_fuzzy_function_name_resolved(self):
        e = _entry(hash=_OTHER_HASH)
        bv = MinimalBV(memory={0x1000: _BYTES_5}, fn_name="FuzzyFunc")
        findings = self._run_fuzzy(bv, [e])
        self.assertEqual(findings[0].function, "FuzzyFunc")


# ---------------------------------------------------------------------------
# match() — fuzzy deduplication (the 17-dup bug)
# ---------------------------------------------------------------------------

class TestMatchFuzzyDedup(unittest.TestCase):
    """Regression test: same vulnerability in N corpus versions → exactly one finding.

    spoolsv.exe has 158 corpus entries (one per patch version). Before the fix,
    match() emitted one finding per corpus version that had a byte-sig match,
    producing up to 17 duplicate findings for the PrinterBug. After the fix,
    the first confirmed byte-match short-circuits and any additional corpus
    versions for the same vulnerability are skipped.
    """

    def _make_versions(self, n: int, *, with_sig: list[int] | None = None) -> list[_CorpusEntry]:
        """Create n corpus entries for the same vulnerability, different hashes.

        `with_sig` is the list of entry indices whose memory is populated with
        the matching byte signature. If None, all entries match.
        """
        entries = []
        for i in range(n):
            h = f"{i:040x}"
            entries.append(_entry(
                module="target.dll",
                hash=h,
                cves=("CVE-2021-1675",),
                desc="PrinterBug",
                vuln_class="rce",
            ))
        return entries

    def test_seventeen_versions_one_finding(self):
        entries = self._make_versions(17)
        bv = MinimalBV(memory={0x1000: _BYTES_5})
        with patch.dict(kvp._BY_HASH, {}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": entries}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value="9" * 40):
            findings = match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
        self.assertEqual(len(findings), 1,
                         f"Expected 1 finding for 17 versions of same vuln, got {len(findings)}")

    def test_two_distinct_vulns_two_findings(self):
        e1 = _entry(module="target.dll", hash="1" * 40,
                    cves=("CVE-2021-1675",), desc="PrinterBug", vuln_class="rce")
        e2 = _entry(module="target.dll", hash="2" * 40,
                    cves=("CVE-2020-1234",), desc="OtherBug", vuln_class="lpe")
        bv = MinimalBV(memory={0x1000: _BYTES_5})
        with patch.dict(kvp._BY_HASH, {}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e1, e2]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value="9" * 40):
            findings = match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
        self.assertEqual(len(findings), 2)
        cats = {frozenset(f.details["cves"]) for f in findings}
        self.assertIn(frozenset(["CVE-2021-1675"]), cats)
        self.assertIn(frozenset(["CVE-2020-1234"]), cats)

    def test_no_sig_match_skips_all_versions(self):
        entries = self._make_versions(5)
        bv = MinimalBV(memory={0x1000: bytes(5)})   # wrong bytes everywhere
        with patch.dict(kvp._BY_HASH, {}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": entries}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value="9" * 40):
            findings = match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
        self.assertEqual(len(findings), 0)


# ---------------------------------------------------------------------------
# match() — exact hit excludes entry from fuzzy pass
# ---------------------------------------------------------------------------

class TestMatchExactExcludesFromFuzzy(unittest.TestCase):

    def test_exact_entry_not_doubled_by_fuzzy(self):
        """An entry consumed by the exact pass must not re-appear in the fuzzy pass."""
        e = _entry(hash=_KNOWN_HASH)
        bv = MinimalBV(memory={0x1000: _BYTES_5})
        # Same entry appears in both by_hash and by_module (normal corpus state)
        with patch.dict(kvp._BY_HASH, {_KNOWN_HASH: [e]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value=_KNOWN_HASH):
            findings = match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].details["match_kind"], "exact")


# ---------------------------------------------------------------------------
# match() — severity propagation
# ---------------------------------------------------------------------------

class TestMatchSeverity(unittest.TestCase):

    def _single_finding(self, vuln_class: str) -> object:
        e = _entry(hash=_KNOWN_HASH, vuln_class=vuln_class)
        bv = MinimalBV(memory={0x1000: _BYTES_5})
        with patch.dict(kvp._BY_HASH, {_KNOWN_HASH: [e]}, clear=True), \
             patch.dict(kvp._BY_MODULE, {"target.dll": [e]}, clear=True), \
             patch.object(kvp, "_file_sha1", return_value=_KNOWN_HASH):
            return match(
                bv, binary="C:\\Windows\\System32\\target.dll",
                arch="x86_64", platform="windows",
            )[0]

    def test_rce_severity_critical(self):
        self.assertEqual(self._single_finding("rce").severity, Severity.CRITICAL)

    def test_lpe_severity_high(self):
        self.assertEqual(self._single_finding("lpe").severity, Severity.HIGH)

    def test_dos_severity_low(self):
        self.assertEqual(self._single_finding("dos").severity, Severity.LOW)


if __name__ == "__main__":
    unittest.main()
