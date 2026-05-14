"""Unit tests for analysis/cloud_files.py — Cloud Files write-proxy detector.

Tests use a MockBV and MockFinding; Binary Ninja is not required.

Coverage:
  _cf_imports_present          — all CF_IMPORTS recognised; non-CF filtered out
  _cf_write_proxy_imports      — subset filter (registration + execute calls only)
  analyze() — no imports       → empty list
  analyze() — import only      → INFO cloud_files_import, no HIGH
  analyze() — import + toctou  → INFO + HIGH (bluehammer_stall shape)
  analyze() — import + sddl    → INFO + HIGH (redsun_write_proxy shape)
  analyze() — import + both    → INFO + HIGH (both shapes)
  analyze() — non-write import → INFO only regardless of co-located findings
  analyze() — details/evidence — cf_imports list, exploitation_shapes, evidence payload
  analyze() — session fallback — binary/arch/platform filled from session attrs
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS.parent))

from scripts.analysis.cloud_files import (
    analyze,
    _cf_imports_present,
    _cf_write_proxy_imports,
    _CF_IMPORTS,
    _CF_WRITE_PROXY_IMPORTS,
    CATEGORY_META,
)


# ---------------------------------------------------------------------------
# Mocks
# ---------------------------------------------------------------------------

class _Sym:
    def __init__(self, name: str):
        self.name = name


class MockBV:
    """Minimal BV stub — only needs bv.symbols to work with _imported_symbols."""

    def __init__(self, import_names: list[str]):
        # Expose as a dict so .values() iteration works (primary path in cloud_files.py)
        self.symbols = {n: _Sym(n) for n in import_names}
        self.start = 0x10000000
        self.end   = 0x10100000

    def get_symbols_of_type(self, *_):
        raise TypeError("mock — falls through to symbols.values() path")


class MockSession:
    def __init__(self, import_names: list[str], *,
                 binary: str = "test.dll", arch: str = "x86_64",
                 platform: str = "windows-x86_64"):
        self.bv = MockBV(import_names)
        self.binary_path = binary
        self.arch = arch
        self.platform = platform


class MockFinding:
    def __init__(self, category: str, function: str = "<fn>", address: int = 0x1000):
        self.category = category
        self.function = function
        self.address  = address


def _toctou():  return MockFinding("toctou",        function="MpIsPathSymlink")
def _sddl():    return MockFinding("permissive_sddl", function="MpComInitializeSecurity")


# ---------------------------------------------------------------------------
# _cf_imports_present
# ---------------------------------------------------------------------------

class TestCfImportsPresent(unittest.TestCase):

    def test_empty_binary(self):
        bv = MockBV([])
        self.assertEqual(_cf_imports_present(bv), [])

    def test_all_cf_imports_detected(self):
        bv = MockBV(list(_CF_IMPORTS))
        found = set(_cf_imports_present(bv))
        self.assertEqual(found, set(_CF_IMPORTS))

    def test_non_cf_imports_filtered(self):
        bv = MockBV(["CreateFileW", "NtCreateFile", "SomeOtherApi"])
        self.assertEqual(_cf_imports_present(bv), [])

    def test_mixed_imports(self):
        bv = MockBV(["CreateFileW", "CfRegisterSyncRoot", "GetFileAttributesW"])
        result = _cf_imports_present(bv)
        self.assertEqual(result, ["CfRegisterSyncRoot"])

    def test_result_is_sorted(self):
        bv = MockBV(["CfExecute", "CfConnectSyncRoot", "CfRegisterSyncRoot"])
        result = _cf_imports_present(bv)
        self.assertEqual(result, sorted(result))


# ---------------------------------------------------------------------------
# _cf_write_proxy_imports
# ---------------------------------------------------------------------------

class TestCfWriteProxyImports(unittest.TestCase):

    def test_write_proxy_subset(self):
        all_imports = list(_CF_IMPORTS)
        result = set(_cf_write_proxy_imports(all_imports))
        self.assertTrue(result.issubset(_CF_WRITE_PROXY_IMPORTS))

    def test_non_write_proxy_only(self):
        # CfUnregisterSyncRoot and CfDisconnectSyncRoot are NOT write-proxy
        result = _cf_write_proxy_imports(["CfUnregisterSyncRoot", "CfDisconnectSyncRoot"])
        self.assertEqual(result, [])

    def test_mixed(self):
        result = _cf_write_proxy_imports([
            "CfUnregisterSyncRoot",   # not write-proxy
            "CfRegisterSyncRoot",     # write-proxy
            "CfExecute",              # write-proxy
        ])
        self.assertIn("CfRegisterSyncRoot", result)
        self.assertIn("CfExecute", result)
        self.assertNotIn("CfUnregisterSyncRoot", result)


# ---------------------------------------------------------------------------
# analyze() — no imports
# ---------------------------------------------------------------------------

class TestAnalyzeNoImports(unittest.TestCase):

    def test_no_cf_imports_returns_empty(self):
        session = MockSession(["CreateFileW", "NtCreateFile"])
        result = analyze(session, binary="test.dll", arch="x86_64", platform="windows")
        self.assertEqual(result, [])

    def test_none_bv_returns_empty(self):
        class NoBV:
            bv = None
        result = analyze(NoBV(), binary="test.dll", arch="x86_64", platform="windows")
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# analyze() — import only (no co-located findings)
# ---------------------------------------------------------------------------

class TestAnalyzeImportOnly(unittest.TestCase):

    def setUp(self):
        self.session = MockSession(["CfRegisterSyncRoot", "CfConnectSyncRoot"])

    def test_emits_info_finding(self):
        result = analyze(self.session, binary="t.dll", arch="x", platform="p")
        cats = [f.category for f in result]
        self.assertIn("cloud_files_import", cats)

    def test_no_high_finding_without_colocated_signals(self):
        result = analyze(self.session, binary="t.dll", arch="x", platform="p")
        cats = [f.category for f in result]
        self.assertNotIn("cloud_files_write_proxy", cats)

    def test_info_severity(self):
        from scripts.analysis.cloud_files import CATEGORY_META
        result = analyze(self.session, binary="t.dll", arch="x", platform="p")
        info = next(f for f in result if f.category == "cloud_files_import")
        self.assertEqual(info.severity, CATEGORY_META["cloud_files_import"]["severity"])

    def test_info_finding_lists_imports(self):
        result = analyze(self.session, binary="t.dll", arch="x", platform="p")
        info = next(f for f in result if f.category == "cloud_files_import")
        self.assertIn("CfRegisterSyncRoot", info.details.get("cf_imports", []))
        self.assertIn("CfConnectSyncRoot",  info.details.get("cf_imports", []))

    def test_no_colocated_findings_still_emits_info(self):
        # Empty findings list explicitly passed
        result = analyze(self.session, findings=[], binary="t.dll", arch="x", platform="p")
        cats = [f.category for f in result]
        self.assertIn("cloud_files_import", cats)


# ---------------------------------------------------------------------------
# analyze() — import + TOCTOU → HIGH (bluehammer_stall shape)
# ---------------------------------------------------------------------------

class TestAnalyzeWithToctou(unittest.TestCase):

    def _run(self, extra_imports: list[str] = None):
        imports = ["CfRegisterSyncRoot", "CfConnectSyncRoot"] + (extra_imports or [])
        session = MockSession(imports)
        return analyze(
            session,
            findings=[_toctou()],
            binary="MpSvc.dll", arch="x86_64", platform="windows-x86_64",
        )

    def test_emits_high_finding(self):
        result = self._run()
        cats = [f.category for f in result]
        self.assertIn("cloud_files_write_proxy", cats)

    def test_high_has_bluehammer_shape(self):
        result = self._run()
        high = next(f for f in result if f.category == "cloud_files_write_proxy")
        shapes = high.details.get("exploitation_shapes", [])
        self.assertIn("bluehammer_stall", shapes)

    def test_high_has_toctou_flag(self):
        result = self._run()
        high = next(f for f in result if f.category == "cloud_files_write_proxy")
        self.assertTrue(high.details.get("has_toctou"))
        self.assertFalse(high.details.get("has_sddl"))

    def test_toctou_function_name_propagated(self):
        result = self._run()
        high = next(f for f in result if f.category == "cloud_files_write_proxy")
        self.assertEqual(high.details.get("toctou_function"), "MpIsPathSymlink")

    def test_both_info_and_high_emitted(self):
        result = self._run()
        cats = [f.category for f in result]
        self.assertIn("cloud_files_import", cats)
        self.assertIn("cloud_files_write_proxy", cats)
        self.assertEqual(len(result), 2)


# ---------------------------------------------------------------------------
# analyze() — import + SDDL → HIGH (redsun_write_proxy shape)
# ---------------------------------------------------------------------------

class TestAnalyzeWithSddl(unittest.TestCase):

    def _run(self):
        session = MockSession(["CfCreatePlaceholders", "CfExecute"])
        return analyze(
            session,
            findings=[_sddl()],
            binary="MpSvc.dll", arch="x86_64", platform="windows-x86_64",
        )

    def test_emits_high_finding(self):
        result = self._run()
        cats = [f.category for f in result]
        self.assertIn("cloud_files_write_proxy", cats)

    def test_redsun_shape(self):
        result = self._run()
        high = next(f for f in result if f.category == "cloud_files_write_proxy")
        shapes = high.details.get("exploitation_shapes", [])
        self.assertIn("redsun_write_proxy", shapes)

    def test_sddl_function_name_propagated(self):
        result = self._run()
        high = next(f for f in result if f.category == "cloud_files_write_proxy")
        self.assertEqual(high.details.get("sddl_function"), "MpComInitializeSecurity")


# ---------------------------------------------------------------------------
# analyze() — import + TOCTOU + SDDL → both shapes
# ---------------------------------------------------------------------------

class TestAnalyzeBothShapes(unittest.TestCase):

    def test_both_exploitation_shapes_present(self):
        session = MockSession(["CfRegisterSyncRoot", "CfExecute"])
        result = analyze(
            session,
            findings=[_toctou(), _sddl()],
            binary="MpSvc.dll", arch="x86_64", platform="windows-x86_64",
        )
        high = next(f for f in result if f.category == "cloud_files_write_proxy")
        shapes = high.details.get("exploitation_shapes", [])
        self.assertIn("bluehammer_stall",  shapes)
        self.assertIn("redsun_write_proxy", shapes)

    def test_both_flags_set_in_details(self):
        session = MockSession(["CfConnectSyncRoot", "CfHydratePlaceholder"])
        result = analyze(
            session,
            findings=[_toctou(), _sddl()],
            binary="t.dll", arch="x86_64", platform="windows",
        )
        high = next(f for f in result if f.category == "cloud_files_write_proxy")
        self.assertTrue(high.details.get("has_toctou"))
        self.assertTrue(high.details.get("has_sddl"))


# ---------------------------------------------------------------------------
# analyze() — non-write-proxy imports only → no HIGH
# ---------------------------------------------------------------------------

class TestAnalyzeNonWriteProxyImports(unittest.TestCase):

    def test_disconnect_and_unregister_only_no_high(self):
        # These are cleanup-only calls; attacker can't exploit them directly
        session = MockSession(["CfDisconnectSyncRoot", "CfUnregisterSyncRoot"])
        result = analyze(
            session,
            findings=[_toctou(), _sddl()],
            binary="t.dll", arch="x86_64", platform="windows",
        )
        cats = [f.category for f in result]
        self.assertIn("cloud_files_import", cats)
        self.assertNotIn("cloud_files_write_proxy", cats)

    def test_open_with_oplock_only_no_high(self):
        session = MockSession(["CfOpenFileWithOplock"])
        result = analyze(
            session,
            findings=[_toctou()],
            binary="t.dll", arch="x86_64", platform="windows",
        )
        cats = [f.category for f in result]
        self.assertNotIn("cloud_files_write_proxy", cats)


# ---------------------------------------------------------------------------
# analyze() — evidence payload structure
# ---------------------------------------------------------------------------

class TestAnalyzeEvidence(unittest.TestCase):

    def test_evidence_payload_contains_import_names(self):
        session = MockSession(["CfRegisterSyncRoot", "CfConnectSyncRoot"])
        result = analyze(
            session,
            findings=[_toctou()],
            binary="t.dll", arch="x86_64", platform="windows",
        )
        high = next(f for f in result if f.category == "cloud_files_write_proxy")
        payload = high.evidence[0].payload
        self.assertIn("CfRegisterSyncRoot", payload)

    def test_info_evidence_kind(self):
        session = MockSession(["CfExecute"])
        result = analyze(session, binary="t.dll", arch="x", platform="p")
        info = next(f for f in result if f.category == "cloud_files_import")
        self.assertEqual(info.evidence[0].kind, "import_table")

    def test_high_evidence_kind(self):
        session = MockSession(["CfExecute"])
        result = analyze(
            session,
            findings=[_sddl()],
            binary="t.dll", arch="x", platform="p",
        )
        high = next(f for f in result if f.category == "cloud_files_write_proxy")
        self.assertEqual(high.evidence[0].kind, "cloud_files_write_proxy_composition")


# ---------------------------------------------------------------------------
# analyze() — session attribute fallback
# ---------------------------------------------------------------------------

class TestAnalyzeSessionFallback(unittest.TestCase):

    def test_binary_from_session(self):
        session = MockSession(
            ["CfRegisterSyncRoot"],
            binary="session_binary.dll",
            arch="x86_64",
            platform="windows",
        )
        result = analyze(session)   # no explicit kwargs
        self.assertTrue(all(f.binary == "session_binary.dll" for f in result))

    def test_explicit_kwargs_override_session(self):
        session = MockSession(
            ["CfRegisterSyncRoot"],
            binary="session_binary.dll",
        )
        result = analyze(session, binary="override.dll", arch="x86", platform="w")
        self.assertTrue(all(f.binary == "override.dll" for f in result))


# ---------------------------------------------------------------------------
# CATEGORY_META completeness
# ---------------------------------------------------------------------------

class TestCategoryMeta(unittest.TestCase):

    def test_required_keys_present(self):
        for cat in ("cloud_files_import", "cloud_files_write_proxy"):
            meta = CATEGORY_META[cat]
            self.assertIn("severity",      meta)
            self.assertIn("cwe",           meta)
            self.assertIn("mitre",         meta)
            self.assertIn("knowledge_refs", meta)

    def test_high_has_cwe_367(self):
        self.assertIn("CWE-367", CATEGORY_META["cloud_files_write_proxy"]["cwe"])

    def test_high_has_t1068(self):
        self.assertIn("T1068", CATEGORY_META["cloud_files_write_proxy"]["mitre"])


if __name__ == "__main__":
    unittest.main()
