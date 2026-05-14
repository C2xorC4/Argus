"""Unit tests for analysis/composition.py — cross-detector composition.

Coverage:
  _imported_function_names:
    empty bv → empty frozenset
    bv with imports → names returned
    get_symbols_of_type TypeError → fallback to bv.symbols.values()
    None bv → empty frozenset

  compose_cross_binary (v2 cross-binary reachability):
    A has SDDL, B has TOCTOU, A imports B's fn → cross_binary finding emitted
    A has SDDL, B has TOCTOU, A does NOT import B's fn → nothing emitted
    same binary in both slots → no self-composition
    cluster < 2 entries → empty result
    details fields: sddl_binary, toctou_binary, bridge, lpe_class
    deduplication: same (A, B, toctou_addr) emitted only once
    3-binary cluster: correct pairings only
    NDE-shape: MpSvc-class SDDL → MpClient-class TOCTOU via import

  analyze() peer_cluster:
    no peer_cluster → same-binary compose only
    with peer_cluster → same-binary + cross-binary results combined

  _toctou_payload (module-level):
    finding with evidence → payload extracted
    finding without evidence → empty string

  CATEGORY_META completeness:
    cross_binary_remote_callable_toctou has required keys
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS.parent))

from scripts.analysis.composition import (
    _imported_function_names,
    _toctou_payload,
    compose_cross_binary,
    analyze,
    CATEGORY_META,
)


# ---------------------------------------------------------------------------
# Mocks
# ---------------------------------------------------------------------------

class _Sym:
    def __init__(self, name: str):
        self.name = name


class MockBV:
    def __init__(self, import_names: list[str]):
        self.symbols = {n: _Sym(n) for n in import_names}

    def get_symbols_of_type(self, *_):
        raise TypeError("mock — triggers fallback")


class MockEvidence:
    def __init__(self, payload: str):
        self.payload = payload


class MockFinding:
    def __init__(self, category: str, function: str = "<fn>",
                 address: int = 0x1000, binary: str = "t.dll",
                 evidence: list = None):
        self.category = category
        self.function = function
        self.address = address
        self.binary = binary
        self.id = ""
        self.evidence = evidence or []
        self.details = {}
        self.arch = "x86_64"
        self.platform = "windows"


def _sddl(fn="MpComInitializeSecurity", binary="A.dll"):
    return MockFinding("permissive_sddl", function=fn, address=0x2000,
                       binary=binary)


def _toctou(fn="MpIsPathSymlink", binary="B.dll", addr=0x3000):
    return MockFinding("toctou", function=fn, address=addr, binary=binary)


def _make_cluster(bv_a, findings_a, bv_b, findings_b,
                  bin_a="A.dll", bin_b="B.dll"):
    return [
        {"bv": bv_a, "binary": bin_a, "arch": "x86_64",
         "platform": "windows", "findings": findings_a},
        {"bv": bv_b, "binary": bin_b, "arch": "x86_64",
         "platform": "windows", "findings": findings_b},
    ]


# ---------------------------------------------------------------------------
# _imported_function_names
# ---------------------------------------------------------------------------

class TestImportedFunctionNames(unittest.TestCase):

    def test_none_bv_returns_empty(self):
        result = _imported_function_names(None)
        self.assertEqual(result, frozenset())

    def test_empty_bv_returns_empty(self):
        bv = MockBV([])
        self.assertEqual(_imported_function_names(bv), frozenset())

    def test_names_returned(self):
        bv = MockBV(["MpIsPathSymlink", "CreateFileW", "NtCreateFile"])
        result = _imported_function_names(bv)
        self.assertIn("MpIsPathSymlink", result)
        self.assertIn("CreateFileW", result)

    def test_result_is_frozenset(self):
        bv = MockBV(["Foo", "Bar"])
        self.assertIsInstance(_imported_function_names(bv), frozenset)

    def test_get_symbols_raises_falls_back(self):
        """MockBV.get_symbols_of_type raises TypeError → fallback used."""
        bv = MockBV(["SomeFunc"])
        result = _imported_function_names(bv)
        self.assertIn("SomeFunc", result)


# ---------------------------------------------------------------------------
# _toctou_payload
# ---------------------------------------------------------------------------

class TestToctouPayload(unittest.TestCase):

    def test_no_evidence_returns_empty(self):
        f = MockFinding("toctou")
        self.assertEqual(_toctou_payload(f), "")

    def test_evidence_payload_concatenated(self):
        f = MockFinding("toctou", evidence=[
            MockEvidence("PathFileExistsW -> CreateFileW"),
            MockEvidence("0x1234"),
        ])
        payload = _toctou_payload(f)
        self.assertIn("PathFileExistsW", payload)
        self.assertIn("CreateFileW", payload)

    def test_none_evidence_attr(self):
        f = MockFinding("toctou")
        f.evidence = None
        self.assertEqual(_toctou_payload(f), "")


# ---------------------------------------------------------------------------
# compose_cross_binary — main composition logic
# ---------------------------------------------------------------------------

class TestComposeCrossBinaryBasic(unittest.TestCase):

    def test_empty_cluster_returns_empty(self):
        self.assertEqual(compose_cross_binary([]), [])

    def test_single_entry_returns_empty(self):
        cluster = [{"bv": MockBV([]), "binary": "A.dll", "arch": "x86_64",
                    "platform": "windows", "findings": [_sddl()]}]
        self.assertEqual(compose_cross_binary(cluster), [])

    def test_match_emits_finding(self):
        """A imports B's TOCTOU function → finding emitted."""
        bv_a = MockBV(["MpIsPathSymlink"])
        cluster = _make_cluster(bv_a, [_sddl()], MockBV([]), [_toctou()])
        result = compose_cross_binary(cluster)
        cats = [f.category for f in result]
        self.assertIn("cross_binary_remote_callable_toctou", cats)

    def test_no_import_match_no_finding(self):
        """A does not import B's function → nothing emitted."""
        bv_a = MockBV(["CreateFileW", "NtCreateFile"])  # no MpIsPathSymlink
        cluster = _make_cluster(bv_a, [_sddl()], MockBV([]), [_toctou()])
        result = compose_cross_binary(cluster)
        self.assertEqual(result, [])

    def test_no_sddl_in_a_no_finding(self):
        bv_a = MockBV(["MpIsPathSymlink"])
        cluster = _make_cluster(bv_a, [], MockBV([]), [_toctou()])
        self.assertEqual(compose_cross_binary(cluster), [])

    def test_no_toctou_in_b_no_finding(self):
        bv_a = MockBV(["MpIsPathSymlink"])
        cluster = _make_cluster(bv_a, [_sddl()], MockBV([]), [])
        self.assertEqual(compose_cross_binary(cluster), [])

    def test_same_binary_no_self_composition(self):
        """A and B same name → no cross-binary finding."""
        bv_a = MockBV(["MpIsPathSymlink"])
        cluster = _make_cluster(bv_a, [_sddl(binary="A.dll")],
                                MockBV([]), [_toctou(binary="A.dll")],
                                bin_a="A.dll", bin_b="A.dll")
        result = compose_cross_binary(cluster)
        self.assertEqual(result, [])


class TestComposeCrossBinaryDetails(unittest.TestCase):

    def _run(self):
        bv_a = MockBV(["MpIsPathSymlink"])
        cluster = _make_cluster(
            bv_a, [_sddl("MpComInitializeSecurity", binary="A.dll")],
            MockBV([]), [_toctou("MpIsPathSymlink", binary="B.dll", addr=0x5000)],
            bin_a="A.dll", bin_b="B.dll",
        )
        return compose_cross_binary(cluster)

    def test_sddl_binary_in_details(self):
        result = self._run()
        f = next(f for f in result
                 if f.category == "cross_binary_remote_callable_toctou")
        self.assertEqual(f.details["sddl_binary"], "A.dll")

    def test_toctou_binary_in_details(self):
        result = self._run()
        f = next(f for f in result
                 if f.category == "cross_binary_remote_callable_toctou")
        self.assertEqual(f.details["toctou_binary"], "B.dll")

    def test_bridge_field(self):
        result = self._run()
        f = next(f for f in result
                 if f.category == "cross_binary_remote_callable_toctou")
        self.assertEqual(f.details["cross_binary_bridge"],
                         "import_table_function_match")

    def test_toctou_function_in_details(self):
        result = self._run()
        f = next(f for f in result
                 if f.category == "cross_binary_remote_callable_toctou")
        self.assertEqual(f.details["toctou_function"], "MpIsPathSymlink")

    def test_evidence_kind(self):
        result = self._run()
        f = next(f for f in result
                 if f.category == "cross_binary_remote_callable_toctou")
        self.assertEqual(f.evidence[0].kind, "cross_binary_import_composition")

    def test_finding_binary_is_sddl_binary(self):
        """Finding is attributed to the SDDL binary (entry point)."""
        result = self._run()
        f = next(f for f in result
                 if f.category == "cross_binary_remote_callable_toctou")
        self.assertEqual(f.binary, "A.dll")

    def test_lpe_class_path_race(self):
        """MpIsPathSymlink → path-race shape detected."""
        bv_a = MockBV(["MpIsPathSymlink"])
        toctou = _toctou("MpIsPathSymlink", binary="B.dll")
        toctou.evidence = [MockEvidence("PathFileExistsW -> CreateFileW")]
        cluster = _make_cluster(bv_a, [_sddl()], MockBV([]), [toctou])
        result = compose_cross_binary(cluster)
        f = next(f for f in result
                 if f.category == "cross_binary_remote_callable_toctou")
        self.assertIn("path-race", f.details.get("lpe_class", ""))


class TestComposeCrossBinaryDedup(unittest.TestCase):

    def test_same_pair_emitted_once(self):
        """Multiple SDDL findings in A should not duplicate the cross-binary emit."""
        bv_a = MockBV(["MpIsPathSymlink"])
        sddl1 = _sddl("Fn1", binary="A.dll")
        sddl2 = _sddl("Fn2", binary="A.dll")
        cluster = _make_cluster(bv_a, [sddl1, sddl2], MockBV([]), [_toctou()])
        result = compose_cross_binary(cluster)
        cross = [f for f in result
                 if f.category == "cross_binary_remote_callable_toctou"]
        self.assertEqual(len(cross), 1)


class TestComposeCrossBinaryThreeBinaries(unittest.TestCase):

    def test_correct_pairings_only(self):
        """A imports B's fn but not C's; A has SDDL; B and C have TOCTOU."""
        bv_a = MockBV(["MpIsPathSymlink"])  # imports B's fn, not C's
        findings_a = [_sddl(binary="A.dll")]
        findings_b = [_toctou("MpIsPathSymlink", binary="B.dll")]
        findings_c = [_toctou("SomeOtherFn", binary="C.dll")]

        cluster = [
            {"bv": bv_a, "binary": "A.dll", "arch": "x86_64",
             "platform": "windows", "findings": findings_a},
            {"bv": MockBV([]), "binary": "B.dll", "arch": "x86_64",
             "platform": "windows", "findings": findings_b},
            {"bv": MockBV([]), "binary": "C.dll", "arch": "x86_64",
             "platform": "windows", "findings": findings_c},
        ]
        result = compose_cross_binary(cluster)
        cross = [f for f in result
                 if f.category == "cross_binary_remote_callable_toctou"]
        # Only A→B should fire (A imports MpIsPathSymlink; not SomeOtherFn)
        self.assertEqual(len(cross), 1)
        self.assertEqual(cross[0].details["toctou_binary"], "B.dll")


# ---------------------------------------------------------------------------
# analyze() peer_cluster integration
# ---------------------------------------------------------------------------

class MockSession:
    def __init__(self, bv):
        self.bv = bv
        self.binary_path = "test.dll"
        self.arch = "x86_64"
        self.platform = "windows"


class TestAnalyzePeerCluster(unittest.TestCase):

    def test_no_peer_cluster_same_binary_only(self):
        """Without peer_cluster, analyze returns same-binary compose only."""
        session = MockSession(MockBV([]))
        result = analyze(session, [_sddl()], binary="A.dll", arch="x86_64",
                         platform="windows")
        # No toctou → no remote_callable_toctou; no peer → no cross-binary
        cross = [f for f in result
                 if f.category == "cross_binary_remote_callable_toctou"]
        self.assertEqual(cross, [])

    def test_with_peer_cluster_includes_cross_binary(self):
        """With peer_cluster, cross-binary findings are appended."""
        bv_a = MockBV(["MpIsPathSymlink"])
        session_a = MockSession(bv_a)
        findings_a = [_sddl(binary="A.dll")]
        findings_b = [_toctou(binary="B.dll")]

        cluster = [
            {"bv": bv_a, "binary": "A.dll", "arch": "x86_64",
             "platform": "windows", "findings": findings_a},
            {"bv": MockBV([]), "binary": "B.dll", "arch": "x86_64",
             "platform": "windows", "findings": findings_b},
        ]
        result = analyze(session_a, findings_a, binary="A.dll", arch="x86_64",
                         platform="windows", peer_cluster=cluster)
        cross = [f for f in result
                 if f.category == "cross_binary_remote_callable_toctou"]
        self.assertEqual(len(cross), 1)


# ---------------------------------------------------------------------------
# CATEGORY_META completeness
# ---------------------------------------------------------------------------

class TestCategoryMeta(unittest.TestCase):

    def test_cross_binary_entry_present(self):
        self.assertIn("cross_binary_remote_callable_toctou", CATEGORY_META)

    def test_cross_binary_required_keys(self):
        meta = CATEGORY_META["cross_binary_remote_callable_toctou"]
        for key in ("severity", "cwe", "mitre", "knowledge_refs"):
            self.assertIn(key, meta)

    def test_cross_binary_high_severity(self):
        from scripts.output.finding import Severity
        self.assertEqual(
            CATEGORY_META["cross_binary_remote_callable_toctou"]["severity"],
            Severity.HIGH,
        )

    def test_cross_binary_cwe367(self):
        self.assertIn("CWE-367",
                      CATEGORY_META["cross_binary_remote_callable_toctou"]["cwe"])


if __name__ == "__main__":
    unittest.main()
