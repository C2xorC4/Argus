"""Unit tests for heuristics/chains.py — chain composition + ChainPattern.

Coverage:
  Fix 2.5 — min_per_primitive gate on UE5_PRNG_COOKIE_AMPLIFICATION:
    1 weak_prng_in_security_path finding → chain must NOT fire
    2 findings → must NOT fire
    3 findings → must fire
    4+ findings → must fire
  context_gate — UE5 binary discriminator:
    bv=None (unit-test mode) → gate bypassed, chain composition logic tested
    mock bv with UE5 strings → chain fires at ≥3 PRNG findings
    mock bv without UE5 strings → chain suppressed regardless of PRNG count
  min_per_primitive=None on other chains — match() unaffected
  ChainPattern.min_per_primitive field exists and defaults to None
  ChainPattern.context_gate field exists and defaults to empty frozenset
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SCRIPTS = Path(__file__).parent.parent / "scripts"
if str(_SCRIPTS.parent) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS.parent))

from scripts.heuristics._base import ChainPattern
from scripts.output.finding import Severity
from scripts.heuristics.chains import (
    match,
    UE5_PRNG_COOKIE_AMPLIFICATION,
    _binary_has_tag,
)


# ---------------------------------------------------------------------------
# Minimal finding stub (mirrors what analysis modules produce)
# ---------------------------------------------------------------------------

class _F:
    def __init__(self, category: str, address: int = 0x1000,
                 function: str = "<fn>", binary: str = "t.dll",
                 arch: str = "x86_64", platform: str = "windows"):
        self.category = category
        self.address  = address
        self.function = function
        self.binary   = binary
        self.arch     = arch
        self.platform = platform
        self.id       = ""


def _prng(n: int = 1) -> list:
    return [_F("weak_prng_in_security_path") for _ in range(n)]


# ---------------------------------------------------------------------------
# ChainPattern field check
# ---------------------------------------------------------------------------

class TestChainPatternField(unittest.TestCase):

    def test_min_per_primitive_field_exists(self):
        """ChainPattern must have min_per_primitive with a default of None."""
        cp = ChainPattern(
            name="test.chain",
            description="test",
            severity=Severity.INFO,
            category="test_cat",
            primitives=["foo"],
        )
        self.assertIsNone(cp.min_per_primitive)

    def test_context_gate_field_exists(self):
        """ChainPattern must have context_gate defaulting to empty frozenset."""
        cp = ChainPattern(
            name="test.chain",
            description="test",
            severity=Severity.INFO,
            category="test_cat",
            primitives=["foo"],
        )
        self.assertIsInstance(cp.context_gate, frozenset)
        self.assertEqual(len(cp.context_gate), 0)

    def test_ue5_chain_has_context_gate(self):
        """UE5 chain must carry the ue5_binary context gate."""
        self.assertIn("ue5_binary", UE5_PRNG_COOKIE_AMPLIFICATION.context_gate)

    def test_min_per_primitive_accepts_dict(self):
        cp = ChainPattern(
            name="test.chain",
            description="test",
            severity=Severity.INFO,
            category="test_cat",
            primitives=["foo"],
            min_per_primitive={"foo": 3},
        )
        self.assertEqual(cp.min_per_primitive, {"foo": 3})

    def test_ue5_chain_has_min_per_primitive(self):
        self.assertIsNotNone(UE5_PRNG_COOKIE_AMPLIFICATION.min_per_primitive)
        self.assertIn("weak_prng_in_security_path",
                      UE5_PRNG_COOKIE_AMPLIFICATION.min_per_primitive)
        self.assertEqual(
            UE5_PRNG_COOKIE_AMPLIFICATION.min_per_primitive["weak_prng_in_security_path"],
            3,
        )


# ---------------------------------------------------------------------------
# UE5_PRNG_COOKIE_AMPLIFICATION — min_per_primitive gate (Fix 2.5)
# ---------------------------------------------------------------------------

class TestUe5ChainGate(unittest.TestCase):

    def _run(self, findings: list) -> list:
        return match(
            None,
            binary="game.exe", arch="x86_64", platform="windows",
            existing_findings=findings,
        )

    def _ue5_fired(self, result: list) -> bool:
        return any(f.category == "chain_pattern" and
                   "ue5" in f.description.lower()
                   for f in result)

    def test_zero_prng_findings_no_chain(self):
        result = self._run([])
        self.assertFalse(self._ue5_fired(result))

    def test_one_prng_finding_no_chain(self):
        """Single weak_prng_in_security_path must NOT trigger UE5 chain."""
        result = self._run(_prng(1))
        self.assertFalse(self._ue5_fired(result))

    def test_two_prng_findings_no_chain(self):
        """Two findings still below threshold — must NOT fire."""
        result = self._run(_prng(2))
        self.assertFalse(self._ue5_fired(result))

    def test_three_prng_findings_fires(self):
        """Three findings meets min_per_primitive=3 — chain must fire."""
        result = self._run(_prng(3))
        self.assertTrue(self._ue5_fired(result))

    def test_four_prng_findings_fires(self):
        result = self._run(_prng(4))
        self.assertTrue(self._ue5_fired(result))

    def test_chain_category_correct(self):
        result = self._run(_prng(3))
        chain_findings = [f for f in result if "ue5" in f.description.lower()]
        self.assertEqual(chain_findings[0].category, "chain_pattern")

    def test_chain_inherits_binary_from_anchor(self):
        findings = [_F("weak_prng_in_security_path", binary="custom.exe") for _ in range(3)]
        result = self._run(findings)
        chain_findings = [f for f in result if "ue5" in f.description.lower()]
        self.assertEqual(chain_findings[0].binary, "custom.exe")


# ---------------------------------------------------------------------------
# Other chains — min_per_primitive=None path unaffected (regression guard)
# ---------------------------------------------------------------------------

class TestOtherChainUnaffected(unittest.TestCase):

    def test_chains_without_min_per_primitive_still_run(self):
        """Non-UE5 chains with no min_per_primitive must not break."""
        # Inject a finding for a category that doesn't map to any chain —
        # match() should return an empty list without raising.
        result = match(
            None,
            binary="t.dll", arch="x86_64", platform="windows",
            existing_findings=[_F("nonexistent_category")],
        )
        self.assertIsInstance(result, list)

    def test_match_none_findings_returns_empty(self):
        result = match(None, binary="t.dll", arch="x", platform="p",
                       existing_findings=None)
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# context_gate — UE5 binary discriminator
# ---------------------------------------------------------------------------


class _MockBv:
    """Minimal BinaryView stub for context-gate tests."""

    def __init__(self, string_list: list[str]):
        # strings_in() expects objects with .value and .start attributes,
        # but our implementation falls back to str(s) — use plain strings.
        self._strings = string_list

    @property
    def strings(self):
        return [_MockStr(s) for s in self._strings]


class _MockStr:
    def __init__(self, value: str):
        self.value = value
        self.start = 0
        self.length = len(value)

    def __str__(self):
        return self.value


class TestContextGateBinaryTagHelper(unittest.TestCase):

    def test_none_bv_returns_true(self):
        """bv=None must bypass the gate (unit-test / no-bv mode)."""
        self.assertTrue(_binary_has_tag(None, "ue5_binary"))

    def test_unknown_tag_fails_closed(self):
        """An unrecognised tag with a real bv must return False."""
        bv = _MockBv(["Unreal Engine", "UObject"])
        self.assertFalse(_binary_has_tag(bv, "unknown_tag"))

    def test_ue5_tag_present_on_ue5_strings(self):
        # All markers must be ≥6 chars to clear the strings_in min_length filter.
        for marker in ("Unreal Engine", "UObject", "FString", "TArray",
                       "FMath::", "/Game/", ".uasset", "Epic Games",
                       "FName::", "GEngine", "UnrealEngine", "UnrealEditor"):
            with self.subTest(marker=marker):
                bv = _MockBv([marker])
                self.assertTrue(_binary_has_tag(bv, "ue5_binary"),
                                f"marker {marker!r} should set ue5_binary tag")

    def test_ue5_tag_absent_on_non_ue5_binary(self):
        """A system binary string table must NOT set the ue5_binary tag."""
        bv = _MockBv(["IsItemKeyFocused", "IsDeleteKeyInvokedInSearch",
                      "HandleAccessKeyMessages", "taskmgr.exe",
                      "Windows Task Manager"])
        self.assertFalse(_binary_has_tag(bv, "ue5_binary"))

    def test_ue5_tag_absent_on_empty_strings(self):
        bv = _MockBv([])
        self.assertFalse(_binary_has_tag(bv, "ue5_binary"))


class TestContextGateInMatch(unittest.TestCase):
    """End-to-end: the UE5 chain must be suppressed on non-game binaries."""

    def _run_with_bv(self, bv, findings: list) -> list:
        return match(
            bv,
            binary="target.exe", arch="x86_64", platform="windows",
            existing_findings=findings,
        )

    def _ue5_fired(self, result: list) -> bool:
        return any(f.category == "chain_pattern" and
                   "ue5" in f.description.lower()
                   for f in result)

    def test_non_ue5_bv_suppresses_chain(self):
        """3+ PRNG findings on a non-UE5 binary must NOT fire the chain."""
        bv = _MockBv(["IsItemKeyFocused", "taskmgr.exe"])
        result = self._run_with_bv(bv, _prng(3))
        self.assertFalse(self._ue5_fired(result))

    def test_non_ue5_bv_suppresses_chain_at_high_count(self):
        """46 PRNG findings (taskmgr.exe shape) must NOT fire the chain."""
        bv = _MockBv(["IsItemKeyFocused", "IsDeleteKeyInvokedInSearch",
                      "HandleAccessKeyMessages"])
        result = self._run_with_bv(bv, _prng(46))
        self.assertFalse(self._ue5_fired(result))

    def test_ue5_bv_fires_chain(self):
        """3+ PRNG findings on a UE5 binary MUST fire the chain."""
        bv = _MockBv(["UObject", "FString", "Unreal Engine"])
        result = self._run_with_bv(bv, _prng(3))
        self.assertTrue(self._ue5_fired(result))

    def test_ue5_bv_respects_min_per_primitive(self):
        """UE5 binary + <3 PRNG findings must still NOT fire (count gate)."""
        bv = _MockBv(["UObject", "FString"])
        result = self._run_with_bv(bv, _prng(2))
        self.assertFalse(self._ue5_fired(result))

    def test_none_bv_still_fires_at_threshold(self):
        """bv=None must bypass context gate — chain composition tests pass."""
        result = self._run_with_bv(None, _prng(3))
        self.assertTrue(self._ue5_fired(result))


if __name__ == "__main__":
    unittest.main()
