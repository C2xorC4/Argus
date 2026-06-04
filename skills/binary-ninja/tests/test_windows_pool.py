"""Tests for Group E — Windows kernel pool exploitation.

Covers:
- Pool allocators added to SINKS with alloc_size class
- ALLOC_FUNCTIONS dict in heap.py auto-includes pool allocators
- DEPRECATED_POOL_API_PATTERN fires on ExAllocatePool/WithQuota imports
- Pattern is suppressed for ntoskrnl / hal / ntdll module names
- kernel_deprecated_pool_api is registered in CATEGORY_TO_PRIMITIVE_KIND
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

_SKILLS = Path(__file__).parent.parent
if str(_SKILLS) not in sys.path:
    sys.path.insert(0, str(_SKILLS))

for _mod in ("binaryninja",):
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

import scripts.heuristics.imports as imports_mod
from scripts.heuristics.imports import (
    SINKS,
    DEPRECATED_POOL_API_PATTERN,
    PATTERNS,
    match,
)
from scripts.analysis.heap import ALLOC_FUNCTIONS
from scripts.exploit.primitives import CATEGORY_TO_PRIMITIVE_KIND
from scripts.output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# SINKS table — pool allocators present
# ─────────────────────────────────────────────────────────────────

class TestSinksPoolAllocators(unittest.TestCase):
    """Pool allocators must be in SINKS with alloc_size class."""

    def _sink_entry(self, name: str):
        return next(((n, idx, klass) for (n, idx, klass) in SINKS if n == name), None)

    def test_ExAllocatePool_in_sinks(self):
        entry = self._sink_entry("ExAllocatePool")
        self.assertIsNotNone(entry)
        self.assertEqual(entry[2], "alloc_size")

    def test_ExAllocatePoolWithTag_in_sinks(self):
        entry = self._sink_entry("ExAllocatePoolWithTag")
        self.assertIsNotNone(entry)
        self.assertEqual(entry[2], "alloc_size")

    def test_ExAllocatePool2_in_sinks(self):
        entry = self._sink_entry("ExAllocatePool2")
        self.assertIsNotNone(entry)
        self.assertEqual(entry[2], "alloc_size")

    def test_ExAllocatePoolWithQuota_in_sinks(self):
        entry = self._sink_entry("ExAllocatePoolWithQuota")
        self.assertIsNotNone(entry)
        self.assertEqual(entry[2], "alloc_size")

    def test_pool_size_arg_index_is_1(self):
        """All pool allocators have NumberOfBytes at index 1."""
        pool_names = [
            "ExAllocatePool", "ExAllocatePoolWithTag",
            "ExAllocatePoolWithTagPriority", "ExAllocatePool2",
            "ExAllocatePool3", "ExAllocatePoolWithQuota",
            "ExAllocatePoolWithQuotaTag",
        ]
        for name in pool_names:
            with self.subTest(name=name):
                entry = next(
                    ((n, idx, klass) for (n, idx, klass) in SINKS if n == name),
                    None,
                )
                self.assertIsNotNone(entry, f"{name} not found in SINKS")
                self.assertEqual(entry[1], 1,
                                 f"{name}: expected size at index 1, got {entry[1]}")


# ─────────────────────────────────────────────────────────────────
# ALLOC_FUNCTIONS — pool allocators auto-included via filter
# ─────────────────────────────────────────────────────────────────

class TestAllocFunctionsPoolInclusion(unittest.TestCase):
    """heap.py ALLOC_FUNCTIONS must include pool allocators after SINKS update."""

    def test_ExAllocatePoolWithTag_in_alloc_functions(self):
        self.assertIn("ExAllocatePoolWithTag", ALLOC_FUNCTIONS)

    def test_ExAllocatePool_in_alloc_functions(self):
        self.assertIn("ExAllocatePool", ALLOC_FUNCTIONS)

    def test_ExAllocatePoolWithQuotaTag_in_alloc_functions(self):
        self.assertIn("ExAllocatePoolWithQuotaTag", ALLOC_FUNCTIONS)

    def test_pool_alloc_size_index_propagated(self):
        self.assertEqual(ALLOC_FUNCTIONS["ExAllocatePool2"], 1)


# ─────────────────────────────────────────────────────────────────
# DEPRECATED_POOL_API_PATTERN — static shape checks
# ─────────────────────────────────────────────────────────────────

class TestDeprecatedPoolPattern(unittest.TestCase):

    def test_category_is_kernel_deprecated_pool_api(self):
        self.assertEqual(DEPRECATED_POOL_API_PATTERN.category,
                         "kernel_deprecated_pool_api")

    def test_severity_is_low(self):
        self.assertEqual(DEPRECATED_POOL_API_PATTERN.severity, Severity.LOW)

    def test_detection_altitude_indicator(self):
        self.assertEqual(DEPRECATED_POOL_API_PATTERN.detection_altitude, "indicator")

    def test_cwe_757(self):
        self.assertIn("CWE-757", DEPRECATED_POOL_API_PATTERN.cwe)

    def test_cia_impact_integrity(self):
        self.assertIn("I", DEPRECATED_POOL_API_PATTERN.cia_impact)

    def test_not_all_required(self):
        self.assertFalse(DEPRECATED_POOL_API_PATTERN.all_required)

    def test_import_names_include_ExAllocatePool(self):
        self.assertIn("ExAllocatePool", DEPRECATED_POOL_API_PATTERN.import_names)

    def test_pattern_in_patterns_list(self):
        self.assertIn(DEPRECATED_POOL_API_PATTERN, PATTERNS)


# ─────────────────────────────────────────────────────────────────
# imports.match() — deprecated pool API detection
# ─────────────────────────────────────────────────────────────────

def _match_with_imports(import_set: set, binary: str = "malicious_driver.sys"):
    """Run imports.match() with a mocked imports_in returning import_set."""
    bv = MagicMock()
    with patch("scripts.heuristics._base.imports_in", return_value=import_set):
        return match(
            bv, binary=binary, arch="x86_64",
            platform="windows", detector="test",
        )


class TestDeprecatedPoolMatch(unittest.TestCase):

    def test_ExAllocatePool_fires_indicator(self):
        results = _match_with_imports({"ExAllocatePool"})
        cats = [f.category for f in results]
        self.assertIn("kernel_deprecated_pool_api", cats)

    def test_ExAllocatePoolWithQuota_fires_indicator(self):
        results = _match_with_imports({"ExAllocatePoolWithQuota"})
        cats = [f.category for f in results]
        self.assertIn("kernel_deprecated_pool_api", cats)

    def test_ExAllocatePoolWithTag_alone_does_not_fire_indicator(self):
        # ExAllocatePoolWithTag is NOT in the DEPRECATED pattern's import_names
        results = _match_with_imports({"ExAllocatePoolWithTag"})
        cats = [f.category for f in results]
        self.assertNotIn("kernel_deprecated_pool_api", cats)

    def test_no_pool_import_no_indicator(self):
        results = _match_with_imports({"malloc", "free"})
        cats = [f.category for f in results]
        self.assertNotIn("kernel_deprecated_pool_api", cats)

    def test_ntoskrnl_binary_suppressed(self):
        results = _match_with_imports({"ExAllocatePool"}, binary="ntoskrnl.exe")
        cats = [f.category for f in results]
        self.assertNotIn("kernel_deprecated_pool_api", cats)

    def test_hal_binary_suppressed(self):
        results = _match_with_imports({"ExAllocatePool"}, binary="hal.dll")
        cats = [f.category for f in results]
        self.assertNotIn("kernel_deprecated_pool_api", cats)

    def test_third_party_driver_fires(self):
        results = _match_with_imports({"ExAllocatePool"}, binary="vulnerable_driver.sys")
        cats = [f.category for f in results]
        self.assertIn("kernel_deprecated_pool_api", cats)


# ─────────────────────────────────────────────────────────────────
# Primitives map — kernel_deprecated_pool_api registered
# ─────────────────────────────────────────────────────────────────

class TestPrimitivesMapRegistration(unittest.TestCase):

    def test_kernel_deprecated_pool_api_in_map(self):
        self.assertIn("kernel_deprecated_pool_api", CATEGORY_TO_PRIMITIVE_KIND)

    def test_maps_to_correct_kind(self):
        self.assertEqual(
            CATEGORY_TO_PRIMITIVE_KIND["kernel_deprecated_pool_api"],
            "kernel_deprecated_pool_api",
        )


if __name__ == "__main__":
    unittest.main()
