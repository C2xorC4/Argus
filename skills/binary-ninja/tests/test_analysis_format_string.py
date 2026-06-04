"""Tests for analysis/format_string.py — format string vulnerability detector.

No Binary Ninja runtime required; all MLIL helpers are monkeypatched.
"""
from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_SKILLS = Path(__file__).parent.parent
if str(_SKILLS) not in sys.path:
    sys.path.insert(0, str(_SKILLS))

for _mod in ("binaryninja",):
    if _mod not in sys.modules:
        sys.modules[_mod] = types.ModuleType(_mod)

import scripts.analysis.format_string as fmt_mod
from scripts.analysis.format_string import find_format_string_bugs
from scripts.output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Param expression helpers
# ─────────────────────────────────────────────────────────────────

def _const(value: int = 0x402000):
    """Constant expression stub — has .constant attribute (string literal addr)."""
    c = MagicMock()
    c.constant = value
    return c


def _var():
    """Variable expression stub — no .constant attribute."""
    return MagicMock(spec=[])


def _run(sink_name: str, params: list, *, addr: int = 0x1000,
         func_name: str = "victim", ssa_defn=None) -> list:
    """Run find_format_string_bugs with one mocked call site for `sink_name`."""
    bv = MagicMock()
    mlil = MagicMock()

    with patch.object(fmt_mod, "imports_in", return_value={sink_name}), \
         patch.object(fmt_mod.ilh, "call_sites_of_import",
                      return_value=[(addr, mlil)]), \
         patch.object(fmt_mod.ilh, "call_params", return_value=params), \
         patch.object(fmt_mod.ilh, "function_display_name",
                      return_value=func_name), \
         patch.object(fmt_mod.ilh, "expr_to_ssa_var",
                      return_value=MagicMock()), \
         patch.object(fmt_mod.ilh, "ssa_def_of", return_value=ssa_defn):
        return find_format_string_bugs(
            bv, binary="test.elf", arch="x86_64",
            platform="linux", detector="test",
        )


# ─────────────────────────────────────────────────────────────────
# Basic detection — userspace sinks
# ─────────────────────────────────────────────────────────────────

class TestUserspaceSinks(unittest.TestCase):

    def test_printf_variable_fmt_emits_finding(self):
        # printf(fmt_var)
        results = _run("printf", [_var()])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].category, "format_string")

    def test_printf_string_literal_no_finding(self):
        # printf(0x402000) — constant → .rodata string literal
        results = _run("printf", [_const()])
        self.assertEqual(len(results), 0)

    def test_fprintf_variable_fmt_emits_finding(self):
        # fprintf(stderr, fmt_var) — fmt at idx=1
        results = _run("fprintf", [_var(), _var()])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].details["sink_name"], "fprintf")

    def test_fprintf_literal_fmt_no_finding(self):
        results = _run("fprintf", [_var(), _const()])
        self.assertEqual(len(results), 0)

    def test_sprintf_variable_fmt_emits_finding(self):
        # sprintf(buf, fmt_var) — fmt at idx=1
        results = _run("sprintf", [_var(), _var()])
        self.assertEqual(len(results), 1)

    def test_snprintf_variable_fmt_emits_finding(self):
        # snprintf(buf, size, fmt_var) — fmt at idx=2
        results = _run("snprintf", [_var(), _const(128), _var()])
        self.assertEqual(len(results), 1)

    def test_snprintf_literal_fmt_no_finding(self):
        results = _run("snprintf", [_var(), _const(128), _const()])
        self.assertEqual(len(results), 0)

    def test_vprintf_variable_fmt_emits_finding(self):
        results = _run("vprintf", [_var(), _var()])
        self.assertEqual(len(results), 1)

    def test_dprintf_variable_fmt_emits_finding(self):
        # dprintf(fd, fmt_var) — fmt at idx=1
        results = _run("dprintf", [_var(), _var()])
        self.assertEqual(len(results), 1)


# ─────────────────────────────────────────────────────────────────
# Kernel logging sinks
# ─────────────────────────────────────────────────────────────────

class TestKernelLoggingSinks(unittest.TestCase):

    def test_printk_variable_fmt_emits_finding(self):
        # printk(fmt_var) — fmt at idx=0
        results = _run("printk", [_var()])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].details["sink_name"], "printk")

    def test_printk_literal_fmt_no_finding(self):
        results = _run("printk", [_const()])
        self.assertEqual(len(results), 0)

    def test_dev_err_variable_fmt_emits_finding(self):
        # dev_err(dev, fmt_var) — fmt at idx=1
        results = _run("dev_err", [_var(), _var()])
        self.assertEqual(len(results), 1)

    def test_dev_warn_literal_fmt_no_finding(self):
        results = _run("dev_warn", [_var(), _const()])
        self.assertEqual(len(results), 0)

    def test_pr_err_variable_fmt_emits_finding(self):
        # pr_err(fmt_var) — fmt at idx=0
        results = _run("pr_err", [_var()])
        self.assertEqual(len(results), 1)


# ─────────────────────────────────────────────────────────────────
# Guard conditions
# ─────────────────────────────────────────────────────────────────

class TestGuardConditions(unittest.TestCase):

    def test_mlil_none_no_finding(self):
        bv = MagicMock()
        with patch.object(fmt_mod, "imports_in", return_value={"printf"}), \
             patch.object(fmt_mod.ilh, "call_sites_of_import",
                          return_value=[(0x1000, None)]):
            results = find_format_string_bugs(
                bv, binary="test.elf", arch="x86_64",
                platform="linux", detector="test",
            )
        self.assertEqual(len(results), 0)

    def test_fmt_idx_out_of_range_no_finding(self):
        # snprintf needs 3 params; only 2 given → fmt_idx=2 out of range
        results = _run("snprintf", [_var(), _var()])
        self.assertEqual(len(results), 0)

    def test_sink_not_imported_no_finding(self):
        bv = MagicMock()
        with patch.object(fmt_mod, "imports_in", return_value=set()):
            results = find_format_string_bugs(
                bv, binary="test.elf", arch="x86_64",
                platform="linux", detector="test",
            )
        self.assertEqual(len(results), 0)


# ─────────────────────────────────────────────────────────────────
# Evidence — taint origin via SSA def walk
# ─────────────────────────────────────────────────────────────────

class TestEvidenceTaintOrigin(unittest.TestCase):

    def test_ssa_def_present_adds_evidence(self):
        fake_defn = MagicMock()
        fake_defn.__str__ = lambda self: "arg0#0 = param_fmt"
        results = _run("printf", [_var()], ssa_defn=fake_defn)
        self.assertEqual(len(results), 1)
        self.assertTrue(any("taint origin" in e for e in results[0].evidence))

    def test_no_ssa_def_empty_evidence(self):
        results = _run("printf", [_var()], ssa_defn=None)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].evidence, [])


# ─────────────────────────────────────────────────────────────────
# Finding shape
# ─────────────────────────────────────────────────────────────────

class TestFindingShape(unittest.TestCase):

    def test_cwe_134(self):
        results = _run("printf", [_var()])
        self.assertIn("CWE-134", results[0].cwe)

    def test_severity_high(self):
        results = _run("printf", [_var()])
        self.assertEqual(results[0].severity, Severity.HIGH)

    def test_cia_impact_confidentiality_and_integrity(self):
        results = _run("printf", [_var()])
        self.assertIn("C", results[0].cia_impact)
        self.assertIn("I", results[0].cia_impact)

    def test_detection_altitude_ttp(self):
        results = _run("printf", [_var()])
        self.assertEqual(results[0].detection_altitude, "ttp")

    def test_address_matches_call_site(self):
        results = _run("printf", [_var()], addr=0xBEEF)
        self.assertEqual(results[0].address, 0xBEEF)

    def test_category_format_string(self):
        results = _run("printf", [_var()])
        self.assertEqual(results[0].category, "format_string")


if __name__ == "__main__":
    unittest.main()
