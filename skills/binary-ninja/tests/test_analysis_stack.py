"""Tests for analysis/stack.py — stack buffer overflow detector.

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

import scripts.analysis.stack as stack_mod
from scripts.analysis.stack import find_stack_overflow, _is_crt_internal
from scripts.output.finding import Severity


# ─────────────────────────────────────────────────────────────────
# Param expression helpers
# ─────────────────────────────────────────────────────────────────

def _const(value: int):
    """MLIL constant expression stub — has .constant attribute."""
    c = MagicMock()
    c.constant = value
    return c


def _var():
    """MLIL variable expression stub — no .constant attribute."""
    return MagicMock(spec=[])


def _run(sink_name: str, params: list, *, is_stack: bool = True,
         func_name: str = "victim", addr: int = 0x1000) -> list:
    """Run find_stack_overflow with one mocked call site for `sink_name`.

    All MLIL IL-helper calls are patched; only the decision logic in
    find_stack_overflow() is exercised.
    """
    bv = MagicMock()
    mlil = MagicMock()

    with patch.object(stack_mod, "imports_in", return_value={sink_name}), \
         patch.object(stack_mod.ilh, "call_sites_of_import",
                      return_value=[(addr, mlil)]), \
         patch.object(stack_mod.ilh, "call_params", return_value=params), \
         patch.object(stack_mod.ilh, "expr_to_ssa_var",
                      return_value=MagicMock()), \
         patch.object(stack_mod.ilh, "function_display_name",
                      return_value=func_name), \
         patch.object(stack_mod.ilh, "resolves_to_stack_variable",
                      return_value=is_stack):
        return find_stack_overflow(
            bv, binary="test.dll", arch="x86_64",
            platform="linux", detector="test",
        )


# ─────────────────────────────────────────────────────────────────
# _is_crt_internal
# ─────────────────────────────────────────────────────────────────

class TestIsCrtInternal(unittest.TestCase):

    def test_mingw_prefix(self):
        self.assertTrue(_is_crt_internal("__mingw_vsprintf"))

    def test_scrt_prefix(self):
        self.assertTrue(_is_crt_internal("__scrt_uninitialize_crt"))

    def test_crt_prefix(self):
        self.assertTrue(_is_crt_internal("__crt_stdio_output"))

    def test_chkstk(self):
        self.assertTrue(_is_crt_internal("__chkstk"))

    def test_normal_function(self):
        self.assertFalse(_is_crt_internal("victim"))

    def test_empty_name(self):
        self.assertFalse(_is_crt_internal(""))


# ─────────────────────────────────────────────────────────────────
# Unbounded sinks
# ─────────────────────────────────────────────────────────────────

class TestUnboundedSinks(unittest.TestCase):

    def test_gets_stack_dst_emits_finding(self):
        results = _run("gets", [_var()])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].category, "stack_buffer_overflow")

    def test_gets_heap_dst_no_finding(self):
        results = _run("gets", [_var()], is_stack=False)
        self.assertEqual(len(results), 0)

    def test_sprintf_stack_dst_emits_finding(self):
        results = _run("sprintf", [_var(), _const(0x402000), _var()])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].details["sink_name"], "sprintf")

    def test_vsprintf_stack_dst_emits_finding(self):
        results = _run("vsprintf", [_var(), _const(0x402000)])
        self.assertEqual(len(results), 1)

    def test_gets_empty_params_no_finding(self):
        results = _run("gets", [])
        self.assertEqual(len(results), 0)

    def test_gets_mlil_none_no_finding(self):
        bv = MagicMock()
        with patch.object(stack_mod, "imports_in", return_value={"gets"}), \
             patch.object(stack_mod.ilh, "call_sites_of_import",
                          return_value=[(0x1000, None)]):
            results = find_stack_overflow(
                bv, binary="test.dll", arch="x86_64",
                platform="linux", detector="test",
            )
        self.assertEqual(len(results), 0)

    def test_gets_dst_ssa_none_no_finding(self):
        """expr_to_ssa_var returns None → skipped."""
        bv = MagicMock()
        mlil = MagicMock()
        with patch.object(stack_mod, "imports_in", return_value={"gets"}), \
             patch.object(stack_mod.ilh, "call_sites_of_import",
                          return_value=[(0x1000, mlil)]), \
             patch.object(stack_mod.ilh, "call_params", return_value=[_var()]), \
             patch.object(stack_mod.ilh, "expr_to_ssa_var", return_value=None), \
             patch.object(stack_mod.ilh, "function_display_name",
                          return_value="victim"):
            results = find_stack_overflow(
                bv, binary="test.dll", arch="x86_64",
                platform="linux", detector="test",
            )
        self.assertEqual(len(results), 0)

    def test_sink_not_imported_no_finding(self):
        bv = MagicMock()
        with patch.object(stack_mod, "imports_in", return_value=set()):
            results = find_stack_overflow(
                bv, binary="test.dll", arch="x86_64",
                platform="linux", detector="test",
            )
        self.assertEqual(len(results), 0)


# ─────────────────────────────────────────────────────────────────
# Bounded sinks — no length argument (strcpy / strcat family)
# ─────────────────────────────────────────────────────────────────

class TestBoundedSinksNoLength(unittest.TestCase):

    def test_strcpy_stack_dst_emits_finding(self):
        results = _run("strcpy", [_var(), _var()])
        self.assertEqual(len(results), 1)
        self.assertIn("no length argument", results[0].description)

    def test_strcat_stack_dst_emits_finding(self):
        results = _run("strcat", [_var(), _var()])
        self.assertEqual(len(results), 1)
        self.assertIn("no length argument", results[0].description)

    def test_wcscpy_stack_dst_emits_finding(self):
        results = _run("wcscpy", [_var(), _var()])
        self.assertEqual(len(results), 1)

    def test_strcpy_heap_dst_no_finding(self):
        results = _run("strcpy", [_var(), _var()], is_stack=False)
        self.assertEqual(len(results), 0)

    def test_lstrcpyA_stack_dst_emits_finding(self):
        results = _run("lstrcpyA", [_var(), _var()])
        self.assertEqual(len(results), 1)


# ─────────────────────────────────────────────────────────────────
# Bounded sinks — with length argument
# ─────────────────────────────────────────────────────────────────

class TestBoundedSinksWithLength(unittest.TestCase):

    def test_memcpy_constant_safe_length_no_finding(self):
        results = _run("memcpy", [_var(), _var(), _const(512)])
        self.assertEqual(len(results), 0)

    def test_memcpy_constant_at_threshold_no_finding(self):
        # Exactly at threshold (4096) → still safe
        results = _run("memcpy", [_var(), _var(), _const(4096)])
        self.assertEqual(len(results), 0)

    def test_memcpy_constant_exceeds_threshold_emits_finding(self):
        results = _run("memcpy", [_var(), _var(), _const(8192)])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].details["sink_name"], "memcpy")

    def test_memcpy_variable_length_emits_finding(self):
        results = _run("memcpy", [_var(), _var(), _var()])
        self.assertEqual(len(results), 1)
        self.assertIn("non-constant", results[0].description)

    def test_memcpy_missing_length_arg_emits_finding(self):
        # Only dst + src provided, len index out of range
        results = _run("memcpy", [_var(), _var()])
        self.assertEqual(len(results), 1)
        self.assertIn("length argument missing", results[0].description)

    def test_memcpy_heap_dst_no_finding(self):
        results = _run("memcpy", [_var(), _var(), _var()], is_stack=False)
        self.assertEqual(len(results), 0)

    def test_read_stack_dst_variable_len_emits_finding(self):
        # read(fd, buf, count) — buf idx=1, count idx=2
        results = _run("read", [_var(), _var(), _var()])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].details["sink_name"], "read")

    def test_recv_stack_dst_variable_len_emits_finding(self):
        # recv(sockfd, buf, len, flags) — buf idx=1, len idx=2
        results = _run("recv", [_var(), _var(), _var(), _var()])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].details["sink_name"], "recv")

    def test_fgets_constant_len_no_finding(self):
        # fgets(str, num, stream) — num idx=1
        results = _run("fgets", [_var(), _const(256), _var()])
        self.assertEqual(len(results), 0)

    def test_strncpy_constant_safe_len_no_finding(self):
        results = _run("strncpy", [_var(), _var(), _const(64)])
        self.assertEqual(len(results), 0)

    def test_snprintf_constant_size_no_finding(self):
        # snprintf(dst, size, fmt, ...) — size idx=1
        results = _run("snprintf", [_var(), _const(128), _var()])
        self.assertEqual(len(results), 0)

    def test_snprintf_variable_size_emits_finding(self):
        results = _run("snprintf", [_var(), _var(), _var()])
        self.assertEqual(len(results), 1)

    def test_memmove_variable_len_emits_finding(self):
        results = _run("memmove", [_var(), _var(), _var()])
        self.assertEqual(len(results), 1)


# ─────────────────────────────────────────────────────────────────
# CRT internal suppression
# ─────────────────────────────────────────────────────────────────

class TestCrtSuppression(unittest.TestCase):

    def test_crt_prefix_gets_suppressed(self):
        results = _run("gets", [_var()], func_name="__crt_internal_func")
        self.assertEqual(len(results), 0)

    def test_mingw_prefix_suppressed(self):
        results = _run("memcpy", [_var(), _var(), _var()],
                       func_name="__mingw_memcpy_impl")
        self.assertEqual(len(results), 0)

    def test_non_crt_function_not_suppressed(self):
        results = _run("gets", [_var()], func_name="vulnerable_function")
        self.assertEqual(len(results), 1)


# ─────────────────────────────────────────────────────────────────
# Finding shape
# ─────────────────────────────────────────────────────────────────

class TestFindingShape(unittest.TestCase):

    def test_cwe_121(self):
        results = _run("gets", [_var()])
        self.assertIn("CWE-121", results[0].cwe)

    def test_severity_high(self):
        results = _run("gets", [_var()])
        self.assertEqual(results[0].severity, Severity.HIGH)

    def test_cia_impact_contains_integrity(self):
        results = _run("gets", [_var()])
        self.assertIn("I", results[0].cia_impact)

    def test_detection_altitude_ttp(self):
        results = _run("gets", [_var()])
        self.assertEqual(results[0].detection_altitude, "ttp")

    def test_address_matches_call_site(self):
        results = _run("gets", [_var()], addr=0xDEAD)
        self.assertEqual(results[0].address, 0xDEAD)

    def test_category_stack_buffer_overflow(self):
        results = _run("strcpy", [_var(), _var()])
        self.assertEqual(results[0].category, "stack_buffer_overflow")


if __name__ == "__main__":
    unittest.main()
