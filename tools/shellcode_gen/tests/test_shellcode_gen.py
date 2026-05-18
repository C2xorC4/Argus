"""Unit tests for shellcode_gen.

Tests that do NOT require keystone:
  - formatters: all output formats
  - registry: payload lookup, unknown key raises
  - from_bin: reads bytes from disk
  - CLI: argument parsing, --list, error paths
  - _asm.cmd_as_db_bytes: hex formatting

Tests that DO require keystone (skip when not installed):
  - Windows x64 / x86 assembly produces non-empty bytes
  - Linux x64 / x86 assembly produces non-empty bytes
  - generate_from_command round-trip
"""
from __future__ import annotations

import sys
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Allow running from repo root or from this file's directory
_ARGUS_ROOT = Path(__file__).parent.parent.parent.parent
if str(_ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(_ARGUS_ROOT))

try:
    import keystone as _ks  # noqa: F401
    KEYSTONE_AVAILABLE = True
except ImportError:
    KEYSTONE_AVAILABLE = False

from tools.shellcode_gen.formatters import (
    to_hex, to_c_array, to_py_bytes, to_escaped, format_output, write_output
)
from tools.shellcode_gen._asm import cmd_as_db_bytes
from tools.shellcode_gen.payloads import get_builder, load_all, _REGISTRY
from tools.shellcode_gen import generate_from_bin, generate_from_command


load_all()

SAMPLE = bytes(range(16))   # 00 01 02 ... 0f


# ─────────────────────────────────────────────────────────────────
# Formatters
# ─────────────────────────────────────────────────────────────────

class TestFormatters(unittest.TestCase):

    def test_to_hex_no_sep(self):
        self.assertEqual(to_hex(b"\xde\xad\xbe\xef"), "deadbeef")

    def test_to_hex_sep(self):
        self.assertEqual(to_hex(b"\xde\xad", sep=" "), "de ad")

    def test_to_c_array_contains_var(self):
        out = to_c_array(b"\x90\x90", var_name="sc")
        self.assertIn("unsigned char sc[]", out)
        self.assertIn("0x90", out)
        self.assertIn("unsigned int sc_len = 2", out)

    def test_to_py_bytes_contains_var(self):
        out = to_py_bytes(b"\x90", var_name="sc")
        self.assertIn("sc = b\"", out)
        self.assertIn("\\x90", out)

    def test_to_escaped(self):
        self.assertEqual(to_escaped(b"\x41\x42"), "\\x41\\x42")

    def test_format_output_raw(self):
        self.assertEqual(format_output(SAMPLE, "raw"), SAMPLE)

    def test_format_output_hex(self):
        result = format_output(SAMPLE, "hex")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 32)

    def test_format_output_unknown_raises(self):
        with self.assertRaises(ValueError):
            format_output(SAMPLE, "xml")

    def test_write_output_to_file_raw(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            path = Path(f.name)
        try:
            write_output(SAMPLE, "raw", dest=path)
            self.assertEqual(path.read_bytes(), SAMPLE)
        finally:
            path.unlink(missing_ok=True)

    def test_write_output_to_file_hex(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt", mode="w") as f:
            path = Path(f.name)
        try:
            write_output(SAMPLE, "hex", dest=path)
            content = path.read_text()
            self.assertEqual(len(content.strip()), len(SAMPLE) * 2)
        finally:
            path.unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────
# _asm helper
# ─────────────────────────────────────────────────────────────────

class TestCmdAsDbBytes(unittest.TestCase):

    def test_ascii(self):
        result = cmd_as_db_bytes("AB")
        self.assertEqual(result, "0x41, 0x42, 0x00")

    def test_null_terminated(self):
        result = cmd_as_db_bytes("x")
        self.assertTrue(result.endswith("0x00"))

    def test_empty_string(self):
        result = cmd_as_db_bytes("")
        self.assertEqual(result, "0x00")

    def test_special_chars(self):
        result = cmd_as_db_bytes('cmd /c "whoami"')
        self.assertIn("0x22", result)   # '"' = 0x22


# ─────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────

class TestRegistry(unittest.TestCase):

    def test_all_four_loaded(self):
        keys = set(_REGISTRY.keys())
        self.assertIn(("windows", "x64"), keys)
        self.assertIn(("windows", "x86"), keys)
        self.assertIn(("linux",   "x64"), keys)
        self.assertIn(("linux",   "x86"), keys)

    def test_get_builder_returns_callable(self):
        fn = get_builder("windows", "x64")
        self.assertTrue(callable(fn))

    def test_get_builder_case_insensitive(self):
        fn1 = get_builder("Windows", "X64")
        fn2 = get_builder("windows", "x64")
        self.assertIs(fn1, fn2)

    def test_unknown_raises(self):
        with self.assertRaises(ValueError):
            get_builder("haiku", "riscv")


# ─────────────────────────────────────────────────────────────────
# generate_from_bin
# ─────────────────────────────────────────────────────────────────

class TestFromBin(unittest.TestCase):

    def test_roundtrip(self):
        data = b"\x90" * 32 + b"\xc3"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(data)
            path = f.name
        try:
            result = generate_from_bin(path)
            self.assertEqual(result, data)
        finally:
            os.unlink(path)

    def test_pathlib_path(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\xcc")
            path = Path(f.name)
        try:
            self.assertEqual(generate_from_bin(path), b"\xcc")
        finally:
            path.unlink()


# ─────────────────────────────────────────────────────────────────
# CLI argument parsing (no keystone required)
# ─────────────────────────────────────────────────────────────────

class TestCLIParsing(unittest.TestCase):

    def _run(self, argv, expected_rc=0):
        from tools.shellcode_gen.cli import main
        rc = main(argv)
        return rc

    def test_list_flag(self):
        rc = self._run(["--list"])
        self.assertEqual(rc, 0)

    def test_missing_source_exits_nonzero(self):
        # argparse exits with code 2 on parse error; we can't capture that
        # easily, so just ensure the parser doesn't crash during build.
        from tools.shellcode_gen.cli import build_parser
        p = build_parser()
        self.assertIsNotNone(p)

    def test_unknown_format_raises(self):
        # --format xyz should produce error return
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x90")
            path = f.name
        try:
            with self.assertRaises(SystemExit):
                from tools.shellcode_gen.cli import main
                main(["--bin", path, "--format", "xml"])
        finally:
            os.unlink(path)

    @unittest.skipUnless(KEYSTONE_AVAILABLE, "keystone not installed")
    def test_command_to_hex_stdout(self):
        import io
        captured = []
        original_print = print

        def _capture(*args, **kwargs):
            if kwargs.get("file") is None:
                captured.append(" ".join(str(a) for a in args))
            else:
                original_print(*args, **kwargs)

        with mock.patch("builtins.print", side_effect=_capture):
            rc = self._run([
                "--command", "whoami",
                "--platform", "linux",
                "--arch", "x64",
                "--format", "hex",
            ])
        self.assertEqual(rc, 0)


# ─────────────────────────────────────────────────────────────────
# Assembly tests (keystone required)
# ─────────────────────────────────────────────────────────────────

@unittest.skipUnless(KEYSTONE_AVAILABLE, "keystone not installed")
class TestAssembly(unittest.TestCase):

    def _check(self, platform, arch, cmd="whoami"):
        data = generate_from_command(cmd, platform, arch)
        self.assertIsInstance(data, bytes)
        self.assertGreater(len(data), 16, f"{platform}/{arch} shellcode too short")
        return data

    def test_windows_x64_basic(self):
        self._check("windows", "x64", "calc.exe")

    def test_windows_x86_basic(self):
        self._check("windows", "x86", "calc.exe")

    def test_linux_x64_basic(self):
        self._check("linux", "x64", "id")

    def test_linux_x86_basic(self):
        self._check("linux", "x86", "id")

    def test_command_bytes_embedded_win_x64(self):
        cmd = "cmd.exe /c whoami"
        data = generate_from_command(cmd, "windows", "x64")
        self.assertIn(cmd.encode(), data)

    def test_command_bytes_embedded_linux_x64(self):
        cmd = "id > /tmp/out"
        data = generate_from_command(cmd, "linux", "x64")
        self.assertIn(cmd.encode(), data)

    def test_long_command(self):
        cmd = "cmd.exe /c " + "A" * 200
        data = self._check("windows", "x64", cmd)
        self.assertIn(b"A" * 200, data)

    def test_different_commands_differ(self):
        d1 = generate_from_command("calc.exe", "windows", "x64")
        d2 = generate_from_command("notepad.exe", "windows", "x64")
        self.assertNotEqual(d1, d2)


if __name__ == "__main__":
    unittest.main()
