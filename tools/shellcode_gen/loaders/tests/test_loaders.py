"""Tests for shellcode_gen loaders.

All tests are execution-free — they verify template correctness only.
No shellcode is run; samples are simple NOP sleds for structural checks.
"""
from __future__ import annotations

import sys
import os
import tempfile
import unittest
from pathlib import Path

_ARGUS_ROOT = Path(__file__).parent.parent.parent.parent.parent
if str(_ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(_ARGUS_ROOT))

from tools.shellcode_gen.loaders import get_loader, load_all_loaders, _LOADER_REGISTRY

load_all_loaders()

SAMPLE = b"\x90" * 8 + b"\xc3"   # 8× NOP + RET; 9 bytes


# ─────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────

class TestRegistry(unittest.TestCase):

    def test_all_seven_loaded(self):
        keys = set(_LOADER_REGISTRY.keys())
        for name in ("win_malloc_rwx", "win_rw_rx", "win_heap_exec",
                     "win_fiber", "win_apc_self",
                     "linux_mmap_rwx", "linux_mmap_rw_rx"):
            self.assertIn(name, keys, f"Loader {name!r} not registered")

    def test_get_loader_returns_module(self):
        mod = get_loader("win_malloc_rwx")
        self.assertTrue(callable(getattr(mod, "generate_c", None)))
        self.assertTrue(callable(getattr(mod, "generate_python", None)))

    def test_get_loader_case_insensitive(self):
        mod1 = get_loader("win_malloc_rwx")
        mod2 = get_loader("WIN_MALLOC_RWX")
        self.assertIs(mod1, mod2)

    def test_unknown_raises_valueerror(self):
        with self.assertRaises(ValueError):
            get_loader("win_nonexistent_technique")


# ─────────────────────────────────────────────────────────────────
# Per-loader structural checks
# ─────────────────────────────────────────────────────────────────

def _make_loader_tests(loader_name, required_c_symbols, required_py_symbols,
                       required_headers=None):
    """Factory: produces a TestCase class for one loader."""

    class _LoaderTest(unittest.TestCase):

        def setUp(self):
            self.mod = get_loader(loader_name)
            self.c_out = self.mod.generate_c(SAMPLE)
            self.py_out = self.mod.generate_python(SAMPLE)

        # ── C output ────────────────────────────────────────────

        def test_c_is_nonempty_string(self):
            self.assertIsInstance(self.c_out, str)
            self.assertGreater(len(self.c_out), 0)

        def test_c_embeds_shellcode_bytes(self):
            for b in SAMPLE:
                self.assertIn(f"0x{b:02x}", self.c_out)

        def test_c_embeds_length(self):
            self.assertIn(str(len(SAMPLE)), self.c_out)

        def test_c_has_required_symbols(self):
            for sym in required_c_symbols:
                self.assertIn(sym, self.c_out,
                              f"C output missing {sym!r}")

        def test_c_has_headers(self):
            headers = required_headers or ["#include"]
            for hdr in headers:
                self.assertIn(hdr, self.c_out,
                              f"C output missing header {hdr!r}")

        def test_c_has_main(self):
            self.assertIn("int main", self.c_out)

        # ── Python output ────────────────────────────────────────

        def test_py_is_nonempty_string(self):
            self.assertIsInstance(self.py_out, str)
            self.assertGreater(len(self.py_out), 0)

        def test_py_embeds_shellcode_bytes(self):
            for b in SAMPLE:
                self.assertIn(f"\\x{b:02x}", self.py_out)

        def test_py_embeds_length(self):
            self.assertIn(str(len(SAMPLE)), self.py_out)

        def test_py_has_import_ctypes(self):
            self.assertIn("import ctypes", self.py_out)

        def test_py_has_required_symbols(self):
            for sym in required_py_symbols:
                self.assertIn(sym, self.py_out,
                              f"Python output missing {sym!r}")

        # ── Variance ─────────────────────────────────────────────

        def test_different_shellcode_differs(self):
            other = b"\xcc" * 4
            c2 = self.mod.generate_c(other)
            py2 = self.mod.generate_python(other)
            self.assertNotEqual(self.c_out, c2)
            self.assertNotEqual(self.py_out, py2)

    _LoaderTest.__name__ = f"Test_{loader_name}"
    _LoaderTest.__qualname__ = f"Test_{loader_name}"
    return _LoaderTest


# Register per-loader test classes into the module's global namespace so
# unittest discovers them.

_LOADER_SPECS = [
    ("win_malloc_rwx",
     ["VirtualAlloc", "CreateThread", "memcpy", "PAGE_EXECUTE_READWRITE"],
     ["VirtualAlloc", "CreateThread", "RtlMoveMemory"],
     ["#include <windows.h>"]),

    ("win_rw_rx",
     ["VirtualAlloc", "VirtualProtect", "CreateThread", "PAGE_READWRITE", "PAGE_EXECUTE_READ"],
     ["VirtualAlloc", "VirtualProtect", "CreateThread"],
     ["#include <windows.h>"]),

    ("win_heap_exec",
     ["HeapCreate", "HeapAlloc", "CreateThread", "HEAP_CREATE_ENABLE_EXECUTE"],
     ["HeapCreate", "HeapAlloc", "CreateThread"],
     ["#include <windows.h>"]),

    ("win_fiber",
     ["VirtualAlloc", "ConvertThreadToFiber", "CreateFiber", "SwitchToFiber"],
     ["VirtualAlloc", "ConvertThreadToFiber", "CreateFiber", "SwitchToFiber"],
     ["#include <windows.h>"]),

    ("win_apc_self",
     ["VirtualAlloc", "QueueUserAPC", "SleepEx", "GetCurrentThread"],
     ["VirtualAlloc", "QueueUserAPC", "SleepEx", "GetCurrentThread"],
     ["#include <windows.h>"]),

    ("linux_mmap_rwx",
     ["mmap", "pthread_create", "PROT_EXEC", "MAP_ANONYMOUS"],
     ["mmap", "pthread_create", "PROT_EXEC"],
     ["#include <sys/mman.h>", "#include <pthread.h>"]),

    ("linux_mmap_rw_rx",
     ["mmap", "mprotect", "pthread_create", "PROT_EXEC"],
     ["mmap", "mprotect", "pthread_create"],
     ["#include <sys/mman.h>", "#include <pthread.h>"]),
]

for _name, _c_syms, _py_syms, _headers in _LOADER_SPECS:
    globals()[f"Test_{_name}"] = _make_loader_tests(_name, _c_syms, _py_syms, _headers)


# ─────────────────────────────────────────────────────────────────
# CLI integration
# ─────────────────────────────────────────────────────────────────

class TestLoaderCLI(unittest.TestCase):

    def _run(self, argv):
        from tools.shellcode_gen.cli import main
        return main(argv)

    def test_loader_c_from_bin(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            path = f.name
        try:
            rc = self._run(["--bin", path, "--loader", "win_malloc_rwx", "--lang", "c"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_loader_python_from_bin(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            path = f.name
        try:
            rc = self._run(["--bin", path, "--loader", "win_malloc_rwx", "--lang", "python"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_unknown_loader_returns_nonzero(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            path = f.name
        try:
            rc = self._run(["--bin", path, "--loader", "win_nonexistent"])
            self.assertNotEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_list_shows_loaders(self):
        rc = self._run(["--list"])
        self.assertEqual(rc, 0)

    def test_loader_writes_to_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            bin_path = f.name
        out_path = bin_path + ".c"
        try:
            rc = self._run(["--bin", bin_path, "--loader", "linux_mmap_rwx",
                            "--lang", "c", "--output", out_path])
            self.assertEqual(rc, 0)
            content = Path(out_path).read_text()
            self.assertIn("mmap", content)
        finally:
            os.unlink(bin_path)
            if Path(out_path).exists():
                os.unlink(out_path)


if __name__ == "__main__":
    unittest.main()
