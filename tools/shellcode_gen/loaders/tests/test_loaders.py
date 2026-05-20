"""Tests for shellcode_gen loaders.

All tests are execution-free — they verify template correctness only.
No shellcode is run; samples are simple byte sequences for structural checks.
"""
from __future__ import annotations

import sys
import os
import re
import tempfile
import unittest
from pathlib import Path

_ARGUS_ROOT = Path(__file__).parent.parent.parent.parent.parent
if str(_ARGUS_ROOT) not in sys.path:
    sys.path.insert(0, str(_ARGUS_ROOT))

from tools.shellcode_gen.loaders import get_loader, load_all_loaders, _LOADER_REGISTRY

load_all_loaders()

SAMPLE = b"\x90" * 8 + b"\xc3"   # 9 bytes — generic NOP sled + RET
# Distinctive bytes that won't appear by coincidence in XOR keys or template code
DISTINCTIVE = b"\xde\xad\xbe\xef" * 4 + b"\xc3"   # 17 bytes


# ─────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────

class TestRegistry(unittest.TestCase):

    def test_all_eleven_loaded(self):
        keys = set(_LOADER_REGISTRY.keys())
        for name in ("win_malloc_rwx", "win_rw_rx", "win_heap_exec",
                     "win_fiber", "win_apc_self",
                     "win_nt_alloc_thread", "win_split_alloc", "win_section_map",
                     "win_hells_gate",
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
                       required_headers=None, required_go_symbols=None,
                       required_rs_symbols=None):
    """Factory: produces a TestCase class for one loader."""

    class _LoaderTest(unittest.TestCase):

        def setUp(self):
            self.mod = get_loader(loader_name)
            self.c_out  = self.mod.generate_c(SAMPLE)
            self.py_out = self.mod.generate_python(SAMPLE)
            self.go_out = self.mod.generate_go(SAMPLE) if hasattr(self.mod, "generate_go") else None
            self.rs_out = self.mod.generate_rust(SAMPLE) if hasattr(self.mod, "generate_rust") else None

        # ── C output ────────────────────────────────────────────

        def test_c_is_nonempty_string(self):
            self.assertIsInstance(self.c_out, str)
            self.assertGreater(len(self.c_out), 0)

        def test_c_has_xor_decrypt(self):
            # XOR decrypt loop and key variable must be present
            self.assertIn("^=", self.c_out)
            self.assertIn("_sck", self.c_out)

        def test_c_no_plaintext_bytes(self):
            # Plaintext bytes from DISTINCTIVE must not appear consecutively
            for b in DISTINCTIVE:
                hex_plain = f"0x{b:02x}"
                # Allow individual bytes to appear (common hex values), but
                # at least the exact consecutive sequence must not appear
                pass
            out_d = self.mod.generate_c(DISTINCTIVE)
            plain_seq = ", ".join(f"0x{b:02x}" for b in DISTINCTIVE[:4])
            self.assertNotIn(plain_seq, out_d,
                             "Plaintext shellcode bytes visible — encryption not applied")

        def test_c_embeds_sc_len(self):
            # sc_len constant must be present (some loaders pad, so exact value varies)
            self.assertIn("sc_len = ", self.c_out)

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

        def test_py_has_xor_decrypt(self):
            self.assertIn("_sck", self.py_out)
            self.assertIn("^ ", self.py_out)

        def test_py_no_plaintext_bytes(self):
            out_d = self.mod.generate_python(DISTINCTIVE)
            plain_seq = "".join(f"\\x{b:02x}" for b in DISTINCTIVE[:4])
            self.assertNotIn(plain_seq, out_d,
                             "Plaintext shellcode bytes visible — encryption not applied")

        def test_py_has_import_ctypes(self):
            self.assertIn("import ctypes", self.py_out)

        def test_py_has_required_symbols(self):
            for sym in required_py_symbols:
                self.assertIn(sym, self.py_out,
                              f"Python output missing {sym!r}")

        # ── Go output ────────────────────────────────────────────

        def test_go_exists(self):
            self.assertIsNotNone(self.go_out,
                                 f"{loader_name!r} missing generate_go")

        def test_go_is_nonempty_string(self):
            if self.go_out is None:
                self.skipTest("no generate_go")
            self.assertIsInstance(self.go_out, str)
            self.assertGreater(len(self.go_out), 0)

        def test_go_has_xor_decrypt(self):
            if self.go_out is None:
                self.skipTest("no generate_go")
            self.assertIn("_scKey", self.go_out)
            self.assertIn("^=", self.go_out)

        def test_go_no_plaintext_bytes(self):
            if self.go_out is None:
                self.skipTest("no generate_go")
            out_d = self.mod.generate_go(DISTINCTIVE)
            plain_seq = ", ".join(f"0x{b:02x}" for b in DISTINCTIVE[:4])
            self.assertNotIn(plain_seq, out_d,
                             "Plaintext shellcode bytes visible — encryption not applied")

        def test_go_has_package_main(self):
            if self.go_out is None:
                self.skipTest("no generate_go")
            self.assertIn("package main", self.go_out)

        def test_go_has_required_symbols(self):
            if self.go_out is None or not required_go_symbols:
                self.skipTest("no go symbols to check")
            for sym in required_go_symbols:
                self.assertIn(sym, self.go_out,
                              f"Go output missing {sym!r}")

        # ── Rust output ──────────────────────────────────────────

        def test_rs_is_nonempty_or_absent(self):
            if self.rs_out is None:
                return  # Linux loaders legitimately omit Rust
            self.assertIsInstance(self.rs_out, str)
            self.assertGreater(len(self.rs_out), 0)

        def test_rs_has_xor_decrypt(self):
            if self.rs_out is None:
                self.skipTest("no generate_rust")
            self.assertIn("_sck", self.rs_out)
            self.assertIn("^=", self.rs_out)

        def test_rs_no_plaintext_bytes(self):
            if self.rs_out is None:
                self.skipTest("no generate_rust")
            out_d = self.mod.generate_rust(DISTINCTIVE)
            plain_seq = ", ".join(f"0x{b:02x}" for b in DISTINCTIVE[:4])
            self.assertNotIn(plain_seq, out_d,
                             "Plaintext shellcode bytes visible — encryption not applied")

        def test_rs_has_fn_main(self):
            if self.rs_out is None:
                self.skipTest("no generate_rust")
            self.assertIn("fn main()", self.rs_out)

        def test_rs_has_required_symbols(self):
            if self.rs_out is None or not required_rs_symbols:
                self.skipTest("no rust symbols to check")
            for sym in required_rs_symbols:
                self.assertIn(sym, self.rs_out,
                              f"Rust output missing {sym!r}")

        # ── Variance ─────────────────────────────────────────────

        def test_different_shellcode_differs(self):
            other = b"\xcc" * 4
            c2  = self.mod.generate_c(other)
            py2 = self.mod.generate_python(other)
            self.assertNotEqual(self.c_out, c2)
            self.assertNotEqual(self.py_out, py2)

        def test_same_shellcode_differs_each_call(self):
            # Per-build random key means two calls produce different output
            c2 = self.mod.generate_c(SAMPLE)
            self.assertNotEqual(self.c_out, c2,
                                "generate_c returned identical output on two calls — key not random")

    _LoaderTest.__name__ = f"Test_{loader_name}"
    _LoaderTest.__qualname__ = f"Test_{loader_name}"
    return _LoaderTest


# Register per-loader test classes into the module's global namespace so
# unittest discovers them.

_LOADER_SPECS = [
    ("win_malloc_rwx",
     ["VirtualAlloc", "CreateThread", "memcpy", "PAGE_EXECUTE_READWRITE"],
     ["VirtualAlloc", "CreateThread", "RtlMoveMemory"],
     ["#include <windows.h>"],
     ["VirtualAlloc", "CreateThread", "WaitForSingleObject", "syscall"],
     ["VirtualAlloc", "CreateThread", "WaitForSingleObject",
      '#[link(name = "kernel32")]']),

    ("win_rw_rx",
     ["VirtualAlloc", "VirtualProtect", "CreateThread", "PAGE_READWRITE", "PAGE_EXECUTE_READ"],
     ["VirtualAlloc", "VirtualProtect", "CreateThread"],
     ["#include <windows.h>"],
     ["VirtualAlloc", "VirtualProtect", "CreateThread", "syscall"],
     ["VirtualAlloc", "VirtualProtect", "CreateThread",
      '#[link(name = "kernel32")]']),

    ("win_heap_exec",
     ["HeapCreate", "HeapAlloc", "CreateThread", "HEAP_CREATE_ENABLE_EXECUTE"],
     ["HeapCreate", "HeapAlloc", "CreateThread"],
     ["#include <windows.h>"],
     ["HeapCreate", "HeapAlloc", "CreateThread", "syscall"],
     ["HeapCreate", "HeapAlloc", "CreateThread",
      '#[link(name = "kernel32")]']),

    ("win_fiber",
     ["VirtualAlloc", "ConvertThreadToFiber", "CreateFiber", "SwitchToFiber",
      "fiber_trampoline", "FiberArgs"],
     ["VirtualAlloc", "ConvertThreadToFiber", "CreateFiber", "SwitchToFiber"],
     ["#include <windows.h>"],
     ["ConvertThreadToFiber", "CreateFiber", "SwitchToFiber",
      "encoding/binary", "runtime.LockOSThread", "trampSz"],
     ["ConvertThreadToFiber", "CreateFiber", "SwitchToFiber",
      "fiber_trampoline", "AtomicPtr"]),

    ("win_apc_self",
     ["VirtualAlloc", "QueueUserAPC", "SleepEx", "GetCurrentThread"],
     ["VirtualAlloc", "QueueUserAPC", "SleepEx", "GetCurrentThread"],
     ["#include <windows.h>"],
     ["QueueUserAPC", "SleepEx", "GetCurrentThread", "VirtualAlloc"],
     ["QueueUserAPC", "SleepEx", "GetCurrentThread", "VirtualAlloc"]),

    ("linux_mmap_rwx",
     ["mmap", "pthread_create", "PROT_EXEC", "MAP_ANONYMOUS"],
     ["mmap", "pthread_create", "PROT_EXEC"],
     ["#include <sys/mman.h>", "#include <pthread.h>"],
     ["syscall.Mmap", "PROT_EXEC", "LockOSThread"],
     None),   # no Rust for Linux loaders

    ("linux_mmap_rw_rx",
     ["mmap", "mprotect", "pthread_create", "PROT_EXEC"],
     ["mmap", "mprotect", "pthread_create"],
     ["#include <sys/mman.h>", "#include <pthread.h>"],
     ["syscall.Mmap", "syscall.Mprotect", "PROT_EXEC", "LockOSThread"],
     None),   # no Rust for Linux loaders

    ("win_nt_alloc_thread",
     ["NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
      "GetProcAddress", "check_stub", "4C", "8B", "D1", "0xB8"],
     ["NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
      "check_stub", "0x4C"],
     ["#include <windows.h>"],
     ["NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
      "checkStub", "syscall.SyscallN"],
     ["NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
      "check_stub", "FnNtAllocVM"]),

    ("win_split_alloc",
     ["VirtualAlloc", "VirtualProtect", "CreateThread", "CHUNK_SIZE", "TRAMP_SIZE",
      "0x49", "0xBB", "0x41", "0xFF", "0xE3"],
     ["VirtualAlloc", "VirtualProtect", "CreateThread", "CHUNK_SIZE",
      "\\x49\\xbb", "\\x41\\xff\\xe3"],
     ["#include <windows.h>"],
     ["VirtualAlloc", "VirtualProtect", "chunkSize", "trampSize",
      "encoding/binary", "0x49", "0xBB"],
     ["VirtualAlloc", "VirtualProtect", "CHUNK_SIZE", "TRAMP_SIZE",
      "0x49", "0xBB"]),

    ("win_section_map",
     ["NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
      "PAGE_EXECUTE_READWRITE", "PAGE_READWRITE", "PAGE_EXECUTE_READ",
      "SEC_COMMIT", "ViewUnmap"],
     ["NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
      "PAGE_EXECUTE_READ"],
     ["#include <windows.h>"],
     ["NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
      "CreateThread"],
     ["NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
      "FnNtCreateSection"]),

    ("win_hells_gate",
     ["get_ssn", "find_gadget", "write_stub", "cmp_rva",
      "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
      "0x4C", "0x8B", "0xD1", "0x0F", "0x05", "0xC3",
      "IMAGE_SCN_MEM_EXECUTE", "STUB_SIZE"],
     ["get_ssn", "make_stub", "ssn_map",
      "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
      "\\x4c\\x8b\\xd1", "\\x0f\\x05\\xc3", "0x20000000"],
     ["#include <windows.h>"],
     ["getExports", "findGadget", "buildStub", "lookupSSN",
      "syscall.SyscallN", "NtAllocateVirtualMemory", "0x4C", "0x8B"],
     ["get_exports", "find_gadget", "build_stub",
      "NtAllocateVirtualMemory", "FnNtCreateThreadEx", "sort_by_key"]),
]

for _spec in _LOADER_SPECS:
    _name, _c_syms, _py_syms, _headers = _spec[0], _spec[1], _spec[2], _spec[3]
    _go_syms = _spec[4] if len(_spec) > 4 else None
    _rs_syms = _spec[5] if len(_spec) > 5 else None
    globals()[f"Test_{_name}"] = _make_loader_tests(
        _name, _c_syms, _py_syms, _headers, _go_syms, _rs_syms)


# ─────────────────────────────────────────────────────────────────
# Staged loader checks
# ─────────────────────────────────────────────────────────────────

class TestStagedLoaders(unittest.TestCase):
    """Staged variants must read shellcode from a file path, not embed it."""

    _WIN_LOADERS = [
        "win_malloc_rwx", "win_rw_rx", "win_heap_exec",
        "win_fiber", "win_apc_self", "win_nt_alloc_thread",
        "win_split_alloc", "win_section_map", "win_hells_gate",
    ]

    def _check_no_embedded_bytes(self, src: str, label: str):
        """Staged output must not contain the DISTINCTIVE bytes."""
        plain_seq = ", ".join(f"0x{b:02x}" for b in DISTINCTIVE[:4])
        self.assertNotIn(plain_seq, src,
                         f"{label}: embedded shellcode bytes found in staged output")

    def test_c_staged_has_file_read(self):
        for name in self._WIN_LOADERS:
            mod = get_loader(name)
            out = mod.generate_c(DISTINCTIVE, staged=True)
            self.assertIn("argv[1]", out, f"{name}: C staged missing argv[1]")
            self.assertIn("fopen", out, f"{name}: C staged missing fopen")
            self._check_no_embedded_bytes(out, f"{name}/C")

    def test_c_staged_has_argc_argv_main(self):
        mod = get_loader("win_malloc_rwx")
        out = mod.generate_c(SAMPLE, staged=True)
        self.assertIn("argc", out)
        self.assertIn("argv", out)

    def test_go_staged_has_file_read(self):
        for name in self._WIN_LOADERS:
            mod = get_loader(name)
            out = mod.generate_go(DISTINCTIVE, staged=True)
            self.assertIn("os.ReadFile", out, f"{name}: Go staged missing os.ReadFile")
            self.assertIn('"os"', out, f"{name}: Go staged missing os import")
            self._check_no_embedded_bytes(out, f"{name}/Go")

    def test_rust_staged_has_file_read(self):
        for name in self._WIN_LOADERS:
            mod = get_loader(name)
            out = mod.generate_rust(DISTINCTIVE, staged=True)
            self.assertIn("std::fs::read", out, f"{name}: Rust staged missing std::fs::read")
            self.assertIn("std::env::args", out, f"{name}: Rust staged missing std::env::args")
            self._check_no_embedded_bytes(out, f"{name}/Rust")

    def test_python_staged_has_file_read(self):
        for name in self._WIN_LOADERS:
            mod = get_loader(name)
            out = mod.generate_python(DISTINCTIVE, staged=True)
            self.assertIn("sys.argv", out, f"{name}: Python staged missing sys.argv")

    def test_linux_staged_c(self):
        for name in ("linux_mmap_rwx", "linux_mmap_rw_rx"):
            mod = get_loader(name)
            out = mod.generate_c(DISTINCTIVE, staged=True)
            self.assertIn("argv[1]", out, f"{name}: C staged missing argv[1]")

    def test_linux_staged_go(self):
        for name in ("linux_mmap_rwx", "linux_mmap_rw_rx"):
            mod = get_loader(name)
            out = mod.generate_go(DISTINCTIVE, staged=True)
            self.assertIn("os.ReadFile", out, f"{name}: Go staged missing os.ReadFile")

    def test_staged_and_embedded_differ(self):
        mod = get_loader("win_malloc_rwx")
        embedded = mod.generate_go(SAMPLE)
        staged   = mod.generate_go(SAMPLE, staged=True)
        self.assertNotEqual(embedded, staged)


# ─────────────────────────────────────────────────────────────────
# Technique-specific checks
# ─────────────────────────────────────────────────────────────────

class TestSplitAllocChunkSize(unittest.TestCase):

    def setUp(self):
        self.mod = get_loader("win_split_alloc")

    def test_custom_chunk_size_c(self):
        out = self.mod.generate_c(SAMPLE, chunk_size=16)
        self.assertIn("16", out)

    def test_custom_chunk_size_python(self):
        out = self.mod.generate_python(SAMPLE, chunk_size=16)
        self.assertIn("16", out)

    def test_custom_chunk_size_go(self):
        out = self.mod.generate_go(SAMPLE, chunk_size=16)
        self.assertIn("16", out)

    def test_custom_chunk_size_rust(self):
        out = self.mod.generate_rust(SAMPLE, chunk_size=16)
        self.assertIn("16", out)

    def test_default_chunk_size_present_c(self):
        out = self.mod.generate_c(SAMPLE)
        self.assertIn("64", out)

    def test_default_chunk_size_present_go(self):
        out = self.mod.generate_go(SAMPLE)
        self.assertIn("64", out)

    def test_default_chunk_size_present_rust(self):
        out = self.mod.generate_rust(SAMPLE)
        self.assertIn("64", out)

    def test_trampoline_bytes_present_python(self):
        out = self.mod.generate_python(SAMPLE)
        self.assertIn("\\x41\\xff\\xe3", out)
        self.assertIn("\\x49\\xbb", out)

    def test_trampoline_bytes_present_go(self):
        out = self.mod.generate_go(SAMPLE)
        self.assertIn("0x49", out)
        self.assertIn("0xBB", out)
        self.assertIn("0x41", out)

    def test_trampoline_bytes_present_rust(self):
        out = self.mod.generate_rust(SAMPLE)
        self.assertIn("0x49", out)
        self.assertIn("0xBB", out)
        self.assertIn("0x41", out)


class TestSectionMapDoubleMap(unittest.TestCase):

    def setUp(self):
        self.mod = get_loader("win_section_map")

    def test_c_rw_view_before_rx(self):
        out = self.mod.generate_c(SAMPLE)
        rw_pos = out.find("Step 2")
        rx_pos = out.find("Step 5")
        self.assertGreater(rx_pos, rw_pos, "RX map (Step 5) should appear after RW map (Step 2)")

    def test_c_unmap_between_views(self):
        out = self.mod.generate_c(SAMPLE)
        rw_pos    = out.find("Step 2")
        unmap_pos = out.find("Step 4")
        rx_pos    = out.find("Step 5")
        self.assertLess(rw_pos, unmap_pos)
        self.assertLess(unmap_pos, rx_pos)

    def test_c_no_virtualalloc_for_payload(self):
        out = self.mod.generate_c(SAMPLE)
        self.assertNotIn("VirtualAlloc", out)
        self.assertNotIn("VirtualProtect", out)


class TestNtAllocHellsGate(unittest.TestCase):

    def setUp(self):
        self.mod = get_loader("win_nt_alloc_thread")

    def test_c_contains_stub_verification(self):
        out = self.mod.generate_c(SAMPLE)
        self.assertIn("0x4C", out)
        self.assertIn("0x8B", out)
        self.assertIn("0xD1", out)

    def test_c_no_virtualalloc_for_payload(self):
        out = self.mod.generate_c(SAMPLE)
        self.assertNotIn("VirtualAlloc(", out)

    def test_py_stub_check_present(self):
        out = self.mod.generate_python(SAMPLE)
        self.assertIn("check_stub", out)
        self.assertIn("0x4C", out)


class TestHellsGate(unittest.TestCase):

    def setUp(self):
        self.mod = get_loader("win_hells_gate")

    def test_c_no_hook_byte_read(self):
        out = self.mod.generate_c(SAMPLE)
        self.assertNotIn("check_stub", out)

    def test_c_rva_sort_present(self):
        out = self.mod.generate_c(SAMPLE)
        self.assertIn("cmp_rva", out)
        self.assertIn("qsort", out)

    def test_c_gadget_scan_present(self):
        out = self.mod.generate_c(SAMPLE)
        self.assertIn("0x0F", out)
        self.assertIn("0x05", out)
        self.assertIn("0xC3", out)

    def test_c_stub_bytes(self):
        out = self.mod.generate_c(SAMPLE)
        self.assertIn("0x4C", out)
        self.assertIn("0x8B", out)
        self.assertIn("0xD1", out)

    def test_c_no_virtualalloc_for_payload(self):
        out = self.mod.generate_c(SAMPLE)
        self.assertIn("NtAllocateVirtualMemory", out)

    def test_py_rva_sort(self):
        out = self.mod.generate_python(SAMPLE)
        self.assertIn("ssn_map", out)
        self.assertIn(".sort()", out)

    def test_py_gadget_scan(self):
        out = self.mod.generate_python(SAMPLE)
        self.assertIn("\\x0f\\x05\\xc3", out)
        self.assertIn("0x20000000", out)

    def test_py_stub_encoding(self):
        out = self.mod.generate_python(SAMPLE)
        self.assertIn("\\x4c\\x8b\\xd1", out)
        self.assertIn("\\xff\\x25", out)


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

    def test_loader_go_from_bin(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            path = f.name
        try:
            rc = self._run(["--bin", path, "--loader", "win_malloc_rwx", "--lang", "go"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_loader_rust_from_bin(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            path = f.name
        try:
            rc = self._run(["--bin", path, "--loader", "win_malloc_rwx", "--lang", "rust"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_loader_staged_c(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            path = f.name
        try:
            rc = self._run(["--bin", path, "--loader", "win_malloc_rwx",
                            "--lang", "c", "--staged"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_loader_staged_go(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            path = f.name
        try:
            rc = self._run(["--bin", path, "--loader", "win_rw_rx",
                            "--lang", "go", "--staged"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_loader_staged_rust(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            path = f.name
        try:
            rc = self._run(["--bin", path, "--loader", "win_apc_self",
                            "--lang", "rust", "--staged"])
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_staged_output_has_file_read(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            bin_path = f.name
        out_path = bin_path + ".go"
        try:
            rc = self._run(["--bin", bin_path, "--loader", "win_malloc_rwx",
                            "--lang", "go", "--staged", "--output", out_path])
            self.assertEqual(rc, 0)
            content = Path(out_path).read_text()
            self.assertIn("os.ReadFile", content)
        finally:
            os.unlink(bin_path)
            if Path(out_path).exists():
                os.unlink(out_path)

    def test_raw_format_produces_bin(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(SAMPLE)
            bin_path = f.name
        out_path = bin_path + ".out"
        try:
            rc = self._run(["--bin", bin_path, "--format", "raw", "--output", out_path])
            self.assertEqual(rc, 0)
            data = Path(out_path).read_bytes()
            self.assertEqual(data, SAMPLE)
        finally:
            os.unlink(bin_path)
            if Path(out_path).exists():
                os.unlink(out_path)

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
