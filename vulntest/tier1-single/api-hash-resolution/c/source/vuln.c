/*
 * Tier 1 — API hash resolution (C / Windows).
 *
 * Walks the PEB.Ldr.InMemoryOrderModuleList → finds NTDLL → walks
 * the export table → hashes each export name → compares against
 * a hard-coded hash. Returns the resolved address. NTDLL function
 * names never appear in the binary — only the hash constants do.
 *
 * Knowledge: [[Memory/Knowledge/em_hook_evasion_three_approaches]]
 */
#include <windows.h>
#include <stdio.h>

#define NT_DJB2_NTCLOSE  0xa39d3a3eUL    /* example djb2 hash of "NtClose" */

static DWORD djb2(const char *s) {
    DWORD h = 5381;
    while (*s) h = ((h << 5) + h) + (BYTE)*s++;
    return h;
}

typedef struct _LIST_ENTRY_X { struct _LIST_ENTRY_X *Flink, *Blink; } LIST_ENTRY_X;

static PVOID resolve_by_hash(DWORD wanted) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");      /* in real impl: walk PEB */
    if (!ntdll) return NULL;

    BYTE *base = (BYTE *)ntdll;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)
        (base + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
    WORD  *ords  = (WORD  *)(base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char *name = (const char *)(base + names[i]);
        if (djb2(name) == wanted) {
            return (PVOID)(base + funcs[ords[i]]);
        }
    }
    return NULL;
}

int main(void) {
    PVOID p = resolve_by_hash(NT_DJB2_NTCLOSE);
    printf("resolved=%p\n", p);
    return 0;
}
