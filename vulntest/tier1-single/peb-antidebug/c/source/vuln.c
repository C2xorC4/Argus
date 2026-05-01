/*
 * Tier 1 — PEB anti-debug check (C / Windows).
 *
 * Read PEB.BeingDebugged and PEB.NtGlobalFlag — both flag debugger
 * presence under user-mode debugger attach. Combined with manual
 * walks of NtGlobalFlag and HeapFlags, forms the classical PEB
 * anti-debug suite.
 *
 * Knowledge: [[Memory/Knowledge/em_peb_antidebug_fields]]
 */
#include <windows.h>
#include <stdio.h>

typedef struct _PEB_LITE {
    BYTE  Reserved1[2];
    BYTE  BeingDebugged;
    BYTE  Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    /* ... NtGlobalFlag at offset 0xBC (x64) */
} PEB_LITE;

#define PEB_NTGLOBALFLAG_OFFSET 0xBC

int main(void) {
    /* sink: PEB read via segment register (x64: GS:[0x60]) */
#if defined(_M_X64) || defined(__x86_64__)
    PEB_LITE *peb = (PEB_LITE *)__readgsqword(0x60);
#else
    PEB_LITE *peb = (PEB_LITE *)__readfsdword(0x30);
#endif
    if (peb->BeingDebugged) {
        printf("debugger detected via PEB.BeingDebugged\n");
        return 1;
    }
    DWORD ntGlobalFlag = *(DWORD *)((BYTE *)peb + PEB_NTGLOBALFLAG_OFFSET);
    if (ntGlobalFlag & 0x70) {     /* FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | PARAMETERS */
        printf("debugger heap flags detected\n");
        return 1;
    }
    printf("no debugger\n");
    return 0;
}
