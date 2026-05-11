/*
 * Tier 1 — direct-syscall stub (C / Windows).
 *
 * Resolve a syscall service-number (SSN) from NTDLL at runtime,
 * stash it in a stub, then invoke `syscall` directly — bypassing
 * the user-mode NTDLL function (and any hooks installed by EDR
 * inline at the NTDLL entry).
 *
 * Hell's Gate / SysWhispers / TartarusGate are the canonical
 * implementations; this cell is a minimal demonstration.
 *
 * Knowledge: [[Memory/Knowledge/em_direct_syscall_ssn_resolution]]
 * CWE-N/A — this is a malware-detection target, not a vulnerability.
 * MITRE ATT&CK: T1106 (Native API), T1112 (Modify Registry — when used
 *               to bypass userland telemetry).
 *
 * Build notes:
 *   MSVC x64 does not support inline assembly. The stub bytes are
 *   embedded as a static array in `.rdata` and copied to an
 *   RWX page at runtime, then invoked via function-pointer cast.
 *   The detector's byte-pattern scan finds the `4C 8B D1 B8 ...`
 *   prologue in either location.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/*
 * NTDLL syscall-stub prologue, complete shape:
 *   4C 8B D1                 mov r10, rcx       ; arg1 -> r10
 *   B8 ?? ?? ?? ??           mov eax, <ssn>     ; SSN patched at runtime
 *   0F 05                    syscall
 *   C3                       ret
 *
 * 11 bytes total. The SSN immediate (bytes 4-7) is filled in at
 * runtime once the resolver finds the canonical NtClose stub in
 * NTDLL and reads its SSN out.
 */
static const unsigned char syscall_stub_template[11] = {
    0x4C, 0x8B, 0xD1,                  /* mov r10, rcx        */
    0xB8, 0x00, 0x00, 0x00, 0x00,      /* mov eax, <ssn>      */
    0x0F, 0x05,                        /* syscall             */
    0xC3,                              /* ret                 */
};

static DWORD resolve_ssn(const char *name) {
    HMODULE h = GetModuleHandleA("ntdll.dll");
    if (!h) return 0xFFFFFFFF;
    BYTE *p = (BYTE *)GetProcAddress(h, name);
    if (!p) return 0xFFFFFFFF;
    /* Hell's Gate: the first ~16 bytes of the NtXxx stub are
       `mov r10, rcx; mov eax, <ssn>; syscall; ret`. The SSN lives
       at offset +4 as a 32-bit immediate. Read it back. */
    return *(DWORD *)(p + 4);
}

typedef NTSTATUS (NTAPI *do_syscall_fn)(HANDLE, ...);

int main(void) {
    DWORD ssn = resolve_ssn("NtClose");
    printf("NtClose SSN = 0x%X\n", ssn);

    /* Copy the template into an executable page; patch the SSN
       into the `mov eax, imm32` immediate (offset 4..7). */
    LPVOID page = VirtualAlloc(NULL, 0x1000,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (!page) return 1;
    memcpy(page, syscall_stub_template, sizeof(syscall_stub_template));
    *(DWORD *)((BYTE *)page + 4) = ssn;

    do_syscall_fn fn = (do_syscall_fn)page;
    HANDLE bogus = (HANDLE)(uintptr_t)0xFFFFFFFFFFFFFFFFULL;
    NTSTATUS rc = fn(bogus);     /* deliberate invalid handle */
    printf("syscall returned 0x%lX\n", (unsigned long)rc);

    VirtualFree(page, 0, MEM_RELEASE);
    return 0;
}
