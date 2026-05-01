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
 */
#include <windows.h>
#include <stdio.h>

#ifdef _MSC_VER
extern "C" NTSTATUS do_syscall(DWORD ssn, ...);
#else
__attribute__((naked))
static NTSTATUS do_syscall(DWORD ssn, ...) {
    __asm__ __volatile__(
        "mov %rcx, %r10\n\t"      /* arg1 → r10 (Win64 syscall conv) */
        "mov %ecx, %eax\n\t"      /* hmm — placeholder; real impl */
        "syscall\n\t"             /* sink: direct syscall */
        "ret\n\t"
    );
}
#endif

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

int main(void) {
    DWORD ssn = resolve_ssn("NtClose");
    printf("NtClose SSN = 0x%X\n", ssn);
    /* real malware: do_syscall(ssn, handle); */
    return 0;
}
