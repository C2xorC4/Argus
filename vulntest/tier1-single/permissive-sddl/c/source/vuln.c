/*
 * Tier 1 — permissive SDDL on named IPC (C / Windows).
 *
 * CreateNamedPipeW with a SECURITY_DESCRIPTOR built from a permissive
 * SDDL string ("D:(A;;GA;;;WD)" — Everyone, GENERIC_ALL). Any local
 * user can connect to this pipe and exercise whatever protocol the
 * server implements.
 *
 * This is one half of the EAC EOS chain — the named IPC was
 * world-accessible, allowing an unprivileged process to invoke
 * privileged service operations.
 *
 * Knowledge: [[Memory/Knowledge/eac_eos_arbitrary_write_chain]]
 *            [[Memory/Knowledge/gameguard_research_22_findings]]
 * CWE-732 (Incorrect Permission Assignment for Critical Resource).
 */
#include <windows.h>
#include <sddl.h>
#include <stdio.h>

int wmain(void) {
    const wchar_t *sddl = L"D:(A;;GA;;;WD)";   /* sink: Everyone GENERIC_ALL */
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sd, NULL)) {
        return 1;
    }

    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };

    HANDLE pipe = CreateNamedPipeW(
        L"\\\\.\\pipe\\argus_demo_pipe",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
        1, 4096, 4096, 0, &sa);

    if (pipe == INVALID_HANDLE_VALUE) {
        LocalFree(sd);
        return 1;
    }

    wprintf(L"named pipe created with permissive SDDL\n");

    /* server loop omitted for brevity — Phase 0 needs only the
       structural pattern (CreateNamedPipe + permissive SDDL) */

    CloseHandle(pipe);
    LocalFree(sd);
    return 0;
}
