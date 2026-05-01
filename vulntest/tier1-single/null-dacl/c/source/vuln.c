/*
 * Tier 1 — NULL DACL on named IPC (C / Windows).
 *
 * SetSecurityDescriptorDacl(sd, TRUE, NULL, FALSE) — NULL DACL means
 * "no access control"; everyone has full access. Distinct from the
 * permissive-SDDL pattern which builds an explicit Everyone ACE;
 * NULL DACL is the "I disabled the gate entirely" form.
 *
 * Knowledge: [[Memory/Knowledge/gameguard_research_22_findings]]
 * CWE-732.
 */
#include <windows.h>
#include <stdio.h>

int wmain(void) {
    SECURITY_DESCRIPTOR sd = {0};
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION)) return 1;

    /* sink: NULL DACL — equivalent to "Everyone has full access" */
    if (!SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE)) return 1;

    SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd, FALSE };

    HANDLE pipe = CreateNamedPipeW(
        L"\\\\.\\pipe\\argus_null_dacl",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
        1, 4096, 4096, 0, &sa);

    if (pipe == INVALID_HANDLE_VALUE) return 1;
    wprintf(L"named pipe created with NULL DACL\n");
    CloseHandle(pipe);
    return 0;
}
