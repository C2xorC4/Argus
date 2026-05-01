/*
 * Tier 1 — NULL DACL — remediation.
 *
 * Build an explicit DACL with the principals that should have access.
 */
#include <windows.h>
#include <sddl.h>
#include <stdio.h>

int wmain(void) {
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, NULL)) {
        return 1;
    }
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\argus_null_dacl",
        PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 4096, 4096, 0, &sa);
    if (pipe == INVALID_HANDLE_VALUE) { LocalFree(sd); return 1; }
    CloseHandle(pipe);
    LocalFree(sd);
    return 0;
}
