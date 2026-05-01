/*
 * Tier 1 — permissive SDDL — remediation.
 *
 * Restrict the SDDL to specific authorised principals — the calling
 * service account, members of an admin group, etc. Never grant
 * Everyone (WD) or Anonymous (AN).
 */
#include <windows.h>
#include <sddl.h>
#include <stdio.h>

int wmain(void) {
    /* allow only Local System (SY) and Administrators (BA) GENERIC_ALL,
       Authenticated Users (AU) GENERIC_READ for status queries */
    const wchar_t *sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;AU)";
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

    if (pipe == INVALID_HANDLE_VALUE) { LocalFree(sd); return 1; }
    wprintf(L"named pipe created with restricted SDDL\n");
    CloseHandle(pipe);
    LocalFree(sd);
    return 0;
}
