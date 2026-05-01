/*
 * Tier 1 — pre-verify-write — remediation.
 *
 * Either verify before write (compute hash on input, compare,
 * then commit), or write to a staging path that gets atomically
 * renamed only on verification success.
 */
#include <windows.h>
#include <stdio.h>

BOOL verify_bytes(const wchar_t *bytes) {
    (void)bytes;
    return FALSE;                       /* same simulation as vuln */
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) return 1;

    /* fix: verify the input bytes BEFORE the privileged write */
    if (!verify_bytes(argv[2])) {
        wprintf(L"verification failed — refusing write\n");
        return 1;
    }

    HANDLE h = CreateFileW(argv[1], GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 1;
    DWORD written = 0;
    WriteFile(h, argv[2], (DWORD)(wcslen(argv[2]) * sizeof(wchar_t)), &written, NULL);
    CloseHandle(h);
    return 0;
}
