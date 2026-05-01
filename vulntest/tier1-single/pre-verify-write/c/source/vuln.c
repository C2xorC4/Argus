/*
 * Tier 1 — pre-verification write with no cleanup (C / Windows).
 *
 * Privileged service writes attacker-supplied data to a target
 * file, *then* verifies. If verification fails, the file remains —
 * no cleanup. An attacker who triggers verification failures
 * leaves crafted bytes behind that downstream code (or a future
 * privileged read) trusts.
 *
 * The EAC EOS chain canonical pattern.
 *
 * Knowledge: [[Memory/Knowledge/eac_eos_arbitrary_write_chain]]
 * CWE-471, CWE-377 (related: insecure temporary file).
 */
#include <windows.h>
#include <stdio.h>

BOOL verify_payload(const wchar_t *path) {
    /* placeholder — real check would hash + compare against allowlist */
    (void)path;
    return FALSE;                       /* simulated verification failure */
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) {
        wprintf(L"usage: %s <path> <bytes>\n", argv[0]);
        return 1;
    }

    HANDLE h = CreateFileW(argv[1], GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 1;

    DWORD written = 0;
    /* sink: write before verify, no cleanup-on-failure path */
    WriteFile(h, argv[2], (DWORD)(wcslen(argv[2]) * sizeof(wchar_t)), &written, NULL);
    CloseHandle(h);

    if (!verify_payload(argv[1])) {
        wprintf(L"verification failed — file remains: %s\n", argv[1]);
        return 1;                       /* file not deleted */
    }

    wprintf(L"verified\n");
    return 0;
}
