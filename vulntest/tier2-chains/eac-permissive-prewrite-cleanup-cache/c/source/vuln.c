/*
 * Tier 2 — EAC arbitrary-write chain skeleton (C / Windows).
 *
 * Two linked primitives in one program:
 *   1. Permissive-SDDL named pipe (Everyone GENERIC_ALL).
 *   2. Pre-verification write — WriteFile precedes verify_payload(),
 *      no rollback on the verification-fail path.
 *
 * Together these form the operational shape of the EAC EOS arbitrary-
 * write chain (Sub 01). The full chain also requires the missing
 * cleanup detector (currently subsumed into pre_verification_write)
 * and a trusted-path cache-load detector (not yet implemented).
 *
 * Argus emits:
 *   - `permissive_sddl`            (from analysis/sddl.py)
 *   - `pre_verification_write`     (from analysis/integrity_check_order.py)
 *   - `chain_pattern`              (from heuristics/chains.py:match,
 *                                   gated by min_primitives=2)
 *
 * Knowledge: [[Memory/Knowledge/eac_eos_arbitrary_write_chain]]
 */
#include <windows.h>
#include <sddl.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

BOOL verify_payload(const wchar_t *path) {
    /* placeholder — real check would hash + compare against allowlist */
    (void)path;
    return FALSE;
}

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) {
        wprintf(L"usage: %s <pipe_name> <bytes>\n", argv[0]);
        return 1;
    }

    /* Component 1 — permissive-SDDL named pipe. */
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &sd, NULL)) {
        return 1;
    }
    SECURITY_ATTRIBUTES sa = { sizeof(sa), sd, FALSE };
    HANDLE pipe = CreateNamedPipeW(
        argv[1], PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE,
        1, 4096, 4096, 0, &sa);
    if (pipe == INVALID_HANDLE_VALUE) {
        if (sd) LocalFree(sd);
        return 1;
    }
    CloseHandle(pipe);
    if (sd) LocalFree(sd);

    /* Component 2 — pre-verify-write: commit before verify, no
       cleanup on the verify-fail branch. */
    HANDLE h = CreateFileW(L"C:\\Windows\\Temp\\eac_target.bin",
                           GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 1;
    DWORD written = 0;
    WriteFile(h, argv[2], (DWORD)(wcslen(argv[2]) * sizeof(wchar_t)),
              &written, NULL);
    CloseHandle(h);

    if (!verify_payload(L"C:\\Windows\\Temp\\eac_target.bin")) {
        wprintf(L"verification failed — file remains: eac_target.bin\n");
        return 1;
    }
    wprintf(L"verified\n");
    return 0;
}
