/*
 * Tier 1 — TLS callback first-stage (C / Windows).
 *
 * IMAGE_TLS_DIRECTORY → callback array. Callbacks fire BEFORE the
 * binary's entry point — useful for malware that wants execution
 * during the loader's own initialisation, before anti-debug or
 * sandbox instrumentation has fully attached.
 *
 * Knowledge: [[Memory/Knowledge/em_covert_execution_tls_seh]]
 * CWE-N/A — malware-detection target.
 * MITRE ATT&CK: T1106 (Native API), T1543 (Create or Modify System Process).
 */
#include <windows.h>
#include <stdio.h>

void NTAPI tls_callback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    (void)DllHandle; (void)Reserved;
    if (Reason == DLL_PROCESS_ATTACH) {
        /* fires before main() — first-stage execution slot */
        OutputDebugStringA("argus: tls callback fired\n");
    }
}

#ifdef _MSC_VER
#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB"))
PIMAGE_TLS_CALLBACK tls_used = tls_callback;
#else
PIMAGE_TLS_CALLBACK tls_callback_ptr __attribute__((section(".CRT$XLB"))) = tls_callback;
#endif

int main(void) {
    printf("main()\n");
    return 0;
}
