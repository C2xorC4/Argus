/*
 * Tier 1 — hidden-from-debugger thread (C / Windows).
 *
 * NtSetInformationThread(thread, ThreadHideFromDebugger, NULL, 0)
 * sets a flag in the kernel ETHREAD that suppresses thread-creation
 * events from debuggers. The thread runs unobserved.
 *
 * Knowledge: [[Memory/Knowledge/em_covert_execution_tls_seh]]
 */
#include <windows.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI *PNtSetInformationThread)(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength);

#define ThreadHideFromDebugger 0x11

DWORD WINAPI worker(LPVOID arg) {
    (void)arg;
    Sleep(100);
    return 0;
}

int main(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 1;
    PNtSetInformationThread NtSetInformationThread =
        (PNtSetInformationThread)GetProcAddress(ntdll, "NtSetInformationThread");
    if (!NtSetInformationThread) return 1;

    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (!t) return 1;

    /* sink: hide the thread from debugger */
    NtSetInformationThread(t, ThreadHideFromDebugger, NULL, 0);

    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    return 0;
}
