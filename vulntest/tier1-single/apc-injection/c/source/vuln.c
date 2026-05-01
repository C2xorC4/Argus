/*
 * Tier 1 — APC injection variant (C / Windows).
 *
 * NtQueueApcThread queues a user-mode APC against a target thread.
 * When the thread enters an alertable wait, the APC fires —
 * jumping into the attacker-supplied function pointer. This is
 * the "Early Bird" / "Atom Bombing precursor" injection variant.
 *
 * Knowledge: [[Memory/Knowledge/em_advanced_injection_variants]]
 *            [[Memory/Knowledge/bhg_process_injection_fundamentals]]
 */
#include <windows.h>
#include <stdio.h>

VOID CALLBACK apc_payload(ULONG_PTR arg) {
    (void)arg;
    /* in real malware: stage-2 shellcode here */
    OutputDebugStringA("argus: apc fired\n");
}

DWORD WINAPI worker(LPVOID arg) {
    (void)arg;
    SleepEx(50, TRUE);                 /* alertable wait — APC fires here */
    return 0;
}

int main(void) {
    HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    if (!t) return 1;

    /* sink: queue an APC to a thread we control; in real malware
       the target is a thread of a different (target) process */
    QueueUserAPC(apc_payload, t, 0);

    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
    return 0;
}
