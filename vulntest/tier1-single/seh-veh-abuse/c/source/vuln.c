/*
 * Tier 1 — SEH/VEH handler abuse (C / Windows).
 *
 * Installs a vectored exception handler that gains control on any
 * exception. Combined with a deliberate exception trigger, this
 * gives the attacker an execution slot that bypasses straightforward
 * call-trace tracking.
 *
 * Knowledge: [[Memory/Knowledge/em_covert_execution_tls_seh]]
 *            [[Memory/Knowledge/em_veh_hwbp_hook_evasion]]
 */
#include <windows.h>
#include <stdio.h>

LONG CALLBACK veh_handler(PEXCEPTION_POINTERS info) {
    /* sink: VEH gains control on any first-chance exception */
    fprintf(stderr, "veh: exc=%lx addr=%p\n",
            info->ExceptionRecord->ExceptionCode,
            info->ExceptionRecord->ExceptionAddress);
    info->ContextRecord->Rip += 2;        /* skip the offending instruction */
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main(void) {
    AddVectoredExceptionHandler(1, veh_handler);

    /* deliberately trigger an exception so VEH fires */
    __try {
        int *p = NULL;
        *p = 0xdeadbeef;                   /* AV — handled by VEH */
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("seh caught exception\n");
    }

    printf("main continues\n");
    return 0;
}
