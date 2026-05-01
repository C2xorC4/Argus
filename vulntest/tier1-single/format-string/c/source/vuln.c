/*
 * Tier 1 — format-string (C variant).
 *
 * printf with attacker-controlled format string. Provides arbitrary
 * read (%x, %s, %p) and arbitrary write (%n) primitives.
 *
 * Historical exploit class — largely killed by FORTIFY_SOURCE and
 * compiler warnings, but resurfaces in code paths that bypass the
 * checked variants (sprintf into local buffer, syslog, vendor-
 * private printf-likes).
 *
 * Knowledge: legacy security_audit baseline; see also
 * [[Memory/Knowledge/em_advanced_injection_variants]] for the
 * format-string-as-leak-primitive pattern.
 * CWE-134.
 */
#include <stdio.h>

void log_message(const char *user) {
    printf(user);                    /* sink: format string == user */
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <message>\n", argv[0]);
        return 1;
    }
    log_message(argv[1]);
    return 0;
}
