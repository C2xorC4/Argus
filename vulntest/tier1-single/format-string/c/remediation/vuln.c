/*
 * Tier 1 — format-string / C — remediation.
 */
#include <stdio.h>

void log_message(const char *user) {
    printf("%s", user);              /* literal format string; user as %s arg */
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <message>\n", argv[0]);
        return 1;
    }
    log_message(argv[1]);
    return 0;
}
