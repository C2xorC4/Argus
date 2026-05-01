/*
 * Tier 1 — command injection (C variant).
 *
 * system() / popen() called with attacker-controlled string. Shell
 * metacharacters (`;`, `&&`, `|`, backticks, `$()`) escape into
 * shell context.
 *
 * Knowledge: legacy security_audit baseline.
 * CWE-78 (OS Command Injection).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void backup(const char *filename) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cp %s /tmp/backup/", filename);  /* sink: shell */
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <filename>\n", argv[0]);
        return 1;
    }
    backup(argv[1]);
    return 0;
}
