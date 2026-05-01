/*
 * Tier 1 — TOCTOU / time-of-check time-of-use (C variant).
 *
 * Pattern: access(path, R_OK) followed by fopen(path, ...). Between
 * the two calls, an attacker swaps the path target via symlink /
 * junction redirect, gaining a privileged read of a different file.
 *
 * Knowledge: [[Memory/Knowledge/eac_eos_arbitrary_write_chain]]
 *            (junction-redirect race in admin → SYSTEM scenario)
 * CWE-367 (TOCTOU).
 */
#include <stdio.h>
#include <unistd.h>

int read_user_file(const char *path) {
    if (access(path, R_OK) != 0) {       /* check */
        return -1;
    }
    /* attacker swaps path target here — symlink redirect */
    FILE *fp = fopen(path, "r");          /* use */
    if (!fp) return -1;
    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) fputs(buf, stdout);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 1;
    }
    return read_user_file(argv[1]);
}
