/*
 * Tier 1 — path-traversal / C — remediation.
 *
 * realpath() the constructed path, then verify the result is under
 * the BASE directory. Reject mismatches.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#define BASE "/var/data/"

int read_file(const char *name) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s%s", BASE, name);

    char resolved[PATH_MAX];
    if (!realpath(path, resolved)) return -1;

    if (strncmp(resolved, BASE, strlen(BASE)) != 0) {
        fprintf(stderr, "path escapes base\n");
        return -1;
    }

    FILE *fp = fopen(resolved, "r");
    if (!fp) return -1;
    char line[256];
    while (fgets(line, sizeof(line), fp)) fputs(line, stdout);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 1;
    }
    return read_file(argv[1]);
}
