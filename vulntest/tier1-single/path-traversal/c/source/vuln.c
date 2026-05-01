/*
 * Tier 1 — path traversal (C variant).
 *
 * Filename concat without canonicalisation; "../" segments escape
 * the intended directory. Reads / writes outside the sandbox.
 *
 * Knowledge: legacy baseline.
 * CWE-22 (Path Traversal), CWE-23 (Relative Path Traversal).
 */
#include <stdio.h>
#include <string.h>

#define BASE "/var/data/"

int read_file(const char *name) {
    char path[256];
    snprintf(path, sizeof(path), "%s%s", BASE, name);     /* sink: no canonicalise */
    FILE *fp = fopen(path, "r");
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
