/*
 * Tier 1 — stack-overflow / C — remediation.
 *
 * Idiomatic fix: bounded copy via snprintf. snprintf is preferred
 * over strncpy because strncpy does not guarantee NUL termination
 * when the source is longer than the destination.
 */
#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%s", name);   /* bounded, NUL-terminated */
    printf("Hello, %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 1;
    }
    greet(argv[1]);
    return 0;
}
