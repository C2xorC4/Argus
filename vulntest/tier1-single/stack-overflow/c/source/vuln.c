/*
 * Tier 1 — stack buffer overflow (C variant).
 *
 * Single bug: strcpy() into a fixed 64-byte stack buffer with no
 * length check. argv[1] is the attacker-controlled source.
 *
 * Knowledge: [[Memory/Knowledge/hw_stack_overflow_mechanics]]
 * CWE-121: Stack-based Buffer Overflow.
 */
#include <stdio.h>
#include <string.h>

void greet(const char *name) {
    char buf[64];
    strcpy(buf, name);              /* sink: unbounded copy */
    printf("Hello, %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <name>\n", argv[0]);
        return 1;
    }
    greet(argv[1]);                 /* source: argv → tainted */
    return 0;
}
