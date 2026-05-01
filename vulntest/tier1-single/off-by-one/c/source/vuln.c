/*
 * Tier 1 — off-by-one bounds check (C variant).
 *
 * Single bug: loop condition `i <= len` instead of `i < len` writes
 * one byte past the buffer. On stack, this can corrupt saved RBP's
 * low byte (frame pointer overwrite); on heap, it corrupts the next
 * chunk's size LSB.
 *
 * Knowledge: [[Memory/Knowledge/ue5_fstring_allocation_amplification]]
 * CWE-193: Off-by-one Error.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void normalize(char *out, const char *in, size_t len) {
    for (size_t i = 0; i <= len; ++i) {        /* sink: <= overruns by one */
        out[i] = (char)(in[i] | 0x20);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input>\n", argv[0]);
        return 1;
    }
    char buf[64];
    size_t len = strlen(argv[1]);
    if (len > 64) len = 64;                    /* clamp to dst size */
    normalize(buf, argv[1], len);              /* normalize writes len+1 bytes */
    fwrite(buf, 1, len, stdout);
    fputc('\n', stdout);
    return 0;
}
