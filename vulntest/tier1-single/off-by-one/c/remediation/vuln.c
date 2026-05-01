/*
 * Tier 1 — off-by-one / C — remediation.
 *
 * Strict-less-than bound. Document semantics: len bytes processed,
 * not len+1.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void normalize(char *out, const char *in, size_t len) {
    for (size_t i = 0; i < len; ++i) {            /* fixed: < not <= */
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
    if (len > 64) len = 64;
    normalize(buf, argv[1], len);
    fwrite(buf, 1, len, stdout);
    fputc('\n', stdout);
    return 0;
}
