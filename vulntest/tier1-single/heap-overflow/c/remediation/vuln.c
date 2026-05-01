/*
 * Tier 1 — heap-overflow / C — remediation.
 *
 * Bound the copy by the allocation size.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 64

int handle(const char *input, size_t len) {
    if (len > BUF_SIZE) len = BUF_SIZE;          /* clamp */
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) return -1;
    memcpy(buf, input, len);
    int result = (int)buf[0];
    free(buf);
    return result;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input>\n", argv[0]);
        return 1;
    }
    return handle(argv[1], strlen(argv[1]));
}
