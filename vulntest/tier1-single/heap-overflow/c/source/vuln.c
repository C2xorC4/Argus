/*
 * Tier 1 — heap buffer overflow (C variant).
 *
 * Single bug: malloc(N) followed by memcpy with attacker-controlled
 * length. Adjacent heap chunks (and chunk metadata under glibc /
 * Windows heap) are corruptible.
 *
 * Knowledge: [[Memory/Knowledge/wnapi_heap_internals]]
 * CWE-122: Heap-based Buffer Overflow.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 64

int handle(const char *input, size_t len) {
    char *buf = (char *)malloc(BUF_SIZE);
    if (!buf) return -1;
    memcpy(buf, input, len);            /* sink: len is attacker-controlled */
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
