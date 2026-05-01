/*
 * Tier 1 — integer-overflow / C — remediation.
 *
 * Use checked-arithmetic primitive (__builtin_mul_overflow) or
 * compare against a precomputed safe ceiling.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    uint32_t id;
    char tag[16];
} record_t;

void* alloc_records(size_t count) {
    size_t bytes;
    if (__builtin_mul_overflow(count, sizeof(record_t), &bytes)) {
        return NULL;                       /* overflow detected */
    }
    return malloc(bytes);
}

int main(int argc, char **argv) {
    size_t count = argc > 1 ? strtoull(argv[1], NULL, 10) : 1;
    record_t *recs = (record_t *)alloc_records(count);
    if (!recs) {
        fprintf(stderr, "alloc failed (overflow guard or OOM)\n");
        return 1;
    }
    for (size_t i = 0; i < count; ++i) {
        recs[i].id = (uint32_t)i;
        memset(recs[i].tag, 'A', sizeof(recs[i].tag));
    }
    free(recs);
    return 0;
}
