/*
 * Tier 1 — integer overflow leading to allocation (C variant).
 *
 * count * size wraps to a small value; the small allocation succeeds;
 * subsequent code copies attacker-sized payload into the small
 * allocation. The bug is the multiplication that overflows.
 *
 * Knowledge: [[Memory/Knowledge/ec_undefined_behavior_taxonomy]]
 *            [[Memory/Knowledge/ue5_fstring_allocation_amplification]]
 * CWE-190 (Integer Overflow), CWE-680 (Integer Overflow to Buffer Overflow).
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
    size_t bytes = count * sizeof(record_t);    /* sink: multiplication wraps */
    void *buf = malloc(bytes);
    return buf;
}

int main(int argc, char **argv) {
    size_t count = argc > 1 ? strtoull(argv[1], NULL, 10) : 1;
    record_t *recs = (record_t *)alloc_records(count);
    if (!recs) return 1;

    /* caller assumes count records of space, fills accordingly — when
       multiplication wrapped, this is a heap overflow */
    for (size_t i = 0; i < count; ++i) {
        recs[i].id = (uint32_t)i;
        memset(recs[i].tag, 'A', sizeof(recs[i].tag));
    }
    free(recs);
    return 0;
}
