/*
 * Tier 1 — type confusion (C variant).
 *
 * C doesn't have RTTI. Idiomatic shape: tagged union where the tag
 * is not consistently checked before accessing union members. Code
 * accesses the wrong-tag member, reinterpreting bytes as the wrong
 * type.
 *
 * Knowledge: [[Memory/Knowledge/ec_undefined_behavior_taxonomy]]
 * CWE-843.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum { TAG_INT, TAG_PTR } tag_t;

typedef struct {
    tag_t tag;
    union {
        int i;
        char *p;
    } u;
} value_t;

void process(value_t *v) {
    /* sink: assumes TAG_PTR but does not verify; if tag is TAG_INT
       we reinterpret an int as a pointer and dereference. */
    printf("ptr len=%zu\n", strlen(v->u.p));
}

int main(int argc, char **argv) {
    value_t v;
    if (argc > 1 && argv[1][0] == 'p') {
        v.tag = TAG_PTR;
        v.u.p = argv[1];
    } else {
        v.tag = TAG_INT;
        v.u.i = 0xdeadbeef;
    }
    process(&v);                          /* called regardless of tag */
    return 0;
}
