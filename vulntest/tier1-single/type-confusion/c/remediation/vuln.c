/*
 * Tier 1 — type-confusion / C — remediation.
 *
 * Switch on the tag and only access the matching union member.
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
    switch (v->tag) {
    case TAG_PTR:
        printf("ptr len=%zu\n", v->u.p ? strlen(v->u.p) : 0);
        break;
    case TAG_INT:
        printf("int=%d\n", v->u.i);
        break;
    }
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
    process(&v);
    return 0;
}
