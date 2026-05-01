/*
 * Tier 1 — double-free / C — remediation.
 *
 * Establish single-owner discipline: the destroy helper is the
 * sole free site, callers must not free.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    int len;
} entry_t;

static void entry_destroy(entry_t *e) {
    free(e->name);
    e->name = NULL;                         /* explicit invalidation */
    e->len = 0;
}

int main(int argc, char **argv) {
    const char *src = argc > 1 ? argv[1] : "guest";
    entry_t e;
    e.name = strdup(src);
    e.len = (int)strlen(src);

    entry_destroy(&e);
    /* main no longer frees; ownership transferred to entry_destroy */
    return 0;
}
