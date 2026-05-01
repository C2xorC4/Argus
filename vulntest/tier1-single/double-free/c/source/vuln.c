/*
 * Tier 1 — double-free (C variant).
 *
 * Two free paths execute on the same pointer because the caller and
 * an internal cleanup both free. tcache double-free corruption is
 * the canonical exploitation target on modern glibc.
 *
 * Knowledge: [[Memory/Knowledge/wnapi_heap_internals]]
 * CWE-415.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *name;
    int len;
} entry_t;

static void entry_destroy(entry_t *e) {
    free(e->name);                          /* free #1 */
    e->name = (char *)(uintptr_t)0xdeadbeef; /* sentinel — but caller doesn't know */
    e->len = -1;
}

int main(int argc, char **argv) {
    const char *src = argc > 1 ? argv[1] : "guest";
    entry_t e;
    e.name = strdup(src);
    e.len = (int)strlen(src);

    entry_destroy(&e);
    free(e.name);                           /* free #2 — double-free */
    return 0;
}
