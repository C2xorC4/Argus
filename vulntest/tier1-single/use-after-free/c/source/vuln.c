/*
 * Tier 1 — use-after-free (C variant).
 *
 * Free pattern stores the freed pointer in a global; later code
 * dereferences it. Idiomatic shape for many real-world UAFs:
 * lifetime-tracking error where one path frees and another path
 * still holds a reference.
 *
 * Knowledge: [[Memory/Knowledge/wnapi_heap_internals]],
 *            [[Memory/Knowledge/em_advanced_injection_variants]]
 * CWE-416: Use After Free.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *g_session = NULL;

void session_open(const char *user) {
    g_session = (char *)malloc(64);
    if (g_session) snprintf(g_session, 64, "session:%s", user);
}

void session_close(void) {
    free(g_session);                       /* NOT nulled out */
}

void session_log(void) {
    if (g_session) {
        printf("active session: %s\n", g_session);   /* sink: dangling read */
    }
}

int main(int argc, char **argv) {
    const char *user = argc > 1 ? argv[1] : "anon";
    session_open(user);
    session_close();                       /* free */
    session_log();                         /* use after free */
    return 0;
}
