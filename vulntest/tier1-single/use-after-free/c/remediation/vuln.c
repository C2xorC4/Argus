/*
 * Tier 1 — UAF / C — remediation.
 *
 * Null the pointer after free. session_log's null check then
 * correctly skips the dangling read.
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
    free(g_session);
    g_session = NULL;                   /* fix: invalidate handle */
}

void session_log(void) {
    if (g_session) {
        printf("active session: %s\n", g_session);
    }
}

int main(int argc, char **argv) {
    const char *user = argc > 1 ? argv[1] : "anon";
    session_open(user);
    session_close();
    session_log();
    return 0;
}
