/*
 * Tier 1 — command injection / C — remediation.
 *
 * Use exec*() with explicit argv array; no shell involved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

void backup(const char *filename) {
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/cp", "cp", filename, "/tmp/backup/", (char*)NULL);
        _exit(127);
    }
    waitpid(pid, NULL, 0);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <filename>\n", argv[0]);
        return 1;
    }
    backup(argv[1]);
    return 0;
}
