/*
 * Tier 1 — TOCTOU / C — remediation.
 *
 * Open the file once with O_NOFOLLOW (refuse symlinks); rely on
 * fstat() of the open fd for permission checks. The check is now on
 * the same kernel object the use will reference — no race window.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

int read_user_file(const char *path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    /* permission / path-prefix check would go here on st.st_uid etc. */

    FILE *fp = fdopen(fd, "r");
    if (!fp) { close(fd); return -1; }
    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) fputs(buf, stdout);
    fclose(fp);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <path>\n", argv[0]);
        return 1;
    }
    return read_user_file(argv[1]);
}
