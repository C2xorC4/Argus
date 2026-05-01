/*
 * Tier 1 — TOCTOU / C++ — remediation.
 *
 * Open the file once and use the resulting stream / fd. C++ has
 * no portable O_NOFOLLOW equivalent in the standard library; drop
 * to platform open() + fdopen() / std::ifstream(__from_fd) in
 * compilers that support it.
 */
#include <iostream>
#include <fstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int read_user_file(const char* path) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { close(fd); return -1; }

    FILE* fp = fdopen(fd, "r");
    if (!fp) { close(fd); return -1; }

    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) std::cout << buf;
    fclose(fp);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage\n"; return 1; }
    return read_user_file(argv[1]);
}
