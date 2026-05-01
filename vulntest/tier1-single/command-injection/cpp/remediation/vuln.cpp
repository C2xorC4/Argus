/*
 * Tier 1 — command injection / C++ — remediation.
 *
 * Use posix_spawn (POSIX) or CreateProcess (Windows) with explicit
 * argv array. Or std::system with strict allow-list validation if
 * shell semantics are unavoidable.
 */
#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>

bool valid_filename(const std::string& f) {
    for (char c : f) if (!(isalnum(c) || c == '.' || c == '_' || c == '/')) return false;
    return !f.empty();
}

int backup(const std::string& filename) {
    if (!valid_filename(filename)) return -1;            // allow-list
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/cp", "cp", filename.c_str(), "/tmp/backup/", (char*)nullptr);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <filename>\n";
        return 1;
    }
    return backup(argv[1]);
}
