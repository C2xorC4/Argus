/*
 * Tier 1 — command injection (C++ variant).
 *
 * Idiomatic shape: std::string concatenation feeding std::system.
 *
 * Knowledge: legacy baseline.
 * CWE-78.
 */
#include <iostream>
#include <string>
#include <cstdlib>

void backup(const std::string& filename) {
    std::string cmd = "cp " + filename + " /tmp/backup/";    // sink: shell concat
    std::system(cmd.c_str());
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <filename>\n";
        return 1;
    }
    backup(argv[1]);
    return 0;
}
