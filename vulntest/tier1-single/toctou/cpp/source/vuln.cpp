/*
 * Tier 1 — TOCTOU (C++ variant).
 *
 * std::filesystem::exists() check followed by std::ifstream open.
 * Idiomatic but vulnerable C++ shape.
 *
 * Knowledge: [[Memory/Knowledge/eac_eos_arbitrary_write_chain]]
 * CWE-367.
 */
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

int read_user_file(const fs::path& p) {
    if (!fs::exists(p)) return -1;          // check
    /* race window */
    std::ifstream in(p);                    // use
    if (!in) return -1;
    std::cout << in.rdbuf();
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <path>\n";
        return 1;
    }
    return read_user_file(argv[1]);
}
