/*
 * Tier 1 — path-traversal (C++ variant).
 *
 * std::ifstream with concatenated path. Same primitive as C variant;
 * std::filesystem::path arithmetic uses operator/ which preserves
 * "../" segments unless explicitly canonicalised.
 *
 * Knowledge: legacy baseline.
 * CWE-22.
 */
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

int read_file(const std::string& name) {
    fs::path base = "/var/data/";
    fs::path full = base / name;          // sink: no canonicalise / no prefix-check
    std::ifstream in(full);
    if (!in) return -1;
    std::cout << in.rdbuf();
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <name>\n";
        return 1;
    }
    return read_file(argv[1]);
}
