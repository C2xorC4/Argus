/*
 * Tier 1 — path-traversal / C++ — remediation.
 *
 * std::filesystem::weakly_canonical (or canonical for existence-
 * required) resolves "..", then verify prefix.
 */
#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>

namespace fs = std::filesystem;

int read_file(const std::string& name) {
    fs::path base = fs::canonical("/var/data/");
    fs::path full = base / name;

    std::error_code ec;
    fs::path resolved = fs::weakly_canonical(full, ec);
    if (ec) return -1;

    auto rel = fs::relative(resolved, base, ec);
    if (ec || rel.empty() || *rel.begin() == "..") {
        std::cerr << "path escapes base\n";
        return -1;
    }

    std::ifstream in(resolved);
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
