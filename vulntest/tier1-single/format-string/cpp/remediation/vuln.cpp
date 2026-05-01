/*
 * Tier 1 — format-string / C++ — remediation.
 *
 * Either pin the format string ("%s") or use type-safe iostreams /
 * std::format (C++20).
 */
#include <iostream>
#include <string>

void log_message(const std::string& user) {
    std::cout << user << "\n";       // type-safe; no format-string sink
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <message>\n";
        return 1;
    }
    log_message(argv[1]);
    return 0;
}
