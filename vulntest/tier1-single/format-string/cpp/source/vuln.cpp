/*
 * Tier 1 — format-string (C++ variant).
 *
 * The C-style printf survives in C++ codebases; idiomatic C++
 * (iostreams) does not have this class. The variant here demonstrates
 * the same bug in mixed C/C++ code.
 *
 * Knowledge: legacy baseline.
 * CWE-134.
 */
#include <cstdio>
#include <string>
#include <iostream>

void log_message(const std::string& user) {
    std::printf(user.c_str());      // sink: c_str() of attacker-controlled string
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <message>\n";
        return 1;
    }
    log_message(argv[1]);
    return 0;
}
