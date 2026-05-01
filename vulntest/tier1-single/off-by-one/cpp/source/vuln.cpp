/*
 * Tier 1 — off-by-one (C++ variant).
 *
 * Same pattern as C: inclusive loop bound writes one element past
 * a fixed-size container. Idiomatic C++ would use range-for or
 * iterators and largely eliminate the class — this cell exists
 * because real codebases mix C-style loops with C++ containers.
 *
 * Knowledge: [[Memory/Knowledge/ue5_fstring_allocation_amplification]]
 * CWE-193.
 */
#include <iostream>
#include <array>
#include <string>

void normalize(std::array<char, 64>& out, const std::string& in) {
    const size_t len = std::min(in.size(), out.size());
    for (size_t i = 0; i <= len; ++i) {            // sink: <= overruns
        out[i] = static_cast<char>(in[i] | 0x20);
    }
}

int main() {
    std::string line;
    std::getline(std::cin, line);
    std::array<char, 64> buf{};
    normalize(buf, line);
    std::cout.write(buf.data(), std::min<size_t>(line.size(), buf.size())) << "\n";
    return 0;
}
