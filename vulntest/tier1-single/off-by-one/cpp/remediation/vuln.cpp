/*
 * Tier 1 — off-by-one / C++ — remediation.
 *
 * Use range-for or std::transform; both eliminate the index-bound
 * class entirely.
 */
#include <iostream>
#include <array>
#include <string>
#include <algorithm>
#include <cctype>

void normalize(std::array<char, 64>& out, const std::string& in) {
    const size_t n = std::min(in.size(), out.size());
    std::transform(in.begin(), in.begin() + n, out.begin(),
                   [](char c) { return static_cast<char>(c | 0x20); });
}

int main() {
    std::string line;
    std::getline(std::cin, line);
    std::array<char, 64> buf{};
    normalize(buf, line);
    std::cout.write(buf.data(), std::min<size_t>(line.size(), buf.size())) << "\n";
    return 0;
}
