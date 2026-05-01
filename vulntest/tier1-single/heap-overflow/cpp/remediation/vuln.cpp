/*
 * Tier 1 — heap-overflow / C++ — remediation.
 *
 * Replace raw `new char[]` with std::vector<char> and bound the
 * copy at the destination capacity. Or use std::string directly.
 */
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

class Buffer {
public:
    explicit Buffer(size_t n) : data_(n) {}
    void store(const std::string& input) {
        const size_t n = std::min(input.size(), data_.size());
        std::copy_n(input.begin(), n, data_.begin());
    }
    char first() const { return data_.empty() ? 0 : data_[0]; }
private:
    std::vector<char> data_;
};

int main() {
    std::string line;
    std::getline(std::cin, line);
    Buffer b(64);
    b.store(line);
    std::cout << "first=" << static_cast<int>(b.first()) << "\n";
    return 0;
}
