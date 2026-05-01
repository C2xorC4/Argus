/*
 * Tier 1 — heap buffer overflow (C++ variant).
 *
 * Idiomatic C++ shape: `new char[N]` allocation, then a copy loop or
 * std::copy with attacker-controlled length. The C++ shape exposes
 * an additional sink on free path: if the adjacent heap chunk holds
 * an object with a vtable, the overflow can hijack the vptr.
 *
 * Knowledge: [[Memory/Knowledge/wnapi_heap_internals]]
 * CWE-122.
 */
#include <iostream>
#include <cstring>
#include <string>

class Buffer {
public:
    explicit Buffer(size_t n) : size_(n), data_(new char[n]) {}
    ~Buffer() { delete[] data_; }

    void store(const std::string& input) {
        std::memcpy(data_, input.data(), input.size());   // sink: unbounded
    }

    char first() const { return data_[0]; }
private:
    size_t size_;
    char* data_;
};

int main() {
    std::string line;
    std::getline(std::cin, line);            // source: stdin
    Buffer b(64);
    b.store(line);
    std::cout << "first=" << static_cast<int>(b.first()) << "\n";
    return 0;
}
