/*
 * Tier 1 — integer-overflow / C++ — remediation.
 *
 * Replace `new T[n]` with std::vector<T>, which validates against
 * SIZE_MAX/sizeof(T) on construction.
 */
#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>

struct Record {
    uint32_t id;
    char tag[16];
};

int main(int argc, char** argv) {
    size_t count = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 1;
    try {
        std::vector<Record> recs(count);
        for (size_t i = 0; i < count; ++i) {
            recs[i].id = static_cast<uint32_t>(i);
            std::memset(recs[i].tag, 'A', sizeof(recs[i].tag));
        }
    } catch (const std::bad_alloc&) {
        std::cerr << "alloc failed\n";
        return 1;
    } catch (const std::length_error&) {
        std::cerr << "count exceeds vector::max_size\n";    // overflow guard
        return 1;
    }
    return 0;
}
