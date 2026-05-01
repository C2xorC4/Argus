/*
 * Tier 1 — integer overflow → allocation (C++ variant).
 *
 * C++ shape: `new T[n]` with attacker-controlled n. operator new[]
 * computes total size = n * sizeof(T) + array-cookie internally;
 * the multiplication is the same hazard as C's malloc(count*size).
 *
 * Modern C++ (since CWG-1748 / [expr.new]) requires the implementation
 * to throw bad_array_new_length on overflow — but the requirement is
 * frequently misimplemented, especially under MSVC pre-19.x.
 *
 * Knowledge: [[Memory/Knowledge/ec_undefined_behavior_taxonomy]]
 * CWE-190, CWE-680.
 */
#include <iostream>
#include <cstring>
#include <cstdint>

struct Record {
    uint32_t id;
    char tag[16];
};

Record* alloc_records(size_t count) {
    return new Record[count];          // sink: implementation-defined overflow check
}

int main(int argc, char** argv) {
    size_t count = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 1;
    Record* recs = alloc_records(count);
    for (size_t i = 0; i < count; ++i) {
        recs[i].id = static_cast<uint32_t>(i);
        std::memset(recs[i].tag, 'A', sizeof(recs[i].tag));
    }
    delete[] recs;
    return 0;
}
