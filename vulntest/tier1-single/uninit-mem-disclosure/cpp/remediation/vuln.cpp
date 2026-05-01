/*
 * Tier 1 — uninit-mem / C++ — remediation.
 *
 * Value-initialise via {} or assign default member values in the
 * struct declaration.
 */
#include <iostream>
#include <cstdint>
#include <cstring>

#pragma pack(push, 1)
struct Status {
    uint16_t state{};
    uint32_t code{};
    char     message[16]{};
    uint8_t  flags{};
};
#pragma pack(pop)

void emit_status(uint16_t state, uint32_t code, uint8_t flags) {
    Status s{};                          // value-init: all fields zero
    s.state = state;
    s.code = code;
    s.flags = flags;
    std::cout.write(reinterpret_cast<const char*>(&s), sizeof(s));
}

int main() {
    emit_status(1, 0x1234, 0x80);
    return 0;
}
