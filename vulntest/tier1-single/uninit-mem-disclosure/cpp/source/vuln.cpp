/*
 * Tier 1 — uninitialised memory disclosure (C++ variant).
 *
 * Same shape as C; uses C++ class with default member init missing.
 * Default-initialised PODs in C++ have indeterminate values for
 * fundamental types; same hazard as C struct.
 *
 * Knowledge: [[Memory/Knowledge/ec_undefined_behavior_taxonomy]]
 * CWE-457, CWE-908.
 */
#include <iostream>
#include <cstdint>

#pragma pack(push, 1)
struct Status {
    uint16_t state;
    uint32_t code;
    char     message[16];
    uint8_t  flags;
};
#pragma pack(pop)

void emit_status(uint16_t state, uint32_t code, uint8_t flags) {
    Status s;                            // default-init: indeterminate
    s.state = state;
    s.code = code;
    s.flags = flags;
    std::cout.write(reinterpret_cast<const char*>(&s), sizeof(s));
}

int main() {
    emit_status(1, 0x1234, 0x80);
    return 0;
}
