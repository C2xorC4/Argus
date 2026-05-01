/*
 * Tier 1 — LCG / XOR string cipher (C++ variant).
 *
 * Same obfuscation in C++ — typical shape: constexpr ciphertext
 * baked into a string_view, runtime decrypt to std::string. Modern
 * variants use C++14 constexpr to encrypt at compile time.
 *
 * Knowledge: [[Memory/Knowledge/gameguard_research_22_findings]]
 */
#include <iostream>
#include <array>
#include <string>
#include <cstdint>

constexpr std::array<uint8_t, 11> enc_path = {
    0xc4, 0xa1, 0x3a, 0xae, 0x77, 0x73, 0x1a, 0x33, 0x73, 0x4d, 0xb1
};

std::string lcg_xor_decrypt(const uint8_t* in, size_t n, uint32_t seed) {
    uint32_t s = seed;
    std::string out(n, '\0');
    for (size_t i = 0; i < n; ++i) {
        s = s * 1103515245u + 12345u;
        out[i] = static_cast<char>(in[i] ^ static_cast<uint8_t>(s >> 16));
    }
    return out;
}

int main() {
    auto path = lcg_xor_decrypt(enc_path.data(), enc_path.size(), 0xCAFEBABE);
    std::cout << "opening " << path << "\n";
    return 0;
}
