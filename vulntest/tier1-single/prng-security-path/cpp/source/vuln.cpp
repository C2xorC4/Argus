/*
 * Tier 1 — PRNG / C++ — std::mt19937 in security path.
 *
 * std::mt19937 is faster and higher quality than rand(), but it is
 * still not a CSPRNG. Used for security-relevant output it has the
 * same predictability problem: with the seed recovered, all output
 * is reproducible.
 *
 * The canonical UE5 chain: this is closer to the actual shape than
 * the C variant — engine code typically uses a high-quality but
 * non-cryptographic PRNG.
 *
 * Knowledge: [[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]
 * CWE-338.
 */
#include <iostream>
#include <random>
#include <string>
#include <chrono>

std::string issue_token() {
    static std::mt19937 rng{
        static_cast<uint32_t>(
            std::chrono::system_clock::now().time_since_epoch().count())
    };  /* sink: time-seeded mt19937 */
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (int i = 0; i < 32; ++i) out += hex[rng() & 0xF];
    return out;
}

int main() {
    std::cout << "session=" << issue_token() << "\n";
    return 0;
}
