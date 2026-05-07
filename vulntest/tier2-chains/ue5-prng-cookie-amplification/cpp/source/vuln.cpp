/*
 * Tier 2 — UE5 PRNG → cookie-forge → amplification (cpp / Linux+Win).
 *
 * Skeleton of the UE5 server-crash chain. Three intended primitives:
 *   1. Weak-PRNG-derived handshake secret (mt19937 seeded from clock).
 *   2. Signed-token bypass — secret recoverable by attacker, so any
 *      client-supplied "signed" cookie is forgeable.
 *   3. FString-style size amplification — server allocates buffer
 *      from attacker-supplied length before bounds-checking content.
 *
 * Argus emits today (2026-05-07):
 *   - `weak_prng_in_security_path` (Path C: mt19937 + security-named
 *     function `update_handshake_secret` + no CSPRNG imports)
 *   - `chain_pattern` (UE5 chain template, gated by min_primitives=1)
 *
 * The other two primitive detectors are aspirational — see
 * `heuristics/chains.py:UE5_PRNG_COOKIE_AMPLIFICATION` for the
 * deferred-detector annotation.
 *
 * Knowledge:
 *   `[[Memory/Knowledge/ue5_server_crash_chain_prng_fstring]]`
 *   `[[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]`
 *   `[[Memory/Knowledge/ue5_fstring_allocation_amplification]]`
 */
#include <iostream>
#include <random>
#include <chrono>
#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <cstring>

class HandshakeState {
public:
    /* Component 1 — weak PRNG seeds the handshake secret. */
    void update_handshake_secret() {
        static std::mt19937 rng{
            static_cast<uint32_t>(
                std::chrono::system_clock::now().time_since_epoch().count())
        };
        for (auto &b : handshake_secret_) {
            b = static_cast<uint8_t>(rng() & 0xFF);
        }
    }

    /* Component 2 — sign with recoverable secret. Trivial XOR is a
       stand-in for "HMAC under a key the attacker can recover." A
       real detector for `signed_token_with_recoverable_secret`
       would correlate the PRNG-derived buffer to an HMAC / signature
       call; here we just XOR for fixture purposes. */
    std::vector<uint8_t> sign_cookie(const std::vector<uint8_t> &cookie) {
        std::vector<uint8_t> out(cookie.size());
        for (size_t i = 0; i < cookie.size(); ++i) {
            out[i] = cookie[i] ^ handshake_secret_[i % handshake_secret_.size()];
        }
        return out;
    }

    /* Component 3 — size amplification: allocate buffer based on
       attacker-supplied size before validating content. Argus's
       heap-OF / pre-verify-write detectors don't fire on this
       precise shape; a dedicated `size_amplification` detector
       would. */
    std::vector<uint8_t> deserialise_fstring(uint32_t attacker_size,
                                             const uint8_t *data,
                                             size_t avail) {
        std::vector<uint8_t> buf;
        buf.reserve(attacker_size);            /* untrusted size */
        size_t copy = (avail < attacker_size) ? avail : attacker_size;
        buf.insert(buf.end(), data, data + copy);
        return buf;
    }

private:
    std::array<uint8_t, 64> handshake_secret_{};
};

int main(int argc, char **argv) {
    HandshakeState hs;
    hs.update_handshake_secret();

    std::vector<uint8_t> cookie = {1, 2, 3, 4, 5, 6, 7, 8};
    auto signed_cookie = hs.sign_cookie(cookie);

    if (argc > 1) {
        uint32_t sz = static_cast<uint32_t>(std::stoul(argv[1]));
        const uint8_t fake_payload[] = "ABCDEFGH";
        auto deserialised = hs.deserialise_fstring(sz, fake_payload,
                                                   sizeof(fake_payload));
        std::cout << "deserialised " << deserialised.size() << " bytes\n";
    }

    std::cout << "signed cookie len=" << signed_cookie.size() << "\n";
    return 0;
}
