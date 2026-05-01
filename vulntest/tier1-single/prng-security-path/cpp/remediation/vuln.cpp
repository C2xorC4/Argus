/*
 * Tier 1 — PRNG / C++ — remediation.
 *
 * std::random_device is the C++ idiom for OS-CSPRNG access (when
 * available; some implementations of random_device fall back to a
 * deterministic generator — verify per platform).
 *
 * Safer: call platform CSPRNG directly (BCryptGenRandom on Windows,
 * getrandom() on Linux).
 */
#include <iostream>
#include <random>
#include <string>

std::string issue_token() {
    std::random_device rd;               // OS CSPRNG (typically)
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (int i = 0; i < 32; ++i) out += hex[rd() & 0xF];
    return out;
}

int main() {
    std::cout << "session=" << issue_token() << "\n";
    return 0;
}
