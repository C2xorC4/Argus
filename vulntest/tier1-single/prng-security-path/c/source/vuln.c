/*
 * Tier 1 — PRNG in security-relevant path (C variant).
 *
 * rand() / srand(time(NULL)) used to generate a session token. The
 * non-CSPRNG output is predictable, allowing an attacker who knows
 * approximate connection time to reproduce or precompute tokens.
 *
 * The canonical real-world manifestation: UE5 HandshakeSecret was
 * derived from FMath::Rand() (a non-CSPRNG); offline brute force /
 * synchronous prediction recovered the secret.
 *
 * Knowledge: [[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]
 * CWE-338, CWE-330.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

void issue_token(char *out, size_t n) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned)time(NULL));     /* sink: time-seeded PRNG */
        seeded = 1;
    }
    for (size_t i = 0; i < n - 1; ++i) {
        out[i] = "0123456789abcdef"[rand() & 0xF];   /* sink: rand() in security path */
    }
    out[n - 1] = '\0';
}

int main(void) {
    char token[33];
    issue_token(token, sizeof(token));
    printf("session=%s\n", token);
    return 0;
}
