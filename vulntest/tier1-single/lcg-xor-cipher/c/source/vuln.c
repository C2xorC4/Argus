/*
 * Tier 1 — LCG / XOR string cipher (C variant).
 *
 * Anti-analysis pattern: strings stored encrypted with a Linear
 * Congruential Generator, decrypted at runtime just before use.
 * The decryption stub is the structural signature.
 *
 * Real-world: GameGuard runtime decrypts strings via LCG-XOR with
 * a function-local seed — same pattern as this cell, just larger
 * scale.
 *
 * This is itself NOT a vulnerability — it's an obfuscation pattern
 * the toolchain must recognise so it can deobfuscate strings before
 * downstream import-fingerprinting / taint-source detection.
 *
 * Knowledge: [[Memory/Knowledge/gameguard_research_22_findings]]
 * CWE-N/A (this is a detection/analysis target, not a vulnerability).
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Encrypted at build time: each byte XORed with successive LCG values.
   Plaintext: "/etc/passwd" */
static const uint8_t enc_path[] = {
    0xc4, 0xa1, 0x3a, 0xae, 0x77, 0x73, 0x1a, 0x33, 0x73, 0x4d, 0xb1
};
static const size_t enc_path_len = sizeof(enc_path);

static void lcg_xor_decrypt(char *out, const uint8_t *in, size_t n, uint32_t seed) {
    uint32_t s = seed;
    for (size_t i = 0; i < n; ++i) {
        s = s * 1103515245u + 12345u;            /* glibc rand LCG */
        out[i] = (char)(in[i] ^ (uint8_t)(s >> 16));
    }
    out[n] = 0;
}

int main(void) {
    char path[16];
    lcg_xor_decrypt(path, enc_path, enc_path_len, 0xCAFEBABE);
    printf("opening %s\n", path);
    /* in real malware: fopen(path, ...) follows */
    return 0;
}
