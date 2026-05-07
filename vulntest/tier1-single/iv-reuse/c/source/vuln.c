/*
 * Tier 1 — IV reuse on AES (C / Windows).
 *
 * The same static IV is passed to two BCryptEncrypt calls under
 * (potentially different) keys. Even with strong AES, IV reuse
 * under CTR/GCM is catastrophic — keystream collisions reveal
 * plaintext XOR. Under CBC, the first ciphertext block leaks plaintext
 * equality across messages.
 *
 * Knowledge: [[Memory/Knowledge/ue5_prng_handshake_secret_recovery]]
 * CWE-329, CWE-323.
 */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

/* Static, addressable, zero-initialised — the SAME buffer is used
   for the IV in both encryption calls below. */
static BYTE shared_iv[16] = {0};

int wmain(int argc, wchar_t **argv) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k1 = NULL, k2 = NULL;
    BYTE keybytes[32] = {0};
    BYTE plaintext[16] = "hello world abc";
    BYTE ct[32] = {0};
    DWORD out_len = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) return 1;
    BCryptGenerateSymmetricKey(alg, &k1, NULL, 0, keybytes, 32, 0);
    BCryptGenerateSymmetricKey(alg, &k2, NULL, 0, keybytes, 32, 0);

    /* sink #1: encrypt with shared_iv */
    BCryptEncrypt(k1, plaintext, sizeof(plaintext), NULL,
                  shared_iv, sizeof(shared_iv),
                  ct, sizeof(ct), &out_len, 0);

    /* sink #2: encrypt AGAIN with the same shared_iv — IV reuse */
    BCryptEncrypt(k2, plaintext, sizeof(plaintext), NULL,
                  shared_iv, sizeof(shared_iv),
                  ct, sizeof(ct), &out_len, 0);

    wprintf(L"done\n");
    BCryptDestroyKey(k1);
    BCryptDestroyKey(k2);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}
