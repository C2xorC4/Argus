/*
 * Tier 1 — IV reuse — remediation.
 *
 * Generate a fresh CSPRNG-derived IV for each encryption. Stack
 * buffers receive the random bytes; their addresses are not
 * data-segment constants, so the IV-reuse heuristic correctly does
 * not flag them.
 */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

int wmain(int argc, wchar_t **argv) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE k1 = NULL, k2 = NULL;
    BYTE keybytes[32] = {0};
    BYTE plaintext[16] = "hello world abc";
    BYTE ct[32] = {0};
    BYTE iv1[16], iv2[16];
    DWORD out_len = 0;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) return 1;
    BCryptGenerateSymmetricKey(alg, &k1, NULL, 0, keybytes, 32, 0);
    BCryptGenerateSymmetricKey(alg, &k2, NULL, 0, keybytes, 32, 0);

    /* fix: fresh CSPRNG IV per encryption */
    BCryptGenRandom(NULL, iv1, sizeof(iv1), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, iv2, sizeof(iv2), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    BCryptEncrypt(k1, plaintext, sizeof(plaintext), NULL,
                  iv1, sizeof(iv1), ct, sizeof(ct), &out_len, 0);
    BCryptEncrypt(k2, plaintext, sizeof(plaintext), NULL,
                  iv2, sizeof(iv2), ct, sizeof(ct), &out_len, 0);

    wprintf(L"done\n");
    BCryptDestroyKey(k1);
    BCryptDestroyKey(k2);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}
