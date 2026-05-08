// Brute-force the time seed for the Wayback challenge.
// The binary's seed = day*1000000 + min*100 + sec + hour*10000
//                   + (year+1900)*0x540be400 + (month+1)*0x5f5e100
// where year is tm_year (years since 1900), month is tm_mon (0-11).
// Iterate over all (mon, day, hour, min, sec) for a target year.
// For each, generate the deterministic password, use it as AES-256-CBC key
// (NUL-padded to 32 bytes) to decrypt the inline ciphertext. If plaintext
// starts with "HTB{", print and exit.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

static const char *ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *NUMS = "0123456789";
static const char *SYMS = "!@#$%^&*_+";

static int try_decrypt(const unsigned char *ct, int ct_len,
                       const unsigned char *key, unsigned char *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plen = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, ct);
    EVP_CIPHER_CTX_set_padding(ctx, 1);
    if (EVP_DecryptUpdate(ctx, pt, &len, ct + 16, ct_len - 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plen = len;
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    plen += len;
    pt[plen] = 0;
    EVP_CIPHER_CTX_free(ctx);
    return plen;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <year> <length> <sym 0/1> <num 0/1>\n", argv[0]);
        return 1;
    }
    int year = atoi(argv[1]) - 1900;
    int pw_len = atoi(argv[2]);
    int sym = atoi(argv[3]);
    int num = atoi(argv[4]);

    char alphabet[256];
    int alpha_len = 0;
    memcpy(alphabet, ALPHA, 52);
    alpha_len = 52;
    if (sym) {
        memcpy(alphabet + alpha_len, SYMS, 10);
        alpha_len += 10;
    }
    if (num) {
        memcpy(alphabet + alpha_len, NUMS, 10);
        alpha_len += 10;
    }

    unsigned char ct[80];
    const char *ct_hex = "ad24426047b0ffb03b679773664838462a6f00bdcaf0589dd1748e9ed5c568601edc87d974894f9dd9b98cc35535145c494eb0af84c8f78d440a033c91c7de62d506d8cabdc2a10138b95139bbe60e89";
    for (int i = 0; i < 80; i++) {
        sscanf(ct_hex + i*2, "%2hhx", &ct[i]);
    }

    int days_in_month[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    unsigned char key[32], pt[80];
    char pw[64];

    long long count = 0;
    for (int mon = 0; mon < 12; mon++) {
        for (int day = 1; day <= days_in_month[mon]; day++) {
            for (int hour = 0; hour < 24; hour++) {
                for (int min = 0; min < 60; min++) {
                    for (int sec = 0; sec < 60; sec++) {
                        unsigned int seed = day * 1000000U
                                          + min * 100U
                                          + sec
                                          + hour * 10000U
                                          + (unsigned int)(year + 1900) * 0x540be400U
                                          + (unsigned int)(mon + 1) * 0x5f5e100U;
                        srand(seed);
                        for (int i = 0; i < pw_len; i++) {
                            pw[i] = alphabet[rand() % alpha_len];
                        }
                        pw[pw_len] = 0;
                        memset(key, 0, 32);
                        memcpy(key, pw, pw_len > 32 ? 32 : pw_len);
                        if (try_decrypt(ct, 80, key, pt) > 0) {
                            if (pt[0] == 'H' && pt[1] == 'T' && pt[2] == 'B' && pt[3] == '{') {
                                printf("FOUND! %d-%02d-%02d %02d:%02d:%02d  pw=%s\n",
                                       year + 1900, mon + 1, day, hour, min, sec, pw);
                                printf("  flag: %s\n", pt);
                                return 0;
                            }
                        }
                        count++;
                    }
                }
            }
            if (count % 1000000 < 60) {
                fprintf(stderr, "  ... %d-%02d-%02d (count=%lld)\n",
                        year + 1900, mon + 1, day, count);
            }
        }
    }
    fprintf(stderr, "no match for year %d (count=%lld)\n", year + 1900, count);
    return 1;
}
