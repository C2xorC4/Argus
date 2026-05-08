// Optimized brute force for the Wayback challenge.
// Tests ALL year/length/sym/num combos for a given year range.
// Uses a single AES context, minimal alloc.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>

static const char *ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *NUMS  = "0123456789";
static const char *SYMS  = "!@#$%^&*_+";

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: %s <year_lo> <year_hi> <len>\n", argv[0]);
        return 1;
    }
    int yr_lo = atoi(argv[1]);
    int yr_hi = atoi(argv[2]);
    int pw_len = atoi(argv[3]);

    unsigned char ct[80];
    const char *ct_hex = "ad24426047b0ffb03b679773664838462a6f00bdcaf0589dd1748e9ed5c568601edc87d974894f9dd9b98cc35535145c494eb0af84c8f78d440a033c91c7de62d506d8cabdc2a10138b95139bbe60e89";
    for (int i = 0; i < 80; i++) sscanf(ct_hex + i*2, "%2hhx", &ct[i]);

    int days_in_month[] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32], pt[80], pt2[80];
    char pw[64];

    for (int sn = 0; sn < 4; sn++) {
        int sym = sn & 1, num = (sn >> 1) & 1;
        char alphabet[256];
        int alpha_len = 52;
        memcpy(alphabet, ALPHA, 52);
        if (sym) { memcpy(alphabet + alpha_len, SYMS, 10); alpha_len += 10; }
        if (num) { memcpy(alphabet + alpha_len, NUMS, 10); alpha_len += 10; }

        for (int year = yr_lo; year <= yr_hi; year++) {
            int yr_off = year - 1900;
            unsigned int yr_term = (unsigned int)(yr_off + 1900) * 0x540be400U;

            fprintf(stderr, "year=%d sym=%d num=%d len=%d\n", year, sym, num, pw_len);

            for (int mon = 0; mon < 12; mon++) {
                unsigned int mon_term = (unsigned int)(mon + 1) * 0x5f5e100U;
                int dim = days_in_month[mon];
                for (int day = 1; day <= dim; day++) {
                    unsigned int day_term = (unsigned int)day * 1000000U;
                    for (int hour = 0; hour < 24; hour++) {
                        unsigned int hr_term = (unsigned int)hour * 10000U;
                        for (int minute = 0; minute < 60; minute++) {
                            unsigned int mn_term = (unsigned int)minute * 100U;
                            for (int sec = 0; sec < 60; sec++) {
                                unsigned int seed = day_term + mn_term + sec + hr_term + yr_term + mon_term;
                                srand(seed);
                                for (int i = 0; i < pw_len; i++) {
                                    pw[i] = alphabet[rand() % alpha_len];
                                }
                                memset(key, 0, 32);
                                memcpy(key, pw, pw_len > 32 ? 32 : pw_len);

                                int len;
                                EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, ct);
                                EVP_CIPHER_CTX_set_padding(ctx, 0);
                                if (EVP_DecryptUpdate(ctx, pt, &len, ct + 16, 64) == 1) {
                                    // Valid PKCS7 padding: last byte n in [1,16], last n bytes all == n
                                    unsigned char pad = pt[63];
                                    int valid = (pad >= 1 && pad <= 16);
                                    if (valid) {
                                        for (int p = 0; p < pad; p++) {
                                            if (pt[63 - p] != pad) { valid = 0; break; }
                                        }
                                    }
                                    // Check printable in unpadded region
                                    if (valid) {
                                        int unpadded_len = 64 - pad;
                                        int all_printable = 1;
                                        for (int p = 0; p < unpadded_len; p++) {
                                            if (pt[p] < 0x20 || pt[p] > 0x7e) {
                                                if (pt[p] != '\n' && pt[p] != '\t') { all_printable = 0; break; }
                                            }
                                        }
                                        if (all_printable) {
                                            printf("CANDIDATE %d-%02d-%02d %02d:%02d:%02d sym=%d num=%d len=%d pad=%d  pw=",
                                                year, mon+1, day, hour, minute, sec, sym, num, pw_len, pad);
                                            for (int i = 0; i < pw_len; i++) printf("%c", pw[i]);
                                            printf("\n  msg: ");
                                            for (int i = 0; i < unpadded_len; i++) printf("%c", pt[i]);
                                            printf("\n");
                                            fflush(stdout);
                                            if (pt[0] == 'H' && pt[1] == 'T' && pt[2] == 'B' && pt[3] == '{') {
                                                printf("=== MATCH ===\n");
                                                EVP_CIPHER_CTX_free(ctx);
                                                return 0;
                                            }
                                        }
                                    }
                                }
                                EVP_CIPHER_CTX_reset(ctx);
                            }
                        }
                    }
                }
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    fprintf(stderr, "no match for years %d-%d len=%d\n", yr_lo, yr_hi, pw_len);
    return 1;
}
