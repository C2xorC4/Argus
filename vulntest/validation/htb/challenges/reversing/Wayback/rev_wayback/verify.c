// Generate a single password using the same logic as V1, given fixed time fields.
// Used to sanity-check the brute-force generator against running V1 with faked time.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char *NUMS = "0123456789";
static const char *SYMS = "!@#$%^&*_+";

int main(int argc, char **argv) {
    // year(4-digit), mon(0-11), day, hour, min, sec, len, sym, num
    int year = atoi(argv[1]) - 1900;
    int mon = atoi(argv[2]);
    int day = atoi(argv[3]);
    int hour = atoi(argv[4]);
    int min = atoi(argv[5]);
    int sec = atoi(argv[6]);
    int pw_len = atoi(argv[7]);
    int sym = atoi(argv[8]);
    int num = atoi(argv[9]);

    char alphabet[256];
    int alpha_len = 0;
    memcpy(alphabet, ALPHA, 52); alpha_len = 52;
    if (sym) { memcpy(alphabet + alpha_len, SYMS, 10); alpha_len += 10; }
    if (num) { memcpy(alphabet + alpha_len, NUMS, 10); alpha_len += 10; }

    unsigned int seed = day * 1000000U + min * 100U + sec
                      + hour * 10000U
                      + (unsigned int)(year + 1900) * 0x540be400U
                      + (unsigned int)(mon + 1) * 0x5f5e100U;
    srand(seed);
    char pw[64];
    for (int i = 0; i < pw_len; i++) pw[i] = alphabet[rand() % alpha_len];
    pw[pw_len] = 0;
    printf("%s\n", pw);
    return 0;
}
