#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static uint8_t ror8(uint8_t x, int n) {
    n &= 7;
    return (uint8_t)((x >> n) | (x << (8 - n)));
}

int main(void) {
    FILE *f = fopen("flag.enc", "rb");
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint32_t seed;
    fread(&seed, 4, 1, f);
    long n = sz - 4;
    uint8_t *buf = malloc(n);
    fread(buf, 1, n, f);
    fclose(f);

    srand(seed);
    for (long i = 0; i < n; i++) {
        uint8_t r1 = (uint8_t)rand();        // first rand: was XOR
        uint8_t r2 = (uint8_t)(rand() & 7);  // second: was ROL amount
        // reverse: ROR by r2 then XOR with r1
        buf[i] = ror8(buf[i], r2);
        buf[i] ^= r1;
    }
    fwrite(buf, 1, n, stdout);
    putchar('\n');
    return 0;
}
