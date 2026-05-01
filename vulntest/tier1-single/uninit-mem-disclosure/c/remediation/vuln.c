/*
 * Tier 1 — uninit-mem disclosure / C — remediation.
 *
 * Zero the struct before partial fill. memset() is the standard
 * pattern; designated-initialiser syntax `{0}` also zeros all
 * unspecified fields.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#pragma pack(push, 1)
struct status {
    uint16_t state;
    uint32_t code;
    char     message[16];
    uint8_t  flags;
};
#pragma pack(pop)

void emit_status(uint16_t state, uint32_t code, uint8_t flags) {
    struct status s = {0};               /* zero everything first */
    s.state = state;
    s.code = code;
    s.flags = flags;
    fwrite(&s, 1, sizeof(s), stdout);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    emit_status(1, 0x1234, 0x80);
    return 0;
}
