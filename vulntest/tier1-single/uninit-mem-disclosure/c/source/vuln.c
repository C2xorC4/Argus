/*
 * Tier 1 — uninitialised memory disclosure (C variant).
 *
 * Stack-allocated struct with padding bytes; only some fields are
 * filled, then the entire struct is sent to the network / stdout.
 * The padding (and any unset fields) leaks stack contents from
 * prior frames.
 *
 * This is the kernel info-leak class — Linux CVE-2017-* and many
 * similar ones are exactly this shape.
 *
 * Knowledge: [[Memory/Knowledge/ec_undefined_behavior_taxonomy]]
 * CWE-457 (Use of Uninitialized Variable),
 * CWE-908 (Use of Uninitialized Resource).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#pragma pack(push, 1)
struct status {
    uint16_t state;          /* set */
    /* implicit padding here under default packing — not filled */
    uint32_t code;           /* set */
    char     message[16];    /* declared but never filled */
    uint8_t  flags;          /* set */
};
#pragma pack(pop)

void emit_status(uint16_t state, uint32_t code, uint8_t flags) {
    struct status s;
    /* memset omitted — bug */
    s.state = state;
    s.code = code;
    s.flags = flags;
    /* s.message left uninitialised */
    fwrite(&s, 1, sizeof(s), stdout);   /* sink: write whole struct */
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    emit_status(1, 0x1234, 0x80);
    return 0;
}
