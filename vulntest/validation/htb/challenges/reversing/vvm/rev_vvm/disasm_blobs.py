#!/usr/bin/env python3
"""Disassemble each decrypted blob to identify opcode semantics."""

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from pathlib import Path
import struct

BINARY = Path(r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\vvm\rev_vvm\vvm")

KEY = [0x2a, 0x0b, 0x21, 0x21, 0x4d, 0x2a]
IMAGE_BASE = 0x400000


def vfo(va):
    return va - IMAGE_BASE - 0x4d70 + 0x3d70


# (op_index, source_va, size, label)
# op_index = dest_off // 8, ordered
BLOBS_BY_OP = {
    0:  (0x405160, 0x35, "blob10"),
    1:  (0x4053e0, 0x25, "blob14"),
    2:  (0x405420, 0x24, "blob21"),
    # 3 is sub_401320 (PUSH_INT, native)
    4:  (0x405460, 0x24, "blob18"),
    5:  (0x4054e0, 0x19, "blob22"),
    6:  (0x4054a0, 0x20, "blob24"),
    # 7 is sub_4013e0 (EXIT, native)
    8:  (0x405380, 0x20, "blob12"),
    9:  (0x405300, 0x38, "blob05"),
    # 10 is sub_4013a0 (PRINTF, native)
    11: (0x405260, 0x12, "blob04"),
    12: (0x405360, 0x1b, "blob23"),
    13: (0x405120, 0x3b, "blob09"),
    14: (0x405500, 0x14, "blob08"),
    # 15 is sub_4012a0 (PUSH_BYTES, native)
    16: (0x4051a0, 0x28, "blob11"),
    17: (0x405020, 0xb3, "blob06"),
    18: (0x4050e0, 0x2a, "blob02"),
    19: (0x4052c0, 0x25, "blob17"),
    20: (0x405280, 0x25, "blob07"),
    21: (0x405340, 0x1b, "blob01"),
    22: (0x405200, 0x32, "blob15"),
    23: (0x4051d0, 0x14, "blob13"),
    24: (0x4054c0, 0x19, "blob03"),
    25: (0x405520, 0x21, "blob16"),
    26: (0x4053a0, 0x25, "blob20"),
    27: (0x405240, 0x15, "blob19"),
}


def main():
    data = BINARY.read_bytes()
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    out_lines = []
    for op in sorted(BLOBS_BY_OP.keys()):
        src_va, size, label = BLOBS_BY_OP[op]
        off = vfo(src_va)
        enc = data[off:off + size]
        # Decrypt: key offset starts at 1 (rcx=1) using key[0]=0x2a, src[1]
        # We pulled bytes starting at src_va (which already corresponds to src[rcx=1]).
        dec = bytes((b ^ KEY[i % 6]) for i, b in enumerate(enc))
        out_lines.append(f"\n=== Op {op} ({label}) src=0x{src_va:x} size={size:#x} ===")
        out_lines.append(f"  hex: {dec.hex()}")
        for ins in md.disasm(dec, 0):
            out_lines.append(f"  0x{ins.address:04x}: {ins.mnemonic:7s} {ins.op_str}")
    print("\n".join(out_lines))


if __name__ == "__main__":
    main()
