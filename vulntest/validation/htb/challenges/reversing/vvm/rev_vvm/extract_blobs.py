#!/usr/bin/env python3
"""Extract and XOR-decrypt VM bytecode blobs from the vvm ELF binary."""

import struct
import sys
import os
from pathlib import Path

BINARY = Path(r"D:\Repos\Security\Argus\vulntest\validation\htb\challenges\reversing\vvm\rev_vvm\vvm")
OUT_DIR = BINARY.parent

# XOR key cycle as defined in setup function:
#   var_36 = 0x21210b2a   -> bytes: 0x2a, 0x0b, 0x21, 0x21
#   var_32 = 0x2a4d       -> bytes: 0x4d, 0x2a
# Loop:  rax = key[i % 6]; out = rax ^ src[i]; with i starting at 1
KEY = [0x2a, 0x0b, 0x21, 0x21, 0x4d, 0x2a]

# (source_addr, size_bytes, dest_offset, label)
BLOBS = [
    (0x405340, 0x1b, 0xa8, "blob01"),
    (0x4050e0, 0x2a, 0x90, "blob02"),
    (0x4054c0, 0x19, 0xc0, "blob03"),
    (0x405260, 0x12, 0x58, "blob04"),
    (0x405300, 0x38, 0x48, "blob05"),
    (0x405020, 0xb3, 0x88, "blob06"),
    (0x405280, 0x25, 0xa0, "blob07"),
    (0x405500, 0x14, 0x70, "blob08"),
    (0x405120, 0x3b, 0x68, "blob09"),
    (0x405160, 0x35, 0x00, "blob10"),
    (0x4051a0, 0x28, 0x80, "blob11"),
    (0x405380, 0x20, 0x40, "blob12"),
    (0x4051d0, 0x14, 0xb8, "blob13"),
    (0x4053e0, 0x25, 0x08, "blob14"),
    (0x405200, 0x32, 0xb0, "blob15"),
    (0x405520, 0x21, 0xc8, "blob16"),
    (0x4052c0, 0x25, 0x98, "blob17"),
    (0x405460, 0x24, 0x20, "blob18"),
    (0x405240, 0x15, 0xd8, "blob19"),
    (0x4053a0, 0x25, 0xd0, "blob20"),
    (0x405420, 0x24, 0x10, "blob21"),
    (0x4054e0, 0x19, 0x28, "blob22"),
    (0x405360, 0x1b, 0x60, "blob23"),
    (0x4054a0, 0x20, 0x30, "blob24"),
]


IMAGE_BASE = 0x400000  # Binary Ninja shows addresses relative to this base


def parse_elf_section_offset(data, target_va):
    """Given an ELF64 file's bytes and a Binary-Ninja virtual address (with image base 0x400000),
    return the file offset."""
    assert data[:4] == b"\x7fELF"
    # Adjust for image base
    target_va_real = target_va - IMAGE_BASE
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off + 0x00)[0]
        p_offset = struct.unpack_from("<Q", data, off + 0x08)[0]
        p_vaddr = struct.unpack_from("<Q", data, off + 0x10)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        if p_type == 1 and p_vaddr <= target_va_real < p_vaddr + p_filesz:
            return p_offset + (target_va_real - p_vaddr)
    return None


def main():
    data = BINARY.read_bytes()
    print(f"Binary: {BINARY}, size = {len(data)} bytes")

    manifest_lines = []
    blobs_concat = bytearray()
    decrypted = {}

    for src_va, size, dest_off, label in BLOBS:
        file_off = parse_elf_section_offset(data, src_va)
        if file_off is None:
            print(f"  !! Could not resolve VA 0x{src_va:x}")
            continue
        enc = data[file_off:file_off + size]
        # Decrypt: out[i] = enc[i] ^ key[(i+1) % 6]
        # Reasoning: in HLIL, dest[rcx-1] = key[(rcx-1) % 6 ... actually rcx_before_inc]
        # The HLIL says: rax_3 starts at 0x2a (key[0]); then *(dst + rcx) = rax_3 ^ *(src + rcx)
        # then rax_3 = key[rax_6 u% 6] where rax_6 = rcx (before increment)
        # So pre-loop: rax_3 = key[0]; rcx = 1; uses src[1] xor key[0] and writes dst[1]
        # Wait: dst is &var_88:0xf which is byte-addressing. *(dst + rcx) where rcx starts at 1
        # writes byte at offset rcx in dst. The first iteration writes dst[1] using src[1].
        # Actually src is &data_XXX + rcx with rcx=1, so src[rcx]=data_XXX[1].
        # But mmap size is (size-1)+1 = original size, and data_XXX byte 0 is unused.
        # Hmm. Actually the loop iterates rcx = 1..size, and for each writes dst[rcx] = src[rcx] ^ key[i].
        # That writes dst bytes 1..size-1, leaving dst[0] uninitialized -- but in practice the
        # zmm/var_88 staging buffer's byte 0 is part of an earlier value. Let's trust:
        # decrypted[i] = encrypted[i] ^ key[(i-1) % 6] for i=1..size-1, and byte 0 is whatever
        # was in the source byte 0. Actually more carefully: the dst buffer is var_88..var_98 etc.
        # The *r_blob = var_XX writes all 0x10 bytes from var_XX into mapped[0..0x10].
        # var_88 byte 0 is initialized somewhere -- probably we should just decrypt all `size` bytes
        # from src using key offsets (i-1) mod 6 for i=1..size and put them at offsets 1..size,
        # but mmap is `size` bytes so the meaningful payload is bytes [0..size]. Most likely the
        # very first byte of each blob is essentially padding/unused or written separately.
        #
        # Simpler: assume the entire encrypted blob at src_va of length `size` is XORed byte-by-byte
        # with key[i % 6] starting at i=0. Try BOTH alignments.
        dec_a = bytes((b ^ KEY[i % 6]) for i, b in enumerate(enc))
        dec_b = bytes((b ^ KEY[(i + 1) % 6]) for i, b in enumerate(enc))
        decrypted[label] = (src_va, size, dest_off, enc, dec_a, dec_b)

        manifest_lines.append(
            f"{label}: src_va=0x{src_va:x} size={size:#x} dest_off={dest_off:#x}\n"
            f"  ENC : {enc.hex()}\n"
            f"  DECa: {dec_a.hex()}\n"
            f"  DECb: {dec_b.hex()}\n"
            f"  ASCa: {''.join(chr(c) if 32 <= c < 127 else '.' for c in dec_a)}\n"
            f"  ASCb: {''.join(chr(c) if 32 <= c < 127 else '.' for c in dec_b)}\n"
        )
        blobs_concat += enc + b"\xff\xff"  # separator placeholder

    out_manifest = OUT_DIR / "decrypted_blobs_manifest.txt"
    out_manifest.write_text("\n".join(manifest_lines), encoding="utf-8")
    print(f"Wrote manifest: {out_manifest}")

    # Combined binary
    out_bin = OUT_DIR / "decrypted_blobs.bin"
    with out_bin.open("wb") as f:
        for label, (src_va, size, dest_off, enc, dec_a, dec_b) in decrypted.items():
            # Use the alignment that produces cleaner data; default to dec_b (i+1) since
            # the HLIL loop's first iteration was rcx=1 with rax_3=key[0]. But the encrypted
            # data we read starts at src_va=data_XXX+1 (offset of rcx=1 access), so we already
            # account for the +1 in the source address. Therefore dec_a (i % 6 starting key[0]) is right.
            f.write(f"=== {label} src=0x{src_va:x} size={size:#x} dest_off={dest_off:#x} ===\n".encode())
            f.write(b"ENC : " + enc.hex().encode() + b"\n")
            f.write(b"DECa: " + dec_a.hex().encode() + b"\n")
            f.write(b"DECb: " + dec_b.hex().encode() + b"\n\n")
    print(f"Wrote combined: {out_bin}")

    # Also write per-blob raw decrypted (using dec_a) as one big file with index
    out_raw = OUT_DIR / "decrypted_blobs_raw.bin"
    idx_lines = []
    pos = 0
    with out_raw.open("wb") as f:
        for label, (src_va, size, dest_off, enc, dec_a, dec_b) in decrypted.items():
            idx_lines.append(f"{label}\tsrc=0x{src_va:x}\tsize={size}\tdest_off=0x{dest_off:x}\tfile_off={pos}")
            f.write(dec_a)
            pos += size
    (OUT_DIR / "decrypted_blobs_index.txt").write_text("\n".join(idx_lines), encoding="utf-8")
    print(f"Wrote raw: {out_raw}, index: {OUT_DIR / 'decrypted_blobs_index.txt'}")


if __name__ == "__main__":
    main()
