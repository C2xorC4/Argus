#!/usr/bin/env python3
"""Tier-1 API hash resolution — confirm djb2 constants in binary."""
import sys
binary = sys.argv[1] if len(sys.argv) > 1 else "build/vuln.exe"
with open(binary, "rb") as f: data = f.read()
# 5381 = 0x1505 — djb2 init constant
import struct
flagged = struct.pack("<I", 5381) in data or struct.pack("<I", 0x1505) in data
print(f"djb2_init_constant_in_binary={flagged}")
sys.exit(0 if flagged else 1)
