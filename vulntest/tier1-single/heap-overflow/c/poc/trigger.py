#!/usr/bin/env python3
"""Tier-1 heap-overflow / C — trigger via oversize argv.

Best confirmed under ASan: build with `make asan` and run the asan
binary; ASan reports `heap-buffer-overflow`. Without ASan the
overflow may not crash deterministically (it overwrites adjacent heap
metadata or the next chunk).
"""
import os
import subprocess
import sys

BUF_SIZE = 64
PAD = b"A" * (BUF_SIZE * 4)         # 4× chunk size — guarantees adjacency stomp


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln-asan")
    proc = subprocess.run([binary, PAD], capture_output=True, timeout=5)
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    detected = "heap-buffer-overflow" in out or proc.returncode != 0
    print(f"returncode={proc.returncode} detected={detected}")
    if detected and "heap-buffer-overflow" in out:
        print("ASan confirmed heap-buffer-overflow")
    return 0 if detected else 1


if __name__ == "__main__":
    sys.exit(main())
