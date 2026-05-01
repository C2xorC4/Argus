#!/usr/bin/env python3
"""Tier-1 integer-overflow / C++ — wrap operator new[] sizing."""
import os
import subprocess
import sys

SIZE_MAX = (1 << 64) - 1
SIZEOF_RECORD = 4 + 16
COUNT = (SIZE_MAX // SIZEOF_RECORD) + 1


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln-asan")
    proc = subprocess.run([binary, str(COUNT)], capture_output=True, timeout=10)
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    detected = "heap-buffer-overflow" in out or proc.returncode != 0
    print(f"returncode={proc.returncode} detected={detected}")
    return 0 if detected else 1


if __name__ == "__main__":
    sys.exit(main())
