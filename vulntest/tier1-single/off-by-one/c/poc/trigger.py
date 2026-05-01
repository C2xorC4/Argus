#!/usr/bin/env python3
"""Tier-1 off-by-one / C — ASan run reports buffer-overflow."""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln-asan")
    payload = b"A" * 64                  # exactly fills buf; <= writes one extra
    proc = subprocess.run([binary, payload], capture_output=True, timeout=5)
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    detected = "buffer-overflow" in out or proc.returncode != 0
    print(f"returncode={proc.returncode} detected={detected}")
    return 0 if detected else 1


if __name__ == "__main__":
    sys.exit(main())
