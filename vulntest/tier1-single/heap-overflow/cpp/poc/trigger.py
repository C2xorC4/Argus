#!/usr/bin/env python3
"""Tier-1 heap-overflow / C++ — trigger via stdin payload."""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln-asan")
    payload = b"A" * 256 + b"\n"
    proc = subprocess.run([binary], input=payload, capture_output=True, timeout=5)
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    detected = "heap-buffer-overflow" in out or proc.returncode != 0
    print(f"returncode={proc.returncode} detected={detected}")
    return 0 if detected else 1


if __name__ == "__main__":
    sys.exit(main())
