#!/usr/bin/env python3
"""Tier-1 type-confusion / C — invoke with no 'p' arg → tag is INT
but process() treats the int bytes as a pointer."""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    proc = subprocess.run([binary, "x"], capture_output=True, timeout=5)
    crashed = proc.returncode < 0 or proc.returncode in (134, 139)
    print(f"returncode={proc.returncode} crashed={crashed}")
    return 0 if crashed else 1


if __name__ == "__main__":
    sys.exit(main())
