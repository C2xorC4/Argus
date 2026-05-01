#!/usr/bin/env python3
"""Tier-1 double-free / C — ASan or glibc detection."""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln-asan")
    proc = subprocess.run([binary, "alice"], capture_output=True, timeout=5)
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    detected = (
        "double-free" in out
        or "double free or corruption" in out
        or "attempting double-free" in out
    )
    print(f"returncode={proc.returncode} detected={detected}")
    return 0 if detected else 1


if __name__ == "__main__":
    sys.exit(main())
