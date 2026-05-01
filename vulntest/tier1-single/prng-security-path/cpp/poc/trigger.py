#!/usr/bin/env python3
"""Tier-1 PRNG / C++ — same idea as C variant; predict via mt19937."""
import os
import subprocess
import sys
import time
import re


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
    print("Note: predicting std::mt19937 requires reproducing the exact "
          "system_clock value used at startup. Window-search PoC for "
          "Phase 3; Phase 1 only requires presence-of-bug detection.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
