#!/usr/bin/env python3
"""Tier-1 pre-verify-write — verify the file persists after failure."""
import os
import subprocess
import sys
import tempfile


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "build/vuln.exe"
    with tempfile.TemporaryDirectory() as td:
        target = os.path.join(td, "drop.txt")
        proc = subprocess.run([binary, target, "ATTACKER_BYTES"], capture_output=True, timeout=5)
        persisted = os.path.exists(target)
        print(f"returncode={proc.returncode} persisted_after_verify_fail={persisted}")
        return 0 if persisted else 1


if __name__ == "__main__":
    sys.exit(main())
