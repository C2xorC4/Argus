#!/usr/bin/env python3
"""Tier-1 direct-syscall — verify SSN resolution from NTDLL prologue."""
import subprocess
import sys
import re


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "build/vuln.exe"
    proc = subprocess.run([binary], capture_output=True, timeout=5)
    out = proc.stdout.decode(errors="replace")
    m = re.search(r"NtClose SSN = 0x[0-9A-Fa-f]+", out)
    print(f"returncode={proc.returncode} resolved={'yes' if m else 'no'} out={out.strip()}")
    return 0 if m else 1


if __name__ == "__main__":
    sys.exit(main())
