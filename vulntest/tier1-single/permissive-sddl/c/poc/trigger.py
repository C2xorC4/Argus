#!/usr/bin/env python3
"""Tier-1 permissive-SDDL — verify the pipe is accessible to Everyone.

In Phase 1, this is just structural detection — the server loop is
not implemented in the cell. PoC verifies that the SDDL string is
in fact permissive (i.e., grants Everyone via WD).
"""
import re
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "build/vuln.exe"
    with open(binary, "rb") as f:
        data = f.read()
    permissive = b"D:(A;;GA;;;WD)" in data
    print(f"permissive_sddl_in_binary={permissive}")
    return 0 if permissive else 1


if __name__ == "__main__":
    sys.exit(main())
