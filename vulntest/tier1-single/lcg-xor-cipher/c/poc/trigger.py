#!/usr/bin/env python3
"""Tier-1 LCG-XOR / C — emulator confirms decryption recovers /etc/passwd."""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    proc = subprocess.run([binary], capture_output=True, timeout=5)
    out = proc.stdout.decode(errors="replace")
    decrypted = "/etc/passwd" in out
    print(f"returncode={proc.returncode} decrypted={decrypted} out={out.strip()}")
    return 0 if decrypted else 1


if __name__ == "__main__":
    sys.exit(main())
