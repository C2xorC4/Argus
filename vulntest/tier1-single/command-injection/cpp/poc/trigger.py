#!/usr/bin/env python3
"""Tier-1 command-injection / C++ — argv exit injection."""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    proc = subprocess.run([binary, "x; touch /tmp/argus_pwn"], capture_output=True, timeout=5)
    triggered = os.path.exists("/tmp/argus_pwn")
    print(f"returncode={proc.returncode} triggered={triggered}")
    if triggered:
        try: os.remove("/tmp/argus_pwn")
        except OSError: pass
    return 0 if triggered else 1


if __name__ == "__main__":
    sys.exit(main())
