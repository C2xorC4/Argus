#!/usr/bin/env python3
"""Tier-1 uninit-mem / C++ — same as C variant."""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    proc = subprocess.run([binary], capture_output=True, timeout=5)
    out = proc.stdout
    msg_bytes = out[6:6+16] if len(out) >= 22 else b""
    leaked = any(b != 0 for b in msg_bytes)
    print(f"returncode={proc.returncode} bytes_in_message_field={msg_bytes.hex()} leaked={leaked}")
    return 0 if leaked else 1


if __name__ == "__main__":
    sys.exit(main())
