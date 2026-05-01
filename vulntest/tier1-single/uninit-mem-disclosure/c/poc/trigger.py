#!/usr/bin/env python3
"""Tier-1 uninit-mem / C — observe non-initialised bytes in output.

Runs the binary and inspects the emitted struct. The known fields
land at predictable offsets; bytes outside those offsets should be
attacker-influenceable in real exploits but at minimum non-zero.
"""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    proc = subprocess.run([binary], capture_output=True, timeout=5)
    out = proc.stdout
    # struct is 2 + 4 + 16 + 1 = 23 bytes packed
    # message field at offset 6, length 16, should be zero in remediated build
    msg_bytes = out[6:6+16] if len(out) >= 22 else b""
    leaked = any(b != 0 for b in msg_bytes)
    print(f"returncode={proc.returncode} bytes_in_message_field={msg_bytes.hex()} leaked={leaked}")
    return 0 if leaked else 1


if __name__ == "__main__":
    sys.exit(main())
