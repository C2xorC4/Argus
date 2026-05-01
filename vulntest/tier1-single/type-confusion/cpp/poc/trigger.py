#!/usr/bin/env python3
"""Tier-1 type-confusion / C++ — trigger via 'rect' selection."""
import os
import subprocess
import sys


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "vuln")
    proc = subprocess.run([binary, "rect"], capture_output=True, timeout=5)
    out = (proc.stdout + proc.stderr).decode(errors="replace")
    triggered = "area=" in out
    print(f"returncode={proc.returncode} output={out.strip()}")
    return 0 if triggered else 1


if __name__ == "__main__":
    sys.exit(main())
