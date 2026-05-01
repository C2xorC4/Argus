#!/usr/bin/env python3
"""Tier-1 stack-overflow / C# — trigger via long argv."""
import os, subprocess, sys
binary = sys.argv[1] if len(sys.argv) > 1 else os.path.join("build", "Vuln.exe")
proc = subprocess.run([binary, "A" * 200], capture_output=True, timeout=5)
crashed = proc.returncode != 0
print(f"returncode={proc.returncode} crashed={crashed}")
sys.exit(0 if crashed else 1)
