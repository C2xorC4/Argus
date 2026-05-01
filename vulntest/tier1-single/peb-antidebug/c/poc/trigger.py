#!/usr/bin/env python3
"""Tier-1 PEB anti-debug — confirm normal exit when no debugger."""
import subprocess
import sys
binary = sys.argv[1] if len(sys.argv) > 1 else "build/vuln.exe"
proc = subprocess.run([binary], capture_output=True, timeout=5)
ok = b"no debugger" in proc.stdout
print(f"returncode={proc.returncode} no_debugger_path_taken={ok}")
sys.exit(0 if ok else 1)
