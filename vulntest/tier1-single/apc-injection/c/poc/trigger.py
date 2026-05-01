#!/usr/bin/env python3
"""Tier-1 APC injection — verify imports."""
import sys
try:
    import pefile
except ImportError:
    print("pefile required"); sys.exit(2)
binary = sys.argv[1] if len(sys.argv) > 1 else "build/vuln.exe"
pe = pefile.PE(binary)
imports = set()
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name: imports.add(imp.name.decode())
needed = {"QueueUserAPC", "SleepEx"}
ok = needed.issubset(imports)
print(f"has_apc_pair={ok} (need {needed - imports} more if false)")
sys.exit(0 if ok else 1)
