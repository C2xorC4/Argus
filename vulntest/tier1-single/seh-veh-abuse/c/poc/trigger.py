#!/usr/bin/env python3
"""Tier-1 SEH/VEH abuse — confirm AddVectoredExceptionHandler import."""
import sys
try:
    import pefile
except ImportError:
    print("pefile required"); sys.exit(2)

binary = sys.argv[1] if len(sys.argv) > 1 else "build/vuln.exe"
pe = pefile.PE(binary)
imports = []
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name: imports.append(imp.name.decode())
flagged = "AddVectoredExceptionHandler" in imports
print(f"has_AddVectoredExceptionHandler={flagged}")
sys.exit(0 if flagged else 1)
