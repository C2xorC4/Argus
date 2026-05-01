#!/usr/bin/env python3
"""Tier-1 hidden-thread — string-based PE inspection."""
import sys
binary = sys.argv[1] if len(sys.argv) > 1 else "build/vuln.exe"
with open(binary, "rb") as f: data = f.read()
flagged = b"NtSetInformationThread" in data
print(f"NtSetInformationThread_in_strings={flagged}")
sys.exit(0 if flagged else 1)
