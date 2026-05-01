#!/usr/bin/env python3
"""Tier-1 TLS-callback — pefile inspection confirms TLS directory.

Phase 1 detection is structural; Phase 4 verification can attach a
debugger and observe callback firing before the entry point.
"""
import sys
try:
    import pefile
except ImportError:
    print("pefile not installed; install with `pip install pefile`")
    sys.exit(2)


def main() -> int:
    binary = sys.argv[1] if len(sys.argv) > 1 else "build/vuln.exe"
    pe = pefile.PE(binary)
    has_tls = hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS is not None
    print(f"has_tls_directory={has_tls}")
    return 0 if has_tls else 1


if __name__ == "__main__":
    sys.exit(main())
