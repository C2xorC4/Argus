"""keystone-engine assembler wrapper.

Primary: keystone-engine (pip install keystone-engine).
Fallback: raises ImportError with install hint — no silent degradation,
  since corrupted fallback bytes are worse than a clear failure.
"""
from __future__ import annotations

from typing import Optional


def assemble(source: str, arch: str, mode: str) -> bytes:
    """Assemble NASM-syntax source and return raw machine bytes.

    arch / mode map to keystone KS_ARCH_* / KS_MODE_* constants:
      arch="x86",  mode="32"  → KS_ARCH_X86,  KS_MODE_32
      arch="x86",  mode="64"  → KS_ARCH_X86,  KS_MODE_64
      arch="arm",  mode="64"  → KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN
    """
    try:
        import keystone as ks
    except ImportError:
        raise ImportError(
            "keystone-engine is required for shellcode assembly. "
            "Install with:  pip install keystone-engine"
        ) from None

    arch_map = {
        "x86": ks.KS_ARCH_X86,
        "arm": ks.KS_ARCH_ARM64,
    }
    mode_map = {
        "32": ks.KS_MODE_32,
        "64": ks.KS_MODE_64,
        "arm64": ks.KS_MODE_LITTLE_ENDIAN,
    }
    ks_arch = arch_map.get(arch)
    ks_mode = mode_map.get(mode)
    if ks_arch is None or ks_mode is None:
        raise ValueError(f"Unsupported arch={arch!r} mode={mode!r}")

    engine = ks.Ks(ks_arch, ks_mode)
    # as_bytes=True was added after 0.9.2; use list form for compatibility.
    encoding, count = engine.asm(source)
    if count == 0:
        raise AssemblyError(f"Assembled 0 instructions from source:\n{source[:200]}")
    return bytes(encoding)


def cmd_as_db_bytes(cmd: str) -> str:
    """Return NASM 'db' bytes for a null-terminated command string.

    Formats as comma-separated hex literals safe for any byte value:
      db 0x63,0x61,0x6c,0x63,0x00
    """
    return ", ".join(f"0x{b:02x}" for b in (cmd.encode("latin-1") + b"\x00"))


class AssemblyError(Exception):
    pass
