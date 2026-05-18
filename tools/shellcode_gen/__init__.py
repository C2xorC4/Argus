"""shellcode_gen — custom shellcode generator for Argus.

Public API
----------
  generate_from_command(cmd, platform, arch) -> bytes
  generate_from_bin(path)                    -> bytes
  ShellcodeGenerator                         — stateful builder class

Both functions return raw shellcode bytes.  Use formatters.format_output()
to convert to hex / C array / Python bytes literal.

Standalone usage:
  python -m tools.shellcode_gen --help
"""
from __future__ import annotations

from pathlib import Path

from .payloads import load_all, get_builder
from .formatters import format_output, write_output, FORMATS

# Ensure all payload modules are registered on import
load_all()

__all__ = [
    "generate_from_command",
    "generate_from_bin",
    "ShellcodeGenerator",
    "format_output",
    "write_output",
    "FORMATS",
]


def generate_from_command(cmd: str, platform: str = "windows",
                          arch: str = "x64") -> bytes:
    """Generate shellcode that executes *cmd* on the target platform/arch.

    Args:
        cmd:      Command string, e.g. ``"cmd.exe /c whoami"`` or ``"whoami"``
        platform: ``"windows"`` or ``"linux"``
        arch:     ``"x64"`` or ``"x86"``

    Returns:
        Raw shellcode bytes.

    Raises:
        ValueError: Unknown platform/arch combination.
        ImportError: keystone-engine not installed.
    """
    builder = get_builder(platform, arch)
    return builder(cmd)


def generate_from_bin(path: str | Path) -> bytes:
    """Load raw shellcode from a .bin file and return its bytes.

    The file is returned unchanged — use this path when you already have
    assembled shellcode and want to pass it through the formatter/obfuscation
    pipeline.
    """
    return Path(path).read_bytes()


class ShellcodeGenerator:
    """Stateful shellcode generator — useful when building multiple payloads
    with the same platform/arch settings.

    Example::

        gen = ShellcodeGenerator(platform="windows", arch="x64")
        sc1 = gen.from_command("cmd.exe /c whoami")
        sc2 = gen.from_command("cmd.exe /c calc.exe")
        sc3 = gen.from_bin("custom_payload.bin")
    """

    def __init__(self, platform: str = "windows", arch: str = "x64"):
        self.platform = platform.lower()
        self.arch = arch.lower()
        # Validate early
        get_builder(self.platform, self.arch)

    def from_command(self, cmd: str) -> bytes:
        return generate_from_command(cmd, self.platform, self.arch)

    def from_bin(self, path: str | Path) -> bytes:
        return generate_from_bin(path)

    def __repr__(self) -> str:
        return f"ShellcodeGenerator(platform={self.platform!r}, arch={self.arch!r})"
