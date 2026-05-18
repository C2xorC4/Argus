"""CLI entry point for shellcode_gen.

Invoked as:
  python -m tools.shellcode_gen [options]

Examples:
  python -m tools.shellcode_gen --command "cmd.exe /c whoami" --arch x64
  python -m tools.shellcode_gen --command "whoami" --platform linux --arch x64 --format py_bytes
  python -m tools.shellcode_gen --bin payload.bin --format c_array --output payload.h
  python -m tools.shellcode_gen --command "calc.exe" --format hex --output sc.hex
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import generate_from_command, generate_from_bin
from .formatters import write_output, FORMATS
from .payloads import _REGISTRY, load_all


def build_parser() -> argparse.ArgumentParser:
    load_all()
    available = sorted(f"{p}/{a}" for p, a in _REGISTRY)

    p = argparse.ArgumentParser(
        prog="shellcode_gen",
        description=(
            "Generate shellcode from a command string or a raw .bin file.\n"
            "Outputs raw bytes, hex, C array, Python bytes literal, or escaped string."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument(
        "--command", "-c",
        metavar="CMD",
        help='Command string to execute, e.g. "cmd.exe /c whoami"',
    )
    src.add_argument(
        "--bin", "-b",
        metavar="FILE",
        dest="bin_file",
        help="Path to a raw shellcode .bin file (passthrough)",
    )

    p.add_argument(
        "--platform", "-p",
        default="windows",
        choices=sorted({pl for pl, _ in _REGISTRY}),
        help="Target OS  [default: windows]",
    )
    p.add_argument(
        "--arch", "-a",
        default="x64",
        choices=sorted({arch for _, arch in _REGISTRY}),
        help="Target architecture  [default: x64]",
    )
    p.add_argument(
        "--format", "-f",
        default="hex",
        choices=FORMATS,
        dest="fmt",
        help="Output format  [default: hex]",
    )
    p.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write output to FILE instead of stdout",
    )
    p.add_argument(
        "--var-name",
        default="shellcode",
        help="Variable name used by c_array / py_bytes formatters  [default: shellcode]",
    )
    p.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available platform/arch combinations and exit",
    )
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list:
        load_all()
        print("Available platform/arch combinations:")
        for plat, arch in sorted(_REGISTRY):
            print(f"  {plat}/{arch}")
        return 0

    if not args.list and args.command is None and args.bin_file is None:
        parser.error("one of --command/-c or --bin/-b is required")

    try:
        if args.command:
            data = generate_from_command(args.command, args.platform, args.arch)
        else:
            data = generate_from_bin(args.bin_file)

        dest = Path(args.output) if args.output else None
        write_output(data, args.fmt, dest=dest, var_name=args.var_name)

        if dest:
            print(
                f"[+] {len(data)} bytes written to {dest} ({args.fmt})",
                file=sys.stderr,
            )

    except ImportError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] Unexpected error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
