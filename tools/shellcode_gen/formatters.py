"""Output formatters for shellcode bytes."""
from __future__ import annotations

from pathlib import Path
from typing import Optional


FORMATS = ("raw", "hex", "c_array", "py_bytes", "escaped")


def to_raw(data: bytes) -> bytes:
    return data


def to_hex(data: bytes, sep: str = "") -> str:
    return sep.join(f"{b:02x}" for b in data)


def to_c_array(data: bytes, var_name: str = "shellcode",
               line_width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), line_width):
        chunk = data[i:i + line_width]
        lines.append("  " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    body = "\n".join(lines).rstrip(",")
    return (
        f"unsigned char {var_name}[] = {{\n"
        f"{body}\n"
        f"}};\n"
        f"unsigned int {var_name}_len = {len(data)};\n"
    )


def to_py_bytes(data: bytes, var_name: str = "shellcode") -> str:
    hex_str = "".join(f"\\x{b:02x}" for b in data)
    return f'{var_name} = b"{hex_str}"\n'


def to_escaped(data: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in data)


def format_output(data: bytes, fmt: str, var_name: str = "shellcode") -> object:
    """Dispatch to the requested formatter. Returns bytes for 'raw', str otherwise."""
    fmt = fmt.lower()
    if fmt == "raw":
        return to_raw(data)
    if fmt == "hex":
        return to_hex(data)
    if fmt == "c_array":
        return to_c_array(data, var_name)
    if fmt == "py_bytes":
        return to_py_bytes(data, var_name)
    if fmt == "escaped":
        return to_escaped(data)
    raise ValueError(f"Unknown format {fmt!r}. Choices: {', '.join(FORMATS)}")


def write_output(data: bytes, fmt: str, dest: Optional[Path] = None,
                 var_name: str = "shellcode") -> None:
    """Format and write to dest file, or print to stdout."""
    result = format_output(data, fmt, var_name)
    if dest is None:
        if isinstance(result, bytes):
            import sys
            sys.stdout.buffer.write(result)
        else:
            print(result, end="")
    else:
        if isinstance(result, bytes):
            dest.write_bytes(result)
        else:
            dest.write_text(result, encoding="utf-8")
