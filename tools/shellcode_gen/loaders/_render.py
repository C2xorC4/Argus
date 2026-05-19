"""Shared embedding helpers for loader template generation.

Deliberately thin — delegates hex formatting to formatters.to_c_array /
formatters.to_py_bytes so there is a single canonical implementation.
"""
from __future__ import annotations

import sys
import types

from ..formatters import to_c_array, to_py_bytes


def c_array_literal(data: bytes, var: str = "sc") -> str:
    """Return C unsigned char array + length constant, variable named var."""
    return to_c_array(data, var_name=var)


def python_bytes_literal(data: bytes, var: str = "sc") -> str:
    """Return Python bytes literal assignment, variable named var."""
    return to_py_bytes(data, var_name=var)


def self_register(module_name: str, loader_name: str) -> None:
    """Register the calling module in _LOADER_REGISTRY.

    Call at module level:
        _render.self_register(__name__, "win_malloc_rwx")
    """
    from . import _LOADER_REGISTRY
    mod = sys.modules[module_name]
    _LOADER_REGISTRY[loader_name.lower()] = mod
