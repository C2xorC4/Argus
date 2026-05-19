"""Loader registry — maps name → module with generate_c / generate_python."""
from __future__ import annotations

import types
from typing import Dict

_LOADER_REGISTRY: Dict[str, types.ModuleType] = {}


def loader_register(name: str):
    """Class decorator — registers the decorated module-proxy under name.

    Usage: applied at module level by calling _self_register(__name__, name)
    from within each loader module (see _render.register_self).
    """
    def _deco(module: types.ModuleType) -> types.ModuleType:
        _LOADER_REGISTRY[name.lower()] = module
        return module
    return _deco


def get_loader(name: str) -> types.ModuleType:
    """Return the loader module for name; raises ValueError with choices on miss."""
    mod = _LOADER_REGISTRY.get(name.lower())
    if mod is None:
        available = ", ".join(sorted(_LOADER_REGISTRY))
        raise ValueError(
            f"Unknown loader {name!r}. "
            f"Available: {available or 'none loaded'}"
        )
    return mod


def load_all_loaders() -> None:
    """Import all loader modules so they self-register."""
    from . import (  # noqa: F401
        win_malloc_rwx,
        win_rw_rx,
        win_heap_exec,
        win_fiber,
        win_apc_self,
        win_nt_alloc_thread,
        win_split_alloc,
        win_section_map,
        win_hells_gate,
        linux_mmap_rwx,
        linux_mmap_rw_rx,
    )
