"""Payload registry — maps (platform, arch) → build callable."""
from __future__ import annotations

from typing import Callable, Dict, Tuple

# Registry: (platform, arch) → build(cmd: str) -> bytes
_REGISTRY: Dict[Tuple[str, str], Callable[[str], bytes]] = {}


def register(platform: str, arch: str):
    """Decorator to register a payload builder for a (platform, arch) pair."""
    def _deco(fn: Callable[[str], bytes]) -> Callable[[str], bytes]:
        _REGISTRY[(platform.lower(), arch.lower())] = fn
        return fn
    return _deco


def get_builder(platform: str, arch: str) -> Callable[[str], bytes]:
    key = (platform.lower(), arch.lower())
    builder = _REGISTRY.get(key)
    if builder is None:
        available = ", ".join(f"{p}/{a}" for p, a in sorted(_REGISTRY))
        raise ValueError(
            f"No payload for platform={platform!r} arch={arch!r}. "
            f"Available: {available or 'none loaded'}"
        )
    return builder


def load_all() -> None:
    """Import all payload modules so they self-register."""
    from . import win_x64, win_x86, linux_x64, linux_x86  # noqa: F401
