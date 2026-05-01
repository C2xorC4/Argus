"""Canonical Binary Ninja wrapper — extracted and refactored from the
orphaned `binja_helpers.py` of the legacy skill.

The legacy file mixed analysis primitives with hardcoded heuristic
dicts (`DANGEROUS_SINKS`, `INTERESTING_PATTERNS`). The dicts live
in `heuristics/` modules now; this file is purely the analysis-engine
wrapper — load, navigate, extract, patch, save.

Detector modules import from here instead of recreating the
boilerplate per script.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from typing import Iterator, Optional

# Default Binary Ninja Python path used as last-resort fallback when
# config is unavailable. Production resolution flows through
# `lib/config.py:resolve_binja_python_path()`.
_BINJA_PY_DEFAULT = "/opt/binaryninja/python"


def _config_binja_path() -> Optional[str]:
    """Best-effort consult of the Argus config."""
    try:
        from .config import resolve_binja_python_path
        p = resolve_binja_python_path()
        return str(p) if p else None
    except Exception:
        return None


def _ensure_binja_path(binja_python_path: Optional[str] = None) -> None:
    """Resolution chain:
    1. explicit `binja_python_path` arg
    2. Argus config (which itself consults ARGUS_BINJA_PYTHON_PATH env)
    3. _BINJA_PY_DEFAULT fallback
    """
    path = binja_python_path or _config_binja_path() or _BINJA_PY_DEFAULT
    if path and path not in sys.path:
        sys.path.insert(0, path)


# Lazy import — modules that don't actually use Binja shouldn't pay
# the import cost. Caller invokes `_ensure_binja_path()` before
# touching `bn`.
def _bn():  # pragma: no cover - thin import wrapper
    _ensure_binja_path()
    import binaryninja as bn  # type: ignore
    return bn


class BinjaSession:
    """Context-managed BinaryView for a single binary.

    Use as:
        with BinjaSession(path) as session:
            for func in session.functions():
                ...

    Wraps `bn.load()` and exposes a small, opinionated surface: the
    detector modules need lookup, iteration, MLIL/HLIL access, and
    patch/save. Anything more exotic — they can reach `session.bv`
    directly.
    """

    def __init__(
        self,
        binary_path: str,
        analysis_mode: Optional[str] = None,
        binja_python_path: Optional[str] = None,
        linear_sweep_autorun: Optional[bool] = None,
    ):
        # Best-effort config consult. Defaults from config; explicit args
        # override.
        try:
            from .config import load_config
            cfg = load_config()
            if analysis_mode is None:
                analysis_mode = cfg.binja.analysis_mode
            if linear_sweep_autorun is None:
                linear_sweep_autorun = cfg.binja.linear_sweep_autorun
        except Exception:
            if analysis_mode is None:
                analysis_mode = "full"
            if linear_sweep_autorun is None:
                linear_sweep_autorun = True

        _ensure_binja_path(binja_python_path)
        import binaryninja as bn  # type: ignore

        self._bn = bn
        self.binary_path = binary_path
        self.bv = bn.load(
            binary_path,
            options={
                "analysis.mode": analysis_mode,
                "analysis.linearSweep.autorun": linear_sweep_autorun,
            },
        )

    # ─── Context manager ──────────────────────────────────────────

    def __enter__(self) -> "BinjaSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        # Binary Ninja 5.x manages BinaryView via GC; the legacy
        # close() was a no-op and we preserve that. Override here if
        # an explicit `bv.file.close()` becomes necessary.
        pass

    # ─── Target profile (used by analysis/surface.py) ──────────────

    @property
    def arch(self) -> str:
        return str(self.bv.arch) if self.bv.arch else "unknown"

    @property
    def platform(self) -> str:
        return str(self.bv.platform) if self.bv.platform else "unknown"

    @property
    def entry_point(self) -> int:
        return int(self.bv.entry_point)

    @property
    def file_format(self) -> str:
        # bv.view_type is "PE", "ELF", "Mach-O", "Raw", etc.
        return str(getattr(self.bv, "view_type", "unknown"))

    # ─── Iteration ─────────────────────────────────────────────────

    def functions(self) -> Iterator:
        yield from self.bv.functions

    def function_by_name(self, name: str):
        funcs = self.bv.get_functions_by_name(name)
        return funcs[0] if funcs else None

    def functions_containing(self, address: int) -> list:
        return list(self.bv.get_functions_containing(address))

    def symbol(self, name: str):
        return self.bv.get_symbol_by_raw_name(name)

    def code_refs(self, address: int) -> list:
        return list(self.bv.get_code_refs(address))

    # ─── Strings ──────────────────────────────────────────────────

    def strings(self, min_length: int = 4) -> Iterator:
        for s in self.bv.strings:
            if s.length >= min_length:
                yield s

    # ─── Mid-level / High-level IL access ─────────────────────────

    def hlil_instructions(self, function) -> Iterator:
        if function.hlil:
            for block in function.hlil:
                yield from block

    def mlil_ssa(self, function):
        # Helper for taint passes — returns the MLIL SSA function form.
        return function.mlil.ssa_form if function.mlil else None

    # ─── Disassembly + instruction utilities ──────────────────────

    def instruction_length(self, address: int) -> int:
        return int(self.bv.get_instruction_length(address))

    def disassembly(self, address: int) -> str:
        return self.bv.get_disassembly(address) or ""

    def read(self, address: int, length: int) -> bytes:
        return bytes(self.bv.read(address, length))

    # ─── Patching primitives ──────────────────────────────────────

    def write(self, address: int, data: bytes) -> bool:
        return int(self.bv.write(address, data)) == len(data)

    def nop(self, address: int) -> bool:
        length = self.instruction_length(address)
        if length == 0:
            return False
        nop_byte = self._nop_byte_for_arch()
        return self.write(address, nop_byte * length)

    def _nop_byte_for_arch(self) -> bytes:
        a = self.arch.lower()
        if "x86" in a or "amd64" in a:
            return b"\x90"
        # ARM/AArch64/MIPS callers should use arch.assemble() rather
        # than a fixed byte; callers requiring multi-arch NOP should
        # patch via assemble() instead of nop().
        return b"\x90"

    def assemble(self, source: str, address: int) -> Optional[bytes]:
        try:
            asm = self.bv.arch.assemble(source, address)
        except Exception:
            return None
        return bytes(asm) if asm else None

    # ─── Saving ───────────────────────────────────────────────────

    def save(self, output_path: str) -> bool:
        return bool(self.bv.save(output_path))


@contextmanager
def open_binary(binary_path: str, **kwargs):
    """Convenience context manager that yields a BinjaSession."""
    session = BinjaSession(binary_path, **kwargs)
    try:
        yield session
    finally:
        session.close()
