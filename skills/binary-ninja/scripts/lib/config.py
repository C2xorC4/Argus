"""Argus runtime configuration.

Loads `config/argus.toml` from the Argus repo root, merges per-host
overrides from `config/argus.local.toml`, applies environment-variable
overrides, and exposes a typed `ArgusConfig` dataclass.

Resolution order (highest priority last):

1. `config/argus.toml`           — committed defaults
2. `config/argus.local.toml`     — per-host (gitignored)
3. `ARGUS_*` environment vars    — per-invocation
4. explicit code args            — per-call

Single entry point: `load_config()` returns the resolved config.
Subsequent calls reuse the cached instance unless `reload=True`.

Path resolution helpers:

- `resolve_binja_python_path()` — first existing
  `<search_paths[i]>/<python_subdir>`, or the explicit `python_path`
  override.
- `resolve_jm_path()` — explicit > env > config > PATH > vault default.
- `resolve_toolchain(lang)` — picks per-platform executable.
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import tomllib                              # py3.11+
except ImportError:                              # pragma: no cover
    import tomli as tomllib                      # type: ignore[no-redef]


# ── Defaults baked into the source. Match argus.toml — kept in sync
# manually so config-less smoke tests still work. ─────────────────

_DEFAULTS: dict = {
    "schema_version": 1,
    "host": {"hostname": ""},
    "binja": {
        "search_paths": [
            "C:/Program Files/Vector35/BinaryNinja",
            "/opt/binaryninja",
            "/Applications/Binary Ninja.app/Contents/MacOS",
        ],
        "python_subdir": "python",
        "python_path": "",
        "analysis_mode": "full",
        "update_analysis": True,
        "linear_sweep_autorun": True,
    },
    "ljm": {
        "vault_path": "D:/Repos/LLM/LittleJohnnyMnemonic",
        "jm_path": "",
    },
    "toolchains": {
        "c":      {"windows": "gcc",                       "linux": "gcc",     "darwin": "clang"},
        "cpp":    {"windows": "g++",                       "linux": "g++",     "darwin": "clang++"},
        "cgo":    {"windows": "x86_64-w64-mingw32-gcc",    "linux": "gcc",     "darwin": "clang"},
        "csharp": {"csc": "csc"},
        "rust":   {"cargo": "cargo"},
        "go":     {"go": "go"},
    },
    "paths": {
        "findings_dir": "findings",
        "sessions_dir": "sessions",
        "crashes_dir": "crashes",
        "sarif_out": "out/sarif",
        "report_out": "out/reports",
    },
    "budgets": {
        "max_seconds_per_stage": 600,
        "max_findings_per_run": 1000,
        "binja_analysis_timeout_s": 300,
    },
}


# ── Typed view ───────────────────────────────────────────────────

@dataclass
class BinjaConfig:
    search_paths: list[str]
    python_subdir: str
    python_path: str                 # explicit override; empty → derive from search_paths
    analysis_mode: str
    update_analysis: bool
    linear_sweep_autorun: bool

    def resolved_python_path(self) -> Optional[Path]:
        """First existing python module dir, or None."""
        env = os.environ.get("ARGUS_BINJA_PYTHON_PATH", "").strip()
        if env:
            p = Path(env)
            if p.exists():
                return p
        if self.python_path:
            p = Path(self.python_path)
            if p.exists():
                return p
        for root in self.search_paths:
            candidate = Path(root) / self.python_subdir
            if candidate.exists():
                return candidate
        return None


@dataclass
class LjmConfig:
    vault_path: Path
    jm_path: str                     # explicit; empty → autodetect

    def resolved_jm_path(self) -> Optional[Path]:
        """Resolution chain. Returns None if jm cannot be located."""
        env = os.environ.get("ARGUS_JM_PATH", "").strip()
        if env:
            p = Path(env)
            if p.exists():
                return p
        if self.jm_path:
            p = Path(self.jm_path)
            if p.exists():
                return p
        on_path = shutil.which("jm") or shutil.which("jm.exe")
        if on_path:
            return Path(on_path)
        # Vault default — agent/jm or agent/jm.exe under vault root.
        for name in ("jm.exe", "jm"):
            candidate = self.vault_path / "agent" / name
            if candidate.exists():
                return candidate
        return None


@dataclass
class ToolchainsConfig:
    c: dict[str, str]
    cpp: dict[str, str]
    cgo: dict[str, str]
    csharp: dict[str, str]
    rust: dict[str, str]
    go: dict[str, str]

    def for_lang(self, lang: str) -> Optional[str]:
        """Return the executable name for the current platform.

        For per-platform languages (c, cpp, cgo) returns the entry
        matching `windows`/`linux`/`darwin`. For singleton-tool
        languages (csharp/rust/go) returns the canonical key
        (`csc`/`cargo`/`go`).
        """
        platform_key = _platform_key()
        table = getattr(self, lang, None)
        if table is None:
            return None
        if lang in ("c", "cpp", "cgo"):
            return table.get(platform_key)
        # singletons — first value wins
        return next(iter(table.values()), None)


@dataclass
class PathsConfig:
    findings_dir: Path
    sessions_dir: Path
    crashes_dir: Path
    sarif_out: Path
    report_out: Path


@dataclass
class BudgetsConfig:
    max_seconds_per_stage: int
    max_findings_per_run: int
    binja_analysis_timeout_s: int


@dataclass
class ArgusConfig:
    schema_version: int
    hostname: str
    binja: BinjaConfig
    ljm: LjmConfig
    toolchains: ToolchainsConfig
    paths: PathsConfig
    budgets: BudgetsConfig
    repo_root: Path
    config_path: Optional[Path] = None
    local_config_path: Optional[Path] = None


# ── Loading ──────────────────────────────────────────────────────

_cached: Optional[ArgusConfig] = None


def _platform_key() -> str:
    s = platform.system().lower()
    if "windows" in s:
        return "windows"
    if "linux" in s:
        return "linux"
    if "darwin" in s or "mac" in s:
        return "darwin"
    return "linux"                              # sane fallback


def _argus_root() -> Path:
    """Locate Argus repo root.

    Priority: ARGUS_ROOT env > walk up from this file.
    """
    env = os.environ.get("ARGUS_ROOT", "").strip()
    if env:
        return Path(env)
    # config.py lives at Argus/skills/binary-ninja/scripts/lib/config.py
    return Path(__file__).resolve().parents[4]


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Recursive merge of `overlay` into `base`. Returns new dict."""
    out = dict(base)
    for k, v in overlay.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _load_toml(path: Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def _resolve_path(value: str, root: Path) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (root / p)


def _build_typed(merged: dict, root: Path,
                 config_path: Optional[Path],
                 local_config_path: Optional[Path]) -> ArgusConfig:
    h = merged["host"]
    b = merged["binja"]
    l = merged["ljm"]
    t = merged["toolchains"]
    p = merged["paths"]
    g = merged["budgets"]

    hostname = h.get("hostname", "") or socket.gethostname()

    binja = BinjaConfig(
        search_paths=list(b["search_paths"]),
        python_subdir=b["python_subdir"],
        python_path=b.get("python_path", ""),
        analysis_mode=b["analysis_mode"],
        update_analysis=bool(b["update_analysis"]),
        linear_sweep_autorun=bool(b["linear_sweep_autorun"]),
    )

    ljm = LjmConfig(
        vault_path=Path(l["vault_path"]),
        jm_path=l.get("jm_path", ""),
    )

    toolchains = ToolchainsConfig(
        c=dict(t.get("c", {})),
        cpp=dict(t.get("cpp", {})),
        cgo=dict(t.get("cgo", {})),
        csharp=dict(t.get("csharp", {})),
        rust=dict(t.get("rust", {})),
        go=dict(t.get("go", {})),
    )

    # Env overrides for output paths.
    findings_dir = os.environ.get("ARGUS_FINDINGS_DIR", "") or p["findings_dir"]
    sessions_dir = os.environ.get("ARGUS_SESSIONS_DIR", "") or p["sessions_dir"]
    crashes_dir  = os.environ.get("ARGUS_CRASHES_DIR",  "") or p["crashes_dir"]
    sarif_out    = os.environ.get("ARGUS_SARIF_OUT",    "") or p["sarif_out"]
    report_out   = os.environ.get("ARGUS_REPORT_OUT",   "") or p["report_out"]

    paths = PathsConfig(
        findings_dir=_resolve_path(findings_dir, root),
        sessions_dir=_resolve_path(sessions_dir, root),
        crashes_dir=_resolve_path(crashes_dir, root),
        sarif_out=_resolve_path(sarif_out, root),
        report_out=_resolve_path(report_out, root),
    )

    budgets = BudgetsConfig(
        max_seconds_per_stage=int(g["max_seconds_per_stage"]),
        max_findings_per_run=int(g["max_findings_per_run"]),
        binja_analysis_timeout_s=int(g["binja_analysis_timeout_s"]),
    )

    return ArgusConfig(
        schema_version=int(merged.get("schema_version", 1)),
        hostname=hostname,
        binja=binja,
        ljm=ljm,
        toolchains=toolchains,
        paths=paths,
        budgets=budgets,
        repo_root=root,
        config_path=config_path,
        local_config_path=local_config_path,
    )


def load_config(reload: bool = False,
                config_path: Optional[Path] = None) -> ArgusConfig:
    """Load (and cache) the Argus runtime config.

    Pass `reload=True` to force a re-read (e.g., after editing the
    file in-process). `config_path` overrides the default
    `<repo_root>/config/argus.toml` location.
    """
    global _cached
    if _cached is not None and not reload:
        return _cached

    root = _argus_root()
    cfg_dir = root / "config"
    cfg_path = config_path if config_path else cfg_dir / "argus.toml"
    local_path = cfg_dir / "argus.local.toml"

    merged: dict = _DEFAULTS
    actual_cfg_path: Optional[Path] = None
    actual_local_path: Optional[Path] = None

    if cfg_path.exists():
        merged = _deep_merge(merged, _load_toml(cfg_path))
        actual_cfg_path = cfg_path
    if local_path.exists():
        merged = _deep_merge(merged, _load_toml(local_path))
        actual_local_path = local_path

    _cached = _build_typed(merged, root, actual_cfg_path, actual_local_path)
    return _cached


# ── Convenience accessors (used by other lib modules) ────────────

def resolve_binja_python_path() -> Optional[Path]:
    """Resolved Binja python module dir, or None if not found."""
    return load_config().binja.resolved_python_path()


def resolve_jm_path() -> Optional[Path]:
    """Resolved jm CLI path, or None if not found."""
    return load_config().ljm.resolved_jm_path()


def resolve_toolchain(lang: str) -> Optional[str]:
    return load_config().toolchains.for_lang(lang)


# ── CLI for debugging ────────────────────────────────────────────

def _show() -> None:                            # pragma: no cover - manual use
    cfg = load_config()
    print(f"Argus config")
    print(f"  repo_root:         {cfg.repo_root}")
    print(f"  config_path:       {cfg.config_path}")
    print(f"  local_config_path: {cfg.local_config_path}")
    print(f"  hostname:          {cfg.hostname}")
    print(f"  platform:          {_platform_key()}")
    print()
    print(f"  binja.search_paths:  {cfg.binja.search_paths}")
    print(f"  binja.python_path:   {cfg.binja.python_path or '(derive from search_paths)'}")
    print(f"  binja.resolved:      {cfg.binja.resolved_python_path()}")
    print(f"  binja.analysis_mode: {cfg.binja.analysis_mode}")
    print()
    print(f"  ljm.vault_path:      {cfg.ljm.vault_path}")
    print(f"  ljm.jm_path:         {cfg.ljm.jm_path or '(autodetect)'}")
    print(f"  ljm.resolved:        {cfg.ljm.resolved_jm_path()}")
    print()
    print(f"  toolchain c:         {cfg.toolchains.for_lang('c')}")
    print(f"  toolchain cpp:       {cfg.toolchains.for_lang('cpp')}")
    print(f"  toolchain cgo:       {cfg.toolchains.for_lang('cgo')}")
    print(f"  toolchain csharp:    {cfg.toolchains.for_lang('csharp')}")
    print(f"  toolchain rust:      {cfg.toolchains.for_lang('rust')}")
    print(f"  toolchain go:        {cfg.toolchains.for_lang('go')}")
    print()
    print(f"  paths.findings:      {cfg.paths.findings_dir}")
    print(f"  paths.sessions:      {cfg.paths.sessions_dir}")
    print(f"  paths.sarif_out:     {cfg.paths.sarif_out}")
    print()
    print(f"  budget.max_seconds:  {cfg.budgets.max_seconds_per_stage}")


if __name__ == "__main__":                       # pragma: no cover
    _show()
