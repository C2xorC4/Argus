"""LJM Knowledge integration — `jm` CLI wrapper.

Argus stage agents pre-flight by retrieving domain-relevant Knowledge
entries from LJM. This module is the Python primitive; a bash
equivalent at `lib/jm-helper.sh` exposes the same surface to agent
quick-reference blocks.

The `jm` CLI lives at `D:\\Repos\\LLM\\LittleJohnnyMnemonic\\agent\\jm.exe`
by default. Override via the `ARGUS_JM_PATH` env var or the `jm_path`
argument to each function.

Surface used here:
- `jm retrieve --intent <intent> --tags <tags> --format json`
- `jm associate --query <text> --format json --threshold <T>`
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional


DEFAULT_JM_PATH = r"D:\Repos\LLM\LittleJohnnyMnemonic\agent\jm.exe"


def _config_jm_path() -> Optional[str]:
    """Best-effort consult of the Argus config. Returns None if config
    cannot be loaded (e.g., running from outside the repo)."""
    try:
        from .config import resolve_jm_path
        p = resolve_jm_path()
        return str(p) if p else None
    except Exception:
        return None


@dataclass
class KBEntry:
    """One Knowledge-base entry as returned by `jm retrieve` / `associate`."""

    title: str
    path: str                        # e.g. "Memory/Knowledge/em_direct_syscall_ssn_resolution.md"
    score: float                     # retrieval / association score (higher = more relevant)
    body: str = ""                   # full body when format=full; empty when format=summary
    tags: list[str] = field(default_factory=list)
    type: str = ""                   # "knowledge" / "semantic" / "user" / "feedback" / etc.

    @property
    def knowledge_ref(self) -> str:
        """Wiki-link form for citation in Finding objects."""
        # Strip leading "Memory/" if present and trailing ".md"
        ref = self.path
        if ref.endswith(".md"):
            ref = ref[:-3]
        # Use the canonical [[Memory/...]] form
        if not ref.startswith("Memory/"):
            ref = f"Memory/{ref}"
        return f"[[{ref}]]"

    @classmethod
    def from_dict(cls, d: dict) -> "KBEntry":
        return cls(
            title=d.get("title", ""),
            path=d.get("path", ""),
            score=float(d.get("score", 0.0)),
            body=d.get("body", ""),
            tags=list(d.get("tags", [])),
            type=d.get("type", ""),
        )


class JmUnavailable(RuntimeError):
    """Raised when the jm CLI cannot be located or invoked."""


def _resolve_jm(jm_path: Optional[str]) -> str:
    """Resolution chain:
    1. explicit `jm_path` arg
    2. ARGUS_JM_PATH env var
    3. Argus config (config/argus.toml + argus.local.toml)
    4. PATH lookup
    5. DEFAULT_JM_PATH source-baked fallback
    """
    if jm_path:
        return jm_path
    env = os.environ.get("ARGUS_JM_PATH")
    if env:
        return env
    cfg = _config_jm_path()
    if cfg:
        return cfg
    on_path = shutil.which("jm") or shutil.which("jm.exe")
    if on_path:
        return on_path
    if os.path.exists(DEFAULT_JM_PATH):
        return DEFAULT_JM_PATH
    raise JmUnavailable(
        "jm CLI not found. Set ARGUS_JM_PATH, configure ljm.jm_path in "
        "config/argus.local.toml, place `jm` on PATH, or ensure "
        f"{DEFAULT_JM_PATH} exists."
    )


def _run_jm(args: list[str], jm_path: Optional[str] = None, timeout: float = 30.0) -> str:
    bin_ = _resolve_jm(jm_path)
    try:
        result = subprocess.run(
            [bin_, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise JmUnavailable(f"jm CLI timed out after {timeout}s") from e
    if result.returncode != 0:
        raise JmUnavailable(
            f"jm exited {result.returncode}: {result.stderr.strip() or result.stdout.strip()}"
        )
    return result.stdout


def retrieve(
    intent: str,
    tags: Optional[list[str]] = None,
    limit: int = 10,
    fmt: str = "summary",
    jm_path: Optional[str] = None,
) -> list[KBEntry]:
    """Invoke `jm retrieve` with an intent + tag filter.

    `intent` shapes scoring (one of "guidance"/"who"/"what"/"where" or
    a free-text phrase); `tags` narrows by topic. `fmt` is "summary"
    (frontmatter + first lines) or "full" (whole body).
    """
    args = ["retrieve", "--intent", intent, "--format", "json", "--limit", str(limit)]
    if fmt == "full":
        args.append("--full")
    if tags:
        args.extend(["--tags", ",".join(tags)])
    raw = _run_jm(args, jm_path=jm_path)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise JmUnavailable(f"jm retrieve returned non-JSON output: {e}") from e
    entries = data if isinstance(data, list) else data.get("entries", [])
    return [KBEntry.from_dict(e) for e in entries]


def associate(
    query: str,
    threshold: float = 0.3,
    limit: int = 10,
    jm_path: Optional[str] = None,
) -> list[KBEntry]:
    """Invoke `jm associate` for free-text contextual matching.

    Use for substrate-coherence checks: pass a Finding's category +
    description and confirm the cited Knowledge entries are top
    matches.
    """
    args = [
        "associate",
        "--query", query,
        "--format", "json",
        "--threshold", f"{threshold:.2f}",
        "--limit", str(limit),
    ]
    raw = _run_jm(args, jm_path=jm_path)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise JmUnavailable(f"jm associate returned non-JSON output: {e}") from e
    entries = data if isinstance(data, list) else data.get("entries", [])
    return [KBEntry.from_dict(e) for e in entries]


def verify_finding_citations(
    category: str,
    description: str,
    cited_refs: list[str],
    threshold: float = 0.3,
    jm_path: Optional[str] = None,
) -> tuple[bool, list[KBEntry]]:
    """Substrate-coherence check.

    Run `associate(category + description)` and confirm every entry in
    `cited_refs` appears in the top results above `threshold`.

    Returns (all_cited_ranked_well, top_results). If False, the
    detector module's pattern table is mis-cited and should be revisited.
    """
    query = f"{category}: {description}"
    top = associate(query, threshold=threshold, jm_path=jm_path)
    top_refs = {e.knowledge_ref for e in top}
    all_present = all(ref in top_refs for ref in cited_refs)
    return all_present, top
