"""Shared library — config, Binary Ninja wrapper, jm integration, state machine."""

from .binja import BinjaSession, open_binary
from .config import (
    ArgusConfig,
    BinjaConfig,
    LjmConfig,
    ToolchainsConfig,
    PathsConfig,
    BudgetsConfig,
    load_config,
    resolve_binja_python_path,
    resolve_jm_path,
    resolve_toolchain,
)
from .knowledge import KBEntry, JmUnavailable, retrieve, associate, verify_finding_citations
from .state import (
    FindingState,
    StateTransition,
    IllegalTransition,
    transition,
    can_transition,
    legal_targets,
)

__all__ = [
    "BinjaSession",
    "open_binary",
    "ArgusConfig",
    "BinjaConfig",
    "LjmConfig",
    "ToolchainsConfig",
    "PathsConfig",
    "BudgetsConfig",
    "load_config",
    "resolve_binja_python_path",
    "resolve_jm_path",
    "resolve_toolchain",
    "KBEntry",
    "JmUnavailable",
    "retrieve",
    "associate",
    "verify_finding_citations",
    "FindingState",
    "StateTransition",
    "IllegalTransition",
    "transition",
    "can_transition",
    "legal_targets",
]
