"""Attack-surface enumeration — entry points → reachable sinks.

For each external-input entry point present in the binary, walk the
callgraph forward and flag the sinks the entry can reach within
`max_depth` hops. Output prioritises entries that reach the *most*
sinks — the high-fan-out ingress is the high-value target.

Refactor of the legacy `attack_surface.py` baseline. Source/sink
tables come from `heuristics/imports.py`; mitigation context comes
from `analysis/mitigations.py`.

Findings emitted:
- `attack_surface_entry`     (info) — every detected entry point
- `entry_reaches_sink`       (varies by sink class) — every (entry, sink)
                              pair, severity inheriting from sink class

Phase 1 limitations:
- Reachability is forward callgraph BFS; intra-procedural flow is
  not validated (the entry might call a helper that branches to
  the sink only on a specific input value).
- Indirect calls (function pointer / vtable / RPC dispatcher) are
  followed only when Binja resolved them to concrete callees.
- Multi-hop chains beyond `max_depth` are truncated; raise the limit
  if the operator wants more recall (at the cost of FP rate).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from ..heuristics import imports as heur_imports
from ..heuristics._base import imports_in
from ..output.finding import Evidence, Finding, Severity
from . import _il_helpers as ilh
from . import mitigations as mitigations_mod
from .taint import SINK_CLASS_META, SINK_TABLE


# ─────────────────────────────────────────────────────────────────
# Entry-point taxonomy
# ─────────────────────────────────────────────────────────────────


# (name -> (channel, severity, description))
ENTRY_SOURCES: dict[str, tuple[str, Severity, str]] = {
    # ── Network ────────────────────────────────────────────────────
    "recv":       ("network", Severity.HIGH,     "Network socket receive"),
    "recvfrom":   ("network", Severity.HIGH,     "Network datagram receive"),
    "recvmsg":    ("network", Severity.HIGH,     "Network message receive"),
    "accept":     ("network", Severity.MEDIUM,   "Network connection accept"),
    "WSARecv":    ("network", Severity.HIGH,     "Win32 socket receive"),
    "WSARecvFrom":("network", Severity.HIGH,     "Win32 socket recvfrom"),
    "WSAAccept":  ("network", Severity.MEDIUM,   "Win32 socket accept"),

    # ── File / IO ──────────────────────────────────────────────────
    "fread":      ("file",    Severity.MEDIUM,   "stdio fread"),
    "read":       ("file",    Severity.MEDIUM,   "POSIX read"),
    "fgets":      ("file",    Severity.MEDIUM,   "stdio fgets"),
    "ReadFile":   ("file",    Severity.MEDIUM,   "Win32 ReadFile"),
    "ReadFileEx": ("file",    Severity.MEDIUM,   "Win32 ReadFileEx"),

    # ── Stdin / cmdline / env ──────────────────────────────────────
    "gets":              ("stdin",   Severity.HIGH,   "stdio gets (banned)"),
    "scanf":             ("stdin",   Severity.MEDIUM, "stdio scanf"),
    "fscanf":            ("file",    Severity.MEDIUM, "file scanf"),
    "GetCommandLineA":   ("cmdline", Severity.LOW,    "Win32 command line"),
    "GetCommandLineW":   ("cmdline", Severity.LOW,    "Win32 command line"),
    "getenv":            ("env",     Severity.LOW,    "POSIX getenv"),
    "secure_getenv":     ("env",     Severity.LOW,    "POSIX secure_getenv"),
    "GetEnvironmentVariableA": ("env", Severity.LOW,  "Win32 env"),
    "GetEnvironmentVariableW": ("env", Severity.LOW,  "Win32 env"),

    # ── IPC ────────────────────────────────────────────────────────
    "ConnectNamedPipe":  ("ipc", Severity.HIGH,    "Win32 named pipe accept"),
    "CreateNamedPipeA":  ("ipc", Severity.HIGH,    "Win32 named pipe server"),
    "CreateNamedPipeW":  ("ipc", Severity.HIGH,    "Win32 named pipe server"),
    "CreateFileMappingA":("ipc", Severity.MEDIUM,  "Win32 shared memory"),
    "CreateFileMappingW":("ipc", Severity.MEDIUM,  "Win32 shared memory"),
    "MapViewOfFile":     ("ipc", Severity.MEDIUM,  "Win32 shared memory"),

    # ── Registry / config ──────────────────────────────────────────
    "RegQueryValueExA":  ("registry", Severity.LOW, "Win32 registry read"),
    "RegQueryValueExW":  ("registry", Severity.LOW, "Win32 registry read"),

    # ── HTTP / web ─────────────────────────────────────────────────
    "InternetReadFile":  ("network", Severity.HIGH, "WinINet HTTP read"),
    "WinHttpReadData":   ("network", Severity.HIGH, "WinHTTP read"),
}


@dataclass
class EntryPoint:
    name: str
    channel: str
    severity: Severity
    description: str
    address: int                 # IAT address
    callers: list[tuple[str, int]] = field(default_factory=list)  # (caller_name, call_addr)


@dataclass
class AttackPath:
    entry: EntryPoint
    sink_name: str
    sink_class: str
    sink_address: int
    sink_caller: str
    hops: int


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────


def _enumerate_entries(bv) -> list[EntryPoint]:
    out: list[EntryPoint] = []
    if bv is None:
        return out
    imports = imports_in(bv)
    for name, (channel, severity, desc) in ENTRY_SOURCES.items():
        if name not in imports:
            continue
        # IAT address
        callsites = ilh.call_sites_of_import(bv, name)
        callers: list[tuple[str, int]] = []
        for addr, mlil in callsites:
            func = getattr(mlil, "function", None) if mlil else None
            fname = getattr(func, "name", "") if func else ""
            callers.append((fname, addr))
        if not callers:
            continue
        # Anchor IAT address: take from the first import lookup
        sym = None
        getter = getattr(bv, "get_symbol_by_raw_name", None)
        if callable(getter):
            try:
                sym = getter(name)
            except Exception:
                sym = None
        iat_addr = int(getattr(sym, "address", 0)) if sym else 0
        out.append(EntryPoint(
            name=name, channel=channel, severity=severity,
            description=desc, address=iat_addr, callers=callers,
        ))
    return out


def _function_reaches_sinks(bv, func, sink_imports: set[str],
                           *, max_depth: int = 4) -> list[tuple[str, str, int, str]]:
    """BFS forward over `func.callees` graph; record sinks reached.

    Returns [(sink_name, sink_class, sink_addr, hop_caller_name), ...].
    """
    if func is None:
        return []
    visited: set[int] = set()
    queue = deque([(func, 0)])
    hits: list[tuple[str, str, int, str]] = []
    while queue:
        f, depth = queue.popleft()
        if depth > max_depth:
            continue
        f_addr = int(getattr(f, "start", 0))
        if f_addr in visited:
            continue
        visited.add(f_addr)
        # Inspect call sites in this function
        try:
            call_sites = list(getattr(f, "call_sites", []) or [])
        except Exception:
            call_sites = []
        for site in call_sites:
            site_addr = int(getattr(site, "address", 0))
            site_func = getattr(site, "function", None)
            site_func_name = getattr(site_func, "name", "") if site_func else ""
            # The callee at this site
            hlil = getattr(site, "hlil", None)
            callee = None
            try:
                # Resolve via bv.get_symbol_at on callee address
                if hlil is not None:
                    dest = getattr(hlil, "dest", None)
                    callee_addr = getattr(dest, "constant", None)
                    if callee_addr is not None:
                        sym = bv.get_symbol_at(int(callee_addr))
                        if sym is not None:
                            callee = (getattr(sym, "short_name", None)
                                      or getattr(sym, "name", ""))
            except Exception:
                callee = None
            if callee in sink_imports:
                _arg_idx, sink_class = SINK_TABLE[callee]
                hits.append((callee, sink_class, site_addr, site_func_name))
        # Recurse into callees that are in-binary
        try:
            for callee_func in (f.callees or []):
                queue.append((callee_func, depth + 1))
        except Exception:
            continue
    return hits


# ─────────────────────────────────────────────────────────────────
# Public entry
# ─────────────────────────────────────────────────────────────────


def analyze(session, *, binary: Optional[str] = None,
            arch: Optional[str] = None, platform: Optional[str] = None,
            max_depth: int = 4,
            score_against_mitigations: bool = True,
            detector: str = "analysis.attack_surface") -> list[Finding]:
    if session is None:
        return []
    bv = getattr(session, "bv", None)
    if bv is None:
        return []
    binary = binary or getattr(session, "binary_path", "") or ""
    arch = arch or (str(bv.arch) if bv.arch else "unknown")
    platform = platform or (str(bv.platform) if bv.platform else "unknown")

    findings: list[Finding] = []
    entries = _enumerate_entries(bv)
    sink_imports = set(SINK_TABLE.keys())

    for entry in entries:
        # Emit one entry-point Finding per unique caller
        for caller_name, caller_addr in entry.callers:
            findings.append(Finding(
                id="",
                category="attack_surface_entry",
                severity=entry.severity,
                address=caller_addr,
                function=caller_name,
                binary=binary, arch=arch, platform=platform,
                detector=detector,
                knowledge_refs=[],
                cwe=[],
                mitre_attack=[],
                description=(
                    f"external-input entry: {entry.name} ({entry.description}) "
                    f"called from {caller_name} at 0x{caller_addr:x}"
                ),
                evidence=[Evidence(
                    kind="attack_surface_entry",
                    source=detector,
                    payload=f"channel={entry.channel} entry={entry.name}",
                    address=caller_addr, function=caller_name,
                )],
                details={
                    "entry_name": entry.name,
                    "channel": entry.channel,
                    "caller": caller_name,
                    "caller_addr": hex(caller_addr),
                },
            ))

        # Reachability walk per caller
        seen_paths: set[tuple] = set()
        for caller_name, caller_addr in entry.callers:
            try:
                caller_funcs = list(bv.get_functions_containing(caller_addr))
            except Exception:
                continue
            if not caller_funcs:
                continue
            caller = caller_funcs[0]
            hits = _function_reaches_sinks(bv, caller, sink_imports,
                                           max_depth=max_depth)
            for (sink_name, sink_class, sink_addr, sink_caller_name) in hits:
                key = (entry.name, sink_name, sink_addr)
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                meta = SINK_CLASS_META.get(sink_class)
                if meta is None:
                    continue
                findings.append(Finding(
                    id="",
                    category="entry_reaches_sink",
                    severity=meta["severity"],
                    address=sink_addr,
                    function=sink_caller_name,
                    binary=binary, arch=arch, platform=platform,
                    detector=detector,
                    knowledge_refs=list(meta["knowledge_refs"]),
                    cwe=list(meta["cwe"]),
                    mitre_attack=list(meta["mitre"]),
                    description=(
                        f"reachability: {entry.name} ({entry.channel}) -> "
                        f"{sink_name} ({sink_class}) within {max_depth} hops"
                    ),
                    evidence=[Evidence(
                        kind="reachability_path",
                        source=detector,
                        payload=f"{entry.name}@{caller_name} -> {sink_name}@0x{sink_addr:x}",
                        address=sink_addr,
                        function=sink_caller_name,
                    )],
                    details={
                        "entry_name": entry.name,
                        "entry_channel": entry.channel,
                        "sink_name": sink_name,
                        "sink_class": sink_class,
                        "sink_addr": hex(sink_addr),
                    },
                ))

    if score_against_mitigations and findings and binary:
        try:
            profile = mitigations_mod.extract_mitigations(binary, bv=bv)
            mitigations_mod.score_findings(findings, profile)
        except Exception:
            pass

    return findings
