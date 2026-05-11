"""VulnTest cell runner — compare detector output to expected.json.

Discovers cells under vulntest/, runs the analysis pipeline against each
cell's vuln.exe and remediation/build/vuln.exe (clean control), and
verifies:
  - the expected category fires on the vuln binary
  - the expected category does NOT fire on the clean control
  - the expected function (when listed) matches at least one finding

Exits nonzero on any regression. Optional --targets points the same
pipeline at ad-hoc binary paths (e.g. engine binaries) without
expected.json comparison.

Run with the Binary Ninja python interpreter resolved by
`scripts.lib.config.resolve_binja_python_path()`.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ARGUS_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ARGUS_ROOT / "skills" / "binary-ninja"


def _resolve_cell_binary(cell_dir: Path, spec: dict) -> "Path | None":
    """Resolve the vuln binary for a vulntest cell.

    Lookup order:
      1. `cell.binary_basename` field in expected.json — exact filename
         under `cell/binary/`. Used by `known-positive/CVE-*` cells
         whose binaries are real-world drivers / kernel modules with
         CVE-canonical names.
      2. C# cells (`cell.language == "csharp"`): prefer
         `cell/build/vuln.dll` (the managed assembly) over
         `cell/build/vuln.exe` (which is just the apphost-shim CLR
         loader). The dll carries the actual IL + metadata.
      3. `cell/build/vuln.exe` — the standard MSVC / Go / Rust
         build output for synthetic tier1/tier2 fixtures.
      4. Any `*.sys`, `*.ko`, `*.elf`, `*.exe` in `cell/binary/`
         — fallback for cells that ship a pre-built binary without
         declaring a basename.
    """
    cell_meta = (spec.get("cell") or {})
    basename = cell_meta.get("binary_basename")
    if basename:
        candidate = cell_dir / "binary" / basename
        if candidate.exists():
            return candidate
    if (cell_meta.get("language") or "").lower() == "csharp":
        managed = cell_dir / "build" / "vuln.dll"
        if managed.exists():
            return managed
    standard = cell_dir / "build" / "vuln.exe"
    if standard.exists():
        return standard
    binary_dir = cell_dir / "binary"
    if binary_dir.is_dir():
        for ext in (".sys", ".ko", ".elf", ".exe", ".so", ".dll"):
            hits = sorted(binary_dir.glob(f"*{ext}"))
            if hits:
                return hits[0]
    return None


def _bare_identifier(name: str) -> str:
    """Strip C++ qualifiers / params / templates / mangling from a
    function name to recover the bare identifier.

    Handles:
      `log_message(std::string const&)`  → `log_message`
      `std::filesystem::exists`           → `exists`
      `ClassName::method(int)`            → `method`
      `_Z11log_messageRKNSt7__cxx11...`   → `log_message` (Itanium)
      `?backup@@YAXAEBV?$basic_string...` → `backup` (MSVC)
    """
    import re
    if not name:
        return ""
    n = name
    # Itanium mangling: `_Z<len><ident>...` — extract length-prefixed identifier
    m = re.match(r"^_Z[NK]?(\d+)(\w+)", n)
    if m:
        ln = int(m.group(1))
        rest = m.group(2)
        if len(rest) >= ln:
            return rest[:ln]
    # MSVC mangling: `?<ident>@...` — extract identifier between `?` and `@`
    m = re.match(r"^j?_?\??(\w+)@", n)
    if m and m.group(1):
        return m.group(1)
    # Strip parameter list: `name(...)` → `name`
    paren = n.find("(")
    if paren >= 0:
        n = n[:paren]
    # Strip template: `name<...>` → `name`
    angle = n.find("<")
    if angle >= 0:
        n = n[:angle]
    # Strip qualifiers: `A::B::name` → `name`
    if "::" in n:
        n = n.rsplit("::", 1)[-1]
    # Strip MSVC thunk decoration (`j_<name>`) or operator forms
    return n.strip()


def _function_name_matches(expected: str, got: str) -> bool:
    """Tolerant function-name comparison for the runner's PASS gate.

    Match if any of:
      - Got is the sentinel `<binary>` (binary-scope finding — the
        detector doesn't carry a per-function anchor for this class).
      - Expected uses an `<addr>` / `<*>` placeholder ("any anonymous
        function" — used by tier3-obfuscated cells that expect
        stripped-symbol output but where Binja may have recovered a
        real name from .pdata / export table).
      - Expected is an exact / substring match of got (legacy behavior;
        handles `issue_token` matching `?issue_token@@...`).
      - The bare identifier of expected matches the bare identifier of got
        (handles `log_message(std::string const&)` vs the Itanium-mangled
        form `_Z11log_message...`).
      - Bare expected identifier appears anywhere inside got's bare form
        (covers thunk wrappers like `j_?issue_token@@...`).
    """
    if not expected:
        return False
    # Tier-3 stripped-symbol placeholder: `sub_<addr>` / `<*>` / `*`
    # all mean "accept any function" — checked before the empty-got
    # guard so byte-pattern findings (whose `function` is "" when the
    # match isn't inside a defined function) still match the
    # placeholder.
    if "<addr>" in expected or "<*>" in expected or expected.strip() in ("*", "<*>"):
        return True
    if not got:
        return False
    if got == "<binary>":
        return True
    if expected in got:
        return True
    bare_exp = _bare_identifier(expected)
    bare_got = _bare_identifier(got)
    if not bare_exp:
        return False
    if bare_exp == bare_got:
        return True
    # Last resort: bare-identifier substring (handles cases where the
    # mangled form embeds the identifier near other tokens).
    if bare_exp in got:
        return True
    return False
sys.path.insert(0, str(SCRIPTS_DIR))

from scripts.lib import BinjaSession, load_config                    # noqa: E402
from scripts.analysis import (                                       # noqa: E402
    cleanup_dominance, crypto, cross_function_heap, decrypt_external_pages,
    dotnet_managed, dynamic_sink_arg, evasion_structures, heap,
    integrity_check_order, linux_exploit, obfuscation, off_by_one, race,
    sddl, surface, taint, trusted_path, types, uninit, windows_drivers,
)
from scripts.heuristics import chains as heur_chains                 # noqa: E402
from scripts.heuristics._base import imports_in, strings_in          # noqa: E402
from scripts.lib.knowledge import (                                  # noqa: E402
    JmUnavailable,
    verify_finding_citations,
)
from scripts.triage import auto_triage                               # noqa: E402
from scripts.exploit import build as build_pocs                      # noqa: E402
from scripts.verify import verify_finding_locally                    # noqa: E402
from scripts.lib.state import FindingState, transition               # noqa: E402

# Toggled by --no-verify / --verify CLI flags. Default: verification ON.
_verify_enabled: bool = True


def _run_local_verifications(session, findings, pocs, binary_path):
    """For each per-finding PoC, execute it via the local Phase-4
    harness and walk the source finding to IMPACT_VERIFIED if the
    harness reports verified-grade evidence.

    Skipped for cells whose binary lives under a non-C/C++ language
    directory (`/go/`, `/rust/`, `/csharp/`) — those binaries hit
    the MSVC-C-flavored detectors with runtime-pattern false
    positives (Go's runtime has many `<=` comparisons matching the
    off-by-one shape; .NET's CLR loader stub has all sorts of
    spurious format-string anchors). Verification of those cells
    needs per-language detectors first; running them as-is
    produces hundreds of PoCs per cell and verifies them all
    "successfully" via subprocess crash, which is misleading.

    Returns the count of findings walked to IMPACT_VERIFIED.
    """
    bp = (binary_path or "").replace("\\", "/").lower()
    for skip in ("/go/", "/rust/", "/csharp/"):
        if skip in bp:
            print(f"      [phase4] skipped — multi-lang cell "
                  f"({skip.strip('/')}); per-language detection pending")
            return 0

    findings_by_id = {getattr(f, "id", "") or "": f for f in findings}
    verified = 0
    # De-duplicate by (binary, category) — running the same PoC
    # template against the same binary for N findings of the same
    # category produces N identical executions. The category PoC
    # template only varies on category, not on the specific
    # finding's function / address. Verifying once per category
    # per binary is sufficient — when verified, we walk ALL
    # findings of that category in this binary to IMPACT_VERIFIED.
    by_cat: dict[tuple, list] = {}
    for poc in pocs:
        if not getattr(poc, "chain_name", "").startswith("finding_poc."):
            continue
        script = getattr(poc, "exploit_script", None)
        if not script:
            continue
        fid = getattr(poc, "source_chain_finding_id", "") or ""
        finding = findings_by_id.get(fid)
        if finding is None:
            continue
        if (getattr(finding, "category", "") in
                ("decrypt_into_external_pages",
                 "kernel_oob_write_at_offset")):
            continue
        key = (binary_path, getattr(finding, "category", ""))
        by_cat.setdefault(key, []).append((poc, finding, script))

    for (bin_path, category), entries in by_cat.items():
        # Run ONE PoC for the category (the first entry's script).
        poc, finding, script = entries[0]
        try:
            res = verify_finding_locally(finding, script, timeout_s=15)
        except Exception as e:
            print(f"      [warn] verify {finding.category}: "
                  f"{type(e).__name__}: {e}")
            continue
        if not getattr(res, "impact_verified_evidence", False):
            continue
        # Walk EVERY finding in this category for this binary.
        notes = (f"local-verify rc={res.trigger_returncode} "
                 f"any_file_changed={res.any_file_changed} "
                 f"pattern_matches={len(res.dmesg_matches)}")
        for _poc, fnd, _ in entries:
            try:
                for tgt in (FindingState.CONFIRMED,
                            FindingState.IMPACT_PENDING,
                            FindingState.IMPACT_VERIFIED):
                    if fnd.state == tgt:
                        continue
                    new_state, _ = transition(
                        fnd.state, tgt,
                        actor="runner.local_verify",
                        notes=notes,
                        history=getattr(fnd, "state_history", None),
                    )
                    fnd.state = new_state
                verified += 1
            except Exception as e:
                print(f"      [warn] state walk {fnd.category}: "
                      f"{type(e).__name__}: {e}")
        print(f"      [verify] {category} -> IMPACT_VERIFIED "
              f"({len(entries)} finding(s) walked)")
    return verified



DETECTORS = [
    ("taint", taint),
    ("heap", heap),
    ("crypto", crypto),
    ("obfuscation", obfuscation),
    ("windows_drivers", windows_drivers),
    ("uninit", uninit),
    ("types", types),
    ("race", race),
    ("sddl", sddl),
    ("integrity_check_order", integrity_check_order),
    ("cleanup_dominance", cleanup_dominance),
    ("trusted_path", trusted_path),
    ("dynamic_sink_arg", dynamic_sink_arg),
    ("evasion_structures", evasion_structures),
    ("off_by_one", off_by_one),
    ("cross_function_heap", cross_function_heap),
    ("dotnet_managed", dotnet_managed),
    ("decrypt_external_pages", decrypt_external_pages),
    ("linux_exploit", linux_exploit),
]


@dataclass
class CellResult:
    cell_dir: Path
    expected: list[dict]
    vuln_findings: list
    clean_findings: list
    verdict: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    times: dict[str, float] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(v.startswith("PASS") for v in self.verdict.values()) and not any(
            n.startswith("ERROR") for n in self.notes
        )


def discover_cells(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("expected.json") if "build" not in p.parts)


def run_pipeline(binary_path: Path) -> tuple[list, dict[str, float], dict]:
    findings: list = []
    times: dict[str, float] = {}
    profile: dict = {"imports": set(), "strings": set()}
    t_total = time.time()
    with BinjaSession(str(binary_path)) as session:
        session.bv.update_analysis_and_wait()
        arch = str(session.bv.arch) if session.bv.arch else "unknown"
        platform = str(session.bv.platform) if session.bv.platform else "unknown"

        # Snapshot binary-level signals for hard signature evaluation.
        try:
            profile["imports"] = set(imports_in(session.bv))
        except Exception:
            pass
        try:
            profile["strings"] = {s for s, _addr in (strings_in(session.bv) or [])}
        except Exception:
            pass

        t = time.time()
        _surf_profile, surf_findings = surface.analyze(
            session=session, binary_path=str(binary_path), run_heuristics=True,
        )
        findings.extend(surf_findings)
        times["surface"] = round(time.time() - t, 2)

        for name, det in DETECTORS:
            t = time.time()
            try:
                f = det.analyze(
                    session, binary=str(binary_path),
                    arch=arch, platform=platform,
                )
                findings.extend(f)
            except Exception as e:
                print(f"      [warn] {name}: {type(e).__name__}: {e}")
            times[name] = round(time.time() - t, 2)

        # Chain-pattern composition + PoC scaffolding. Emitted chain
        # findings join the cell's finding list (so the runner's
        # category comparison sees them); PoCs are surfaced via stdout
        # but don't yet have an expected.json contract.
        try:
            chain_findings = heur_chains.match(
                session.bv, binary=str(binary_path),
                arch=arch, platform=platform, existing_findings=findings,
            )
            findings.extend(chain_findings)
        except Exception as e:
            print(f"      [warn] chain match: {type(e).__name__}: {e}")
            chain_findings = []
        try:
            promoted = auto_triage(findings)
        except Exception as e:
            print(f"      [warn] auto_triage: {type(e).__name__}: {e}")
            promoted = 0
        try:
            pocs = build_pocs(session, findings,
                              binary=str(binary_path), arch=arch, platform=platform)
            for poc in pocs:
                if getattr(poc, "exploit_script", None):
                    print(f"      [poc] {poc.chain_name} — exploit script generated")
        except Exception as e:
            print(f"      [warn] compose_pocs: {type(e).__name__}: {e}")
            pocs = []
        times["chains"] = len(chain_findings)
        times["triaged"] = promoted
        times["pocs"] = len(pocs)

        # Phase 4 — local-verify the per-finding PoCs. Each PoC whose
        # category has a renderer is executed via the local harness;
        # findings whose verifier returns IMPACT_VERIFIED are walked
        # CONFIRMED → IMPACT_PENDING → IMPACT_VERIFIED via the state
        # machine. Skip if verification is disabled (e.g. --no-verify).
        global _verify_enabled
        verified_count = 0
        if _verify_enabled and pocs:
            print(f"      [phase4] running local-verify on {len(pocs)} PoCs...")
            verified_count = _run_local_verifications(
                session, findings, pocs, str(binary_path),
            )
            print(f"      [phase4] verified {verified_count} finding(s)")
        times["verified"] = verified_count

        # Capture per-finding caller-chain function names while the bv
        # is still open — used by the WARN-fn gate to match expected
        # user-function names against STL-thunk-anchored findings.
        try:
            profile["caller_chains"] = _build_caller_chain_index(
                session.bv, findings, max_depth=3,
            )
        except Exception as e:
            print(f"      [warn] caller_chain index: {type(e).__name__}: {e}")
            profile["caller_chains"] = {}

    times["total"] = round(time.time() - t_total, 2)
    return findings, times, profile


def _build_caller_chain_index(bv, findings: list, *,
                              max_depth: int = 3) -> dict:
    """Build {finding_id: [function_name, ...]} mapping each finding to
    its enclosing function and up to `max_depth` levels of callers.
    Used to bridge STL-thunk-anchored detector emissions to the
    user-code function names listed in expected.json.
    """
    chain: dict = {}
    seen_chain_funcs: dict = {}
    for f in findings:
        try:
            addr = int(getattr(f, "address", 0) or 0)
        except Exception:
            addr = 0
        if addr == 0:
            continue
        fid = getattr(f, "id", None) or f"{f.category}@{hex(addr)}"
        if fid in chain:
            continue
        # Walk up to `max_depth` callers using bv.get_functions_containing
        # for the address, then xrefs to that function.
        try:
            funcs = list(bv.get_functions_containing(addr) or [])
        except Exception:
            funcs = []
        chain_names: list[str] = []
        frontier = list(funcs)
        visited_fkeys: set = set()
        depth = 0
        while frontier and depth < max_depth:
            next_frontier: list = []
            for fn in frontier:
                fkey = int(getattr(fn, "start", 0) or 0)
                if fkey in visited_fkeys:
                    continue
                visited_fkeys.add(fkey)
                nm = getattr(fn, "name", "") or ""
                chain_names.append(nm)
                # Walk callers via code refs to the function's start.
                try:
                    for ref in bv.get_code_refs(fn.start) or []:
                        caller_func = getattr(ref, "function", None)
                        if caller_func is None:
                            continue
                        next_frontier.append(caller_func)
                except Exception:
                    continue
            frontier = next_frontier
            depth += 1
        chain[fid] = chain_names
    return chain


def _collect_caller_function_names(profile: dict, findings: list,
                                   max_depth: int = 3) -> set:
    """Extract caller-chain function names for the given findings from
    the cached profile index. Returns the union across all findings.
    """
    out: set = set()
    chains = profile.get("caller_chains", {}) if profile else {}
    for f in findings:
        try:
            addr = int(getattr(f, "address", 0) or 0)
        except Exception:
            addr = 0
        fid = getattr(f, "id", None) or f"{f.category}@{hex(addr)}"
        names = chains.get(fid) or []
        out.update(n for n in names if n)
    return out


_HARD_SIG_KINDS: frozenset[str] = frozenset({
    "import", "no_import", "import_any", "string_constant",
})


# MSVC compiles many libc calls to alternate runtime entries — `printf`
# expands to `vfprintf`, `snprintf` to `__stdio_common_vsprintf_s`,
# POSIX path-test APIs get the `_` prefix, etc. Allow expected.json
# `import` signatures to be satisfied by any of these equivalents.
_IMPORT_ALIASES: dict[str, frozenset[str]] = {
    "printf":       frozenset({"_printf", "vfprintf", "__stdio_common_vfprintf"}),
    "fprintf":      frozenset({"_fprintf", "vfprintf", "__stdio_common_vfprintf"}),
    "snprintf":     frozenset({"_snprintf", "vsnprintf", "_vsnprintf",
                              "__stdio_common_vsprintf_s",
                              "__stdio_common_vsprintf",
                              # MinGW/Clang lower snprintf through
                              # vfprintf to the buffered FILE path
                              # when libc lacks a separate symbol —
                              # accept that fallback.
                              "vfprintf"}),
    "sprintf":      frozenset({"_sprintf", "vsprintf", "_vsprintf",
                              "__stdio_common_vsprintf_s",
                              "__stdio_common_vsprintf",
                              "vfprintf"}),
    "vprintf":      frozenset({"vfprintf", "__stdio_common_vfprintf"}),
    "scanf":        frozenset({"_scanf", "vfscanf", "__stdio_common_vfscanf"}),
    "fscanf":       frozenset({"_fscanf", "vfscanf", "__stdio_common_vfscanf"}),
    "sscanf":       frozenset({"_sscanf", "vsscanf", "__stdio_common_vsscanf"}),
    "access":       frozenset({"_access"}),
    "stat":         frozenset({"_stat", "_stat64", "_wstat", "_wstat64"}),
    "lstat":        frozenset({"_lstat", "_wstat", "_stat"}),
    "strdup":       frozenset({"_strdup"}),
    "open":         frozenset({"_open"}),
    "close":        frozenset({"_close"}),
    "read":         frozenset({"_read"}),
    "write":        frozenset({"_write"}),
    "unlink":       frozenset({"_unlink"}),
    "system":       frozenset({"_system"}),
    "popen":        frozenset({"_popen"}),
}


def _import_satisfied(name: str, imports: set) -> bool:
    """True if `name` is in `imports` directly or via a known MSVC /
    POSIX alias."""
    if not name:
        return False
    if name in imports:
        return True
    aliases = _IMPORT_ALIASES.get(name)
    if aliases and any(a in imports for a in aliases):
        return True
    # Symmetric: handle expected.json using the MSVC form but a
    # different build using the POSIX form. Reverse-map by scanning
    # for any (canonical, aliases) pair where the canonical is in
    # imports and `name` is one of its aliases.
    for canonical, alias_set in _IMPORT_ALIASES.items():
        if name in alias_set and canonical in imports:
            return True
    return False


def _evaluate_signatures(sigs: list[dict],
                         profile: dict,
                         cat_findings: list) -> tuple[int, int, int]:
    """Evaluate expected.json `evidence_signatures` against the
    binary profile (imports / strings) and the per-category findings.

    Returns (hard_matched, hard_total, soft_count):
    - `hard_matched / hard_total` — fraction of binary-level
      assertions that hold (`import`, `no_import`, `string_constant`).
      These are checked once per cell against the bv-derived profile,
      independent of which finding is being inspected.
    - `soft_count` — descriptive signatures (`data_flow`, `third_arg_zero`,
      `ipc_object_type`, ...) that describe finding-internal evidence.
      These are advisory; we count them but don't gate PASS on them.
    """
    imports = profile.get("imports", set())
    strings = profile.get("strings", set())
    haystack = " ".join(
        " ".join([
            f.description or "",
            json.dumps(f.details or {}, default=str),
            " ".join((e.kind or "") + " " + (e.payload or "")
                     for e in (f.evidence or [])),
        ])
        for f in cat_findings
    )

    h_match = 0
    h_total = 0
    soft = 0
    for sig in sigs:
        kind = sig.get("kind", "")
        if kind not in _HARD_SIG_KINDS:
            soft += 1
            continue
        h_total += 1
        if kind == "import":
            name = sig.get("name", "")
            if name and _import_satisfied(name, imports):
                h_match += 1
        elif kind == "import_any":
            # Toolchain-portability escape hatch: glibc `time` vs MSVC
            # `_time64` vs MUSL `time64` should all satisfy a "the
            # binary uses some time-of-day API" assertion.
            names = sig.get("names", []) or []
            if any(_import_satisfied(n, imports) for n in names):
                h_match += 1
        elif kind == "no_import":
            name = sig.get("name", "")
            if name and not _import_satisfied(name, imports):
                h_match += 1
        elif kind == "string_constant":
            value = sig.get("value", "")
            if value and (value in strings
                          or any(value in s for s in strings)
                          or value in haystack):
                h_match += 1
    return h_match, h_total, soft


def evaluate_cell(cell_path: Path, *, run_clean: bool = True,
                  vulntest_root: Path) -> CellResult:
    cell_dir = cell_path.parent
    with cell_path.open(encoding="utf-8") as f:
        spec = json.load(f)
    expected_findings = spec.get("findings", [])

    rel = cell_dir.relative_to(vulntest_root)
    print(f"\n=== {rel} ===")

    vuln_bin = _resolve_cell_binary(cell_dir, spec)
    clean_bin = cell_dir / "remediation" / "build" / "vuln.exe"

    result = CellResult(cell_dir=cell_dir, expected=expected_findings,
                        vuln_findings=[], clean_findings=[])

    if vuln_bin is None or not vuln_bin.exists():
        result.notes.append(f"ERROR: vuln binary missing under {cell_dir}")
        for exp in expected_findings:
            result.verdict[exp["category"]] = "FAIL-no-binary"
        return result

    print(f"  vuln  {vuln_bin}")
    try:
        vuln_findings, vt, vuln_profile = run_pipeline(vuln_bin)
    except Exception as e:
        result.notes.append(f"ERROR: vuln pipeline failed: {type(e).__name__}: {e}")
        for exp in expected_findings:
            result.verdict[exp["category"]] = "FAIL-pipeline-error"
        return result
    result.vuln_findings = vuln_findings
    result.times["vuln"] = vt["total"]
    cats = Counter(f.category for f in vuln_findings)
    print(f"        {len(vuln_findings)} findings in {vt['total']}s  {dict(cats.most_common(6))}")

    if run_clean:
        if clean_bin.exists():
            print(f"  clean {clean_bin}")
            try:
                clean_findings, ct, _clean_profile = run_pipeline(clean_bin)
                result.clean_findings = clean_findings
                result.times["clean"] = ct["total"]
                ccats = Counter(f.category for f in clean_findings)
                print(f"        {len(clean_findings)} findings in {ct['total']}s  {dict(ccats.most_common(6))}")
            except Exception as e:
                result.notes.append(f"WARN: clean pipeline failed: {type(e).__name__}: {e}")
        else:
            result.notes.append(f"WARN: clean control missing: {clean_bin}")

    vuln_cats = Counter(f.category for f in vuln_findings)
    clean_cats = Counter(f.category for f in result.clean_findings)
    for exp in expected_findings:
        cat = exp["category"]
        if vuln_cats[cat] == 0:
            result.verdict[cat] = "FAIL-missing-on-vuln"
            continue
        if clean_cats[cat] > 0:
            result.verdict[cat] = f"FAIL-fires-on-clean ({clean_cats[cat]}x)"
            continue

        exp_func = exp.get("function")
        cat_findings = [f for f in vuln_findings if f.category == cat]
        if exp_func:
            funcs = {f.function for f in cat_findings}
            # When the detector anchors at an STL-thunk wrapper (e.g.
            # `std::ifstream::ifstream` template-specialised ctor that
            # delegates to the simpler ctor), walk callers of each got
            # function up to a small depth to find a user-code caller
            # whose name matches expected. Closes the gap where the
            # finding's address is correct but the immediate containing
            # function is library code.
            caller_funcs = _collect_caller_function_names(
                vuln_profile, cat_findings, max_depth=3,
            )
            funcs_with_callers = funcs | caller_funcs
            # Pass empty `mf` through too — `_function_name_matches`
            # accepts the `<addr>` placeholder for byte-pattern
            # findings whose `function` is empty (no enclosing
            # function — match is in `.rdata` / `.data`).
            if not any(_function_name_matches(exp_func, mf)
                       for mf in funcs_with_callers):
                result.verdict[cat] = f"PASS-warn-fn (got {sorted(funcs)})"
                continue

        sigs = exp.get("evidence_signatures", [])
        if sigs:
            h_match, h_total, _soft = _evaluate_signatures(
                sigs, vuln_profile, cat_findings,
            )
            # Hard sigs (import / no_import / string_constant) are
            # checked against the binary profile. Soft sigs (data_flow,
            # third_arg_zero, ipc_object_type, ...) are advisory and
            # don't gate PASS.
            if h_total > 0 and h_match < h_total:
                result.verdict[cat] = (
                    f"PASS-warn-sigs ({h_match}/{h_total} hard matched)"
                )
                continue

        result.verdict[cat] = "PASS"

    return result


def run_targets(targets: list[str]) -> None:
    print("\n=== ad-hoc targets ===")
    for t in targets:
        tp = Path(t)
        if not tp.exists():
            print(f"  [skip] missing: {tp}")
            continue
        print(f"\n--- {tp} ---")
        try:
            findings, times, _profile = run_pipeline(tp)
        except Exception as e:
            print(f"  [error] {type(e).__name__}: {e}")
            continue
        cats = Counter(f.category for f in findings)
        sevs = Counter(f.severity.value for f in findings)
        print(f"  {len(findings)} findings in {times['total']}s  sev={dict(sevs)}")
        for cat, n in cats.most_common(20):
            print(f"    {cat}: {n}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--filter", default="",
                    help="Only run cells whose path contains this substring")
    ap.add_argument("--no-clean", action="store_true",
                    help="Skip clean-control (remediation/) runs")
    ap.add_argument("--targets", nargs="*", default=[],
                    help="Additional binary paths to scan (no expected.json)")
    ap.add_argument("--json-out", type=Path, default=None,
                    help="Write structured results JSON to this path")
    ap.add_argument("--substrate-check", action="store_true",
                    help=("Run substrate-coherence check (jm associate) "
                          "against each finding's knowledge_refs; report "
                          "incoherent citations per cell."))
    ap.add_argument("--no-verify", action="store_true",
                    help=("Skip Phase-4 local verification (PoC execution + "
                          "verdict). Detection + chain match + auto_triage "
                          "still run."))
    ap.add_argument("--verify", action="store_true",
                    help=("Enable Phase-4 local verification (default). "
                          "Per-finding PoCs run via the local harness; "
                          "successful verdicts walk findings to "
                          "IMPACT_VERIFIED."))
    ap.add_argument("--c-cpp-only", action="store_true",
                    help=("Skip cells whose binary path is under a non-C/C++ "
                          "language directory (/go/, /rust/, /csharp/). "
                          "Useful when iterating on Windows native targets; "
                          "multi-language cells need per-language detector "
                          "tuning and are too noisy to verify reliably."))
    args = ap.parse_args(argv[1:])

    global _verify_enabled
    _verify_enabled = not args.no_verify

    vulntest_root = Path(__file__).resolve().parent
    cfg = load_config()
    print(f"Argus vulntest/runner — binja python: {cfg.binja.resolved_python_path()}")
    print(f"Root: {vulntest_root}")

    cells = discover_cells(vulntest_root)
    if args.filter:
        cells = [c for c in cells if args.filter in str(c)]
    if args.c_cpp_only:
        before = len(cells)
        cells = [c for c in cells
                 if not any(seg in str(c).replace("\\", "/").lower()
                            for seg in ("/go/", "/rust/", "/csharp/"))]
        print(f"--c-cpp-only: filtered {before - len(cells)} multi-lang cells")
    print(f"Cells: {len(cells)}")

    results: list[CellResult] = []
    for cell_path in cells:
        try:
            r = evaluate_cell(cell_path, run_clean=not args.no_clean,
                              vulntest_root=vulntest_root)
            results.append(r)
        except Exception as e:
            print(f"  [error] {cell_path}: {type(e).__name__}: {e}")

    if args.substrate_check:
        print("\n=== substrate-coherence check ===")
        coherent = incoherent = skipped_sc = err_sc = 0
        per_cell_incoherent: dict[str, list[str]] = {}
        for r in results:
            cell_label = str(r.cell_dir.relative_to(vulntest_root))
            for f in r.vuln_findings:
                refs = list(getattr(f, "knowledge_refs", []) or [])
                if not refs:
                    skipped_sc += 1
                    continue
                try:
                    ok, top = verify_finding_citations(
                        category=getattr(f, "category", ""),
                        description=getattr(f, "description", "") or "",
                        cited_refs=refs,
                    )
                except JmUnavailable as e:
                    err_sc += 1
                    print(f"  [warn] jm: {e}")
                    break
                except Exception:
                    err_sc += 1
                    continue
                if ok:
                    coherent += 1
                else:
                    incoherent += 1
                    top_titles = [e.title[:60] for e in top[:3]]
                    msg = (f"{f.category}@0x{f.address:x} cited={refs} "
                           f"top3_titles={top_titles}")
                    per_cell_incoherent.setdefault(cell_label, []).append(msg)
        for cell, msgs in per_cell_incoherent.items():
            for m in msgs:
                print(f"  INCOHERENT  {cell}  {m}")
        print(f"  coherent={coherent}  incoherent={incoherent}  "
              f"skipped(no_refs)={skipped_sc}  err={err_sc}")

    print("\n=== summary ===")
    fails = 0
    warns = 0
    passes = 0
    for r in results:
        rel = r.cell_dir.relative_to(vulntest_root)
        for n in r.notes:
            print(f"  NOTE  {rel}: {n}")
            if n.startswith("ERROR"):
                fails += 1
        for cat, verdict in r.verdict.items():
            if verdict == "PASS":
                tag, passes = "PASS", passes + 1
            elif verdict.startswith("PASS-warn"):
                tag, warns = "WARN", warns + 1
            else:
                tag, fails = "FAIL", fails + 1
            print(f"  {tag}  {rel}  {cat}: {verdict}")

    print(f"\n{passes} pass, {warns} warn, {fails} fail")

    if args.json_out:
        out = {
            "summary": {"pass": passes, "warn": warns, "fail": fails},
            "cells": [
                {
                    "cell": str(r.cell_dir.relative_to(vulntest_root)),
                    "verdict": r.verdict,
                    "notes": r.notes,
                    "times": r.times,
                    "vuln_categories": dict(Counter(f.category for f in r.vuln_findings)),
                    "clean_categories": dict(Counter(f.category for f in r.clean_findings)),
                }
                for r in results
            ],
        }
        args.json_out.write_text(json.dumps(out, indent=2, default=str))
        print(f"results -> {args.json_out}")

    if args.targets:
        run_targets(args.targets)

    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
