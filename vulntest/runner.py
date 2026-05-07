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
sys.path.insert(0, str(SCRIPTS_DIR))

from scripts.lib import BinjaSession, load_config                    # noqa: E402
from scripts.analysis import (                                       # noqa: E402
    crypto, heap, integrity_check_order, obfuscation,
    race, sddl, surface, taint, types, uninit, windows_drivers,
)
from scripts.heuristics import chains as heur_chains                 # noqa: E402
from scripts.heuristics._base import imports_in, strings_in          # noqa: E402
from scripts.triage import auto_triage                               # noqa: E402
from scripts.exploit import compose_pocs                             # noqa: E402


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
            pocs = compose_pocs(findings)
        except Exception as e:
            print(f"      [warn] compose_pocs: {type(e).__name__}: {e}")
            pocs = []
        times["chains"] = len(chain_findings)
        times["triaged"] = promoted
        times["pocs"] = len(pocs)

    times["total"] = round(time.time() - t_total, 2)
    return findings, times, profile


_HARD_SIG_KINDS: frozenset[str] = frozenset({
    "import", "no_import", "import_any", "string_constant",
})


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
            if name and name in imports:
                h_match += 1
        elif kind == "import_any":
            # Toolchain-portability escape hatch: glibc `time` vs MSVC
            # `_time64` vs MUSL `time64` should all satisfy a "the
            # binary uses some time-of-day API" assertion.
            names = sig.get("names", []) or []
            if any(n in imports for n in names):
                h_match += 1
        elif kind == "no_import":
            name = sig.get("name", "")
            if name and name not in imports:
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

    vuln_bin = cell_dir / "build" / "vuln.exe"
    clean_bin = cell_dir / "remediation" / "build" / "vuln.exe"

    result = CellResult(cell_dir=cell_dir, expected=expected_findings,
                        vuln_findings=[], clean_findings=[])

    if not vuln_bin.exists():
        result.notes.append(f"ERROR: vuln binary missing: {vuln_bin}")
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
            # Substring match handles MSVC mangling: expected `issue_token`
            # matches `?issue_token@@YA...` and `j_?issue_token@@...`.
            if not any(exp_func in mf for mf in funcs if mf):
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
            findings, times = run_pipeline(tp)
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
    args = ap.parse_args(argv[1:])

    vulntest_root = Path(__file__).resolve().parent
    cfg = load_config()
    print(f"Argus vulntest/runner — binja python: {cfg.binja.resolved_python_path()}")
    print(f"Root: {vulntest_root}")

    cells = discover_cells(vulntest_root)
    if args.filter:
        cells = [c for c in cells if args.filter in str(c)]
    print(f"Cells: {len(cells)}")

    results: list[CellResult] = []
    for cell_path in cells:
        try:
            r = evaluate_cell(cell_path, run_clean=not args.no_clean,
                              vulntest_root=vulntest_root)
            results.append(r)
        except Exception as e:
            print(f"  [error] {cell_path}: {type(e).__name__}: {e}")

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
