"""Clean-corpus FP sweep — Tier 0.1 of the progression list.

Runs every detector module against a list of clean (non-vulnerable)
binaries and emits a per-detector / per-target FP count. The output
is the gate-2 evidence per LIFECYCLE.md §4: "Zero findings that
don't map to a real bug in test programs."

Per-detector verdict:
- 0 findings across all targets → gate 2 PASS for this detector
- N>0 findings → either a real bug in the target (review!) or a
   v1 limitation; document in TESTING.md per-detector

Usage:
    python dev/clean_corpus_sweep.py [--targets path1 path2 ...]
                                     [--json-out PATH]

With no `--targets`, runs against the canonical Windows clean
corpus (System32 utilities + a couple Microsoft-signed binaries).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Optional

ARGUS_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ARGUS_ROOT / "skills" / "binary-ninja"
sys.path.insert(0, str(SCRIPTS_DIR))

from scripts.lib import BinjaSession, load_config                    # noqa: E402
from scripts.analysis import (                                       # noqa: E402
    cleanup_dominance, crypto, heap, integrity_check_order,
    obfuscation, race, sddl, surface, taint, trusted_path,
    types, uninit, windows_drivers,
)


# Default clean corpus — Microsoft-signed Windows utilities that
# do not contain known security vulnerabilities. Cover a range of
# functional classes (GUI accessibility, file utilities, command-
# line tools, registry tools).
DEFAULT_CLEAN_CORPUS_WINDOWS = [
    r"C:\Windows\System32\utilman.exe",
    r"C:\Windows\System32\sethc.exe",
    r"C:\Windows\System32\osk.exe",
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\calc.exe",
    r"C:\Windows\System32\xcopy.exe",
    r"C:\Windows\System32\where.exe",
    r"C:\Windows\System32\whoami.exe",
    r"C:\Windows\System32\hostname.exe",
    r"C:\Windows\System32\fc.exe",
    r"C:\Windows\System32\find.exe",
    r"C:\Windows\System32\reg.exe",
    r"C:\Windows\System32\sc.exe",
    r"C:\Windows\System32\tasklist.exe",
    r"C:\Windows\System32\cmd.exe",
]


# Detectors to sweep. Surface runs separately because of its
# (profile, findings) return shape. Heuristics (`heur_chains`) only
# fires when other detectors emit primitives and is excluded — the
# clean corpus has no primitives to compose.
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
]


def sweep_one(target: Path) -> dict:
    """Run all detectors against `target`. Return per-detector
    finding counts + total time."""
    out = {"target": str(target), "skipped": False, "error": None}
    if not target.exists():
        out["skipped"] = True
        return out
    t0 = time.time()
    counts: dict[str, int] = {}
    categories: Counter = Counter()
    try:
        with BinjaSession(str(target)) as session:
            session.bv.update_analysis_and_wait()
            arch = str(session.bv.arch) if session.bv.arch else "unknown"
            platform = str(session.bv.platform) if session.bv.platform else "unknown"
            # Surface — discard the profile, keep findings.
            try:
                _profile, surf_findings = surface.analyze(
                    session=session, binary_path=str(target),
                    run_heuristics=True,
                )
                counts["surface"] = len(surf_findings)
                for f in surf_findings:
                    categories[getattr(f, "category", "")] += 1
            except Exception as e:
                counts["surface"] = -1
                out["error"] = f"surface: {type(e).__name__}: {e}"
            # Per-detector
            for name, det in DETECTORS:
                try:
                    findings = det.analyze(session, binary=str(target),
                                           arch=arch, platform=platform)
                    counts[name] = len(findings)
                    for f in findings:
                        categories[getattr(f, "category", "")] += 1
                except Exception as e:
                    counts[name] = -1
                    if out["error"] is None:
                        out["error"] = f"{name}: {type(e).__name__}: {e}"
    except Exception as e:
        out["error"] = f"session: {type(e).__name__}: {e}"
    out["counts"] = counts
    out["categories"] = dict(categories)
    out["time_s"] = round(time.time() - t0, 2)
    out["arch"] = arch if "arch" in dir() else "?"
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--targets", nargs="*", default=None,
                    help="Override default Windows clean corpus.")
    ap.add_argument("--json-out", type=Path, default=None,
                    help="Write structured results JSON to this path.")
    args = ap.parse_args(argv[1:])

    targets = [Path(p) for p in (args.targets or DEFAULT_CLEAN_CORPUS_WINDOWS)]

    cfg = load_config()
    print(f"Argus dev/clean_corpus_sweep — binja: {cfg.binja.resolved_python_path()}")
    print(f"Targets: {len(targets)}")

    results: list[dict] = []
    per_detector_total: Counter = Counter()
    per_detector_targets: dict[str, list[str]] = {}
    skipped = 0
    errored = 0

    for t in targets:
        print(f"\n=== {t.name} ===")
        r = sweep_one(t)
        results.append(r)
        if r.get("skipped"):
            skipped += 1
            print(f"  SKIPPED (missing)")
            continue
        if r.get("error"):
            errored += 1
            print(f"  ERROR: {r['error']}")
        counts = r.get("counts") or {}
        nonzero = {k: v for k, v in counts.items() if v > 0}
        print(f"  time={r['time_s']}s  nonzero={nonzero or '{}'}")
        for name, n in counts.items():
            if n > 0:
                per_detector_total[name] += n
                per_detector_targets.setdefault(name, []).append(t.name)

    # Summary
    print(f"\n=== summary ===")
    print(f"Targets analysed: {len(targets) - skipped} / {len(targets)} "
          f"(skipped={skipped}, errored={errored})")
    print(f"\nPer-detector totals (FP candidates - verify each):")
    for name, n in sorted(per_detector_total.items(), key=lambda x: -x[1]):
        targets_str = ", ".join(per_detector_targets[name])
        print(f"  {name:25s} {n:4d}  in: {targets_str}")
    if not per_detector_total:
        print(f"  All detectors clean across the corpus.")

    if args.json_out:
        out = {
            "summary": {
                "targets_total": len(targets),
                "targets_skipped": skipped,
                "targets_errored": errored,
                "per_detector_total": dict(per_detector_total),
                "per_detector_targets": per_detector_targets,
            },
            "results": results,
        }
        args.json_out.write_text(json.dumps(out, indent=2, default=str))
        print(f"\nResults -> {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
