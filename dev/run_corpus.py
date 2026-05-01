"""Phase 1.11 quality-gate harness — run Argus + legacy across the
VulnTest corpus, compute per-cell TP/FP, aggregate to precision /
recall per detector category.

Bypasses per-cell Makefiles (which require GNU make + per-cell
toolchain assumptions) by inferring build flags from the cell's
expected.json + a default flag set per language.

Usage:
    python dev/run_corpus.py [--legacy] [--limit N]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

ARGUS_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ARGUS_ROOT / "skills" / "binary-ninja"
sys.path.insert(0, str(SKILL_DIR))

from scripts.lib import BinjaSession, load_config                    # noqa: E402
from scripts.analysis import (                                        # noqa: E402
    attack_surface, chains, crypto, heap, mitigations, obfuscation,
    surface, taint,
)


VULNTEST_TIER1 = ARGUS_ROOT / "vulntest" / "tier1-single"


# Language-specific default build flags (mirrors per-cell Makefile
# defaults; bypasses make).
BUILD_FLAGS = {
    "c": [
        "-O0", "-g",
        "-fno-stack-protector", "-fno-pie", "-no-pie",
        "-Wno-format-security", "-Wno-deprecated-declarations",
        "-U_FORTIFY_SOURCE", "-Wno-uninitialized",
        "-Wno-implicit-function-declaration",
    ],
    "cpp": [
        "-O0", "-g",
        "-fno-stack-protector", "-fno-pie", "-no-pie",
        "-std=c++17",
        "-Wno-format-security", "-Wno-deprecated-declarations",
        "-Wno-uninitialized", "-Wno-deprecated-copy",
    ],
}

# Conditional flags — added only when source contains the marker.
# `-municode` forces wmain entry; cells that use plain main() must
# not receive it.
WMAIN_FLAGS = ["-municode", "-DUNICODE", "-D_UNICODE"]

# Linker flags — Win-API-heavy cells need explicit linkage MinGW
# doesn't pull by default.
LDFLAGS = ["-ladvapi32", "-lkernel32", "-luser32", "-lbcrypt"]

LANG_COMPILER = {"c": "gcc", "cpp": "g++"}


def _classify_cell(cell_dir: Path) -> dict | None:
    """Return cell metadata or None if expected.json absent."""
    exp_path = cell_dir / "expected.json"
    if not exp_path.exists():
        return None
    try:
        with open(exp_path) as f:
            exp = json.load(f)
    except json.JSONDecodeError:
        return None
    return {
        "path": cell_dir,
        "expected": exp,
        "language": exp.get("cell", {}).get("language"),
        "platform": exp.get("cell", {}).get("platform", "any"),
        "vuln_class": exp.get("cell", {}).get("class"),
        "expected_categories": [f.get("category") for f in exp.get("findings", [])],
    }


def _build_cell(cell: dict) -> Path | None:
    """Compile the cell's vuln source. Returns the binary path or None."""
    src_dir = cell["path"] / "source"
    candidates = list(src_dir.glob("vuln.*"))
    src = next((c for c in candidates if c.suffix in (".c", ".cpp")), None)
    if src is None:
        return None
    lang = cell["language"]
    if lang not in LANG_COMPILER:
        return None
    build_dir = cell["path"] / "build"
    build_dir.mkdir(exist_ok=True)
    out = build_dir / "vuln.exe"
    cc = LANG_COMPILER[lang]
    # Conditional flags: only add -municode for cells whose source
    # actually defines wmain (otherwise -municode forces a wmain
    # entry that doesn't exist and the build fails).
    extra_flags = []
    try:
        src_text = src.read_text(errors="replace")
        if "wmain(" in src_text or "wWinMain(" in src_text:
            extra_flags = WMAIN_FLAGS
    except OSError:
        pass
    cmd = [cc, *BUILD_FLAGS[lang], *extra_flags, "-o", str(out), str(src), *LDFLAGS]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=60)
    except subprocess.TimeoutExpired:
        return None
    if proc.returncode != 0:
        return None
    return out if out.exists() else None


def _run_argus(binary: Path) -> list:
    """Run the Argus pipeline and return Findings."""
    findings: list = []
    with BinjaSession(str(binary)) as s:
        s.bv.update_analysis_and_wait()
        profile, surf = surface.analyze(session=s, binary_path=str(binary))
        findings += surf
        findings += taint.analyze(s)
        findings += heap.analyze(s)
        findings += crypto.analyze(s)
        findings += obfuscation.analyze(s)
        findings += attack_surface.analyze(s)
        findings += chains.analyze(s, existing_findings=findings)
    return findings


def _run_legacy(binary: Path, env: dict) -> int:
    """Run the legacy security_audit + heap_analysis modules; return total findings."""
    legacy_dir = Path(r"C:\Users\C2xor\.claude\skills\binary-ninja\scripts")
    total = 0
    for script, key in (
        ("security_audit.py", "findings"),
        ("heap_analysis.py", "vulnerabilities"),
    ):
        sp = legacy_dir / script
        if not sp.exists():
            continue
        try:
            proc = subprocess.run(
                [sys.executable, str(sp), str(binary)],
                capture_output=True, env=env, timeout=120,
            )
        except subprocess.TimeoutExpired:
            continue
        if proc.returncode != 0:
            continue
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            continue
        if key == "findings":
            total += len(report.get("findings", []))
        elif key == "vulnerabilities":
            v = report.get("vulnerabilities", {})
            if isinstance(v, dict):
                total += int(v.get("total", 0))
            elif isinstance(v, list):
                total += len(v)
    return total


def _classify_findings(emitted: list, expected_cats: list[str]) -> dict:
    """Return TP/FP/FN counts per category for one cell."""
    expected_set = set(expected_cats)
    emitted_cats = {f.category for f in emitted}
    tp = expected_set & emitted_cats
    fn = expected_set - emitted_cats
    fp = emitted_cats - expected_set
    return {
        "tp": sorted(tp),
        "fn": sorted(fn),
        "fp": sorted(fp),
        "tp_count": len(tp),
        "fn_count": len(fn),
        "fp_count": len(fp),
        "emitted_count": len(emitted),
        "expected_count": len(expected_set),
    }


def _legacy_env() -> dict:
    env = os.environ.copy()
    binja_py = r"C:\Program Files\Vector35\BinaryNinja\python"
    sep = ";" if os.name == "nt" else ":"
    env["PYTHONPATH"] = binja_py + sep + env.get("PYTHONPATH", "")
    return env


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--legacy", action="store_true", help="also run legacy pipeline")
    p.add_argument("--limit", type=int, default=0, help="limit cells (0 = all)")
    p.add_argument("--lang", default="c,cpp", help="comma-separated language filter")
    args = p.parse_args(argv[1:])

    lang_filter = set(args.lang.split(","))

    cfg = load_config()
    print(f"Argus dev/run_corpus — binja: {cfg.binja.resolved_python_path()}")

    cells: list[dict] = []
    for cell_dir in sorted(VULNTEST_TIER1.iterdir()):
        if not cell_dir.is_dir():
            continue
        for lang_dir in sorted(cell_dir.iterdir()):
            if not lang_dir.is_dir():
                continue
            cell = _classify_cell(lang_dir)
            if cell is None:
                continue
            if cell["language"] not in lang_filter:
                continue
            cells.append(cell)
    if args.limit:
        cells = cells[:args.limit]
    print(f"Cells in scope: {len(cells)} (lang filter: {lang_filter})")

    legacy_env = _legacy_env() if args.legacy else None
    results: list[dict] = []
    per_cat_tp: Counter = Counter()
    per_cat_fn: Counter = Counter()
    per_cat_fp: Counter = Counter()

    for i, cell in enumerate(cells, 1):
        rel = cell["path"].relative_to(VULNTEST_TIER1)
        print(f"\n[{i}/{len(cells)}] {rel} (class={cell['vuln_class']}, lang={cell['language']})")

        t0 = time.time()
        binary = _build_cell(cell)
        build_t = time.time() - t0
        if binary is None:
            print(f"  build: FAILED ({build_t:.1f}s)")
            results.append({"cell": str(rel), "build_failed": True})
            continue
        print(f"  build: {build_t:.1f}s -> {binary}")

        t1 = time.time()
        try:
            findings = _run_argus(binary)
        except Exception as e:
            print(f"  argus: ERROR {type(e).__name__}: {e}")
            results.append({"cell": str(rel), "argus_error": str(e)})
            continue
        argus_t = time.time() - t1
        cls = _classify_findings(findings, cell["expected_categories"])
        print(f"  argus: {argus_t:.1f}s  emitted={cls['emitted_count']}  "
              f"TP={cls['tp_count']}/{cls['expected_count']} FP={cls['fp_count']}")
        if cls["fn"]:
            print(f"    MISSED: {cls['fn']}")
        if cls["fp"]:
            print(f"    EXTRA:  {cls['fp']}")

        legacy_count = None
        if legacy_env:
            t2 = time.time()
            legacy_count = _run_legacy(binary, legacy_env)
            print(f"  legacy: {time.time()-t2:.1f}s  emitted={legacy_count}")

        for c in cls["tp"]:
            per_cat_tp[c] += 1
        for c in cls["fn"]:
            per_cat_fn[c] += 1
        for c in cls["fp"]:
            per_cat_fp[c] += 1
        results.append({
            "cell": str(rel),
            "vuln_class": cell["vuln_class"],
            "language": cell["language"],
            "build_time_s": round(build_t, 2),
            "argus_time_s": round(argus_t, 2),
            "argus_emitted": cls["emitted_count"],
            "argus_tp": cls["tp"], "argus_fn": cls["fn"], "argus_fp": cls["fp"],
            "legacy_emitted": legacy_count,
        })

    # Aggregate
    print("\n=== Per-category aggregate (Argus) ===")
    cats = set(per_cat_tp) | set(per_cat_fn) | set(per_cat_fp)
    for c in sorted(cats):
        tp, fn, fp = per_cat_tp[c], per_cat_fn[c], per_cat_fp[c]
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        print(f"  {c:36s}  TP={tp:>3} FN={fn:>3} FP={fp:>3}  "
              f"P={prec:.2f} R={rec:.2f}")

    built = [r for r in results if not r.get("build_failed")]
    cell_pass = sum(1 for r in built
                    if r.get("argus_fn") == [] and r.get("argus_fp") == [])
    cell_clean = sum(1 for r in built if r.get("argus_fp") == [])
    cell_complete = sum(1 for r in built if r.get("argus_fn") == [])
    print(f"\n=== Cell-level summary ===")
    print(f"  total cells in scope:    {len(results)}")
    print(f"  build succeeded:         {len(built)}")
    print(f"  build failed:            {len(results) - len(built)}")
    print(f"  detection complete (FN=0): {cell_complete}/{len(built)}")
    print(f"  zero FP:                 {cell_clean}/{len(built)}")
    print(f"  perfect (FN=0 & FP=0):   {cell_pass}/{len(built)}")

    if legacy_env:
        argus_total = sum(r.get("argus_emitted", 0) for r in built)
        legacy_total = sum(r.get("legacy_emitted", 0) or 0 for r in built)
        print(f"\n  argus total emissions:  {argus_total}")
        print(f"  legacy total emissions: {legacy_total}")

    out = ARGUS_ROOT / "dev" / "corpus_results.json"
    with open(out, "w") as f:
        json.dump({
            "results": results,
            "aggregate": {
                "tp": dict(per_cat_tp),
                "fn": dict(per_cat_fn),
                "fp": dict(per_cat_fp),
            },
        }, f, indent=2, default=str)
    print(f"\n  wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
