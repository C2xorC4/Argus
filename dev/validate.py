"""End-to-end validation harness against live binaries.

Loads each target with Binary Ninja, runs the recon → identification
pipeline (surface + taint + heap + crypto + obfuscation), reports
timing + findings summary.

Usage:
    python dev/validate.py [path1] [path2] ...

With no arguments, runs the canonical Windows control-sample set:
utilman.exe / sethc.exe / osk.exe — Microsoft-signed accessibility
binaries that exercise the toolchain on full-Win32-mitigation
targets. High FP volume on these = calibration problem.
"""
from __future__ import annotations

import os
import sys
import time
from collections import Counter
from pathlib import Path

# Ensure scripts/ is importable regardless of cwd
ARGUS_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ARGUS_ROOT / "skills" / "binary-ninja"
sys.path.insert(0, str(SCRIPTS_DIR))

from scripts.lib import BinjaSession, load_config                    # noqa: E402
from scripts.analysis import (                                       # noqa: E402
    crypto, heap, integrity_check_order, mitigations, obfuscation,
    race, sddl, source_surface, surface, taint, types, uninit,
    windows_drivers,
)


DEFAULT_TARGETS = [
    r"C:\Windows\System32\utilman.exe",
    r"C:\Windows\System32\sethc.exe",
    r"C:\Windows\System32\osk.exe",
]


def _summarise(findings, label: str) -> None:
    if not findings:
        print(f"    {label}: none")
        return
    cats = Counter(f.category for f in findings)
    sevs = Counter(f.severity.value for f in findings)
    print(f"    {label}: {len(findings)} findings  severities={dict(sevs)}")
    for cat, n in cats.most_common(8):
        print(f"      {cat}: {n}")


def validate_one(path: Path) -> dict:
    if not path.exists():
        print(f"[skip] missing: {path}")
        return {"path": str(path), "skipped": True}

    print(f"\n=== {path.name} ({path.stat().st_size:,} bytes) ===")
    t0 = time.time()
    result: dict = {"path": str(path)}

    with BinjaSession(str(path)) as session:
        session.bv.update_analysis_and_wait()
        result["arch"] = str(session.bv.arch) if session.bv.arch else "unknown"
        result["platform"] = str(session.bv.platform) if session.bv.platform else "unknown"
        result["functions"] = sum(1 for _ in session.bv.functions)
        load_t = time.time() - t0
        print(f"  loaded in {load_t:.1f}s  arch={result['arch']}  "
              f"platform={result['platform']}  funcs={result['functions']}")

        # Surface (recon + heuristics + mitigation profile)
        t1 = time.time()
        profile, surf_findings = surface.analyze(
            session=session, binary_path=str(path), run_heuristics=True,
        )
        result["surface_time_s"] = round(time.time() - t1, 2)
        result["mitigations"] = profile.mitigations.to_dict()
        result["sections"] = len(profile.sections)
        result["imports"] = len(profile.imports)
        print(f"  surface: {result['surface_time_s']}s  "
              f"sections={result['sections']}  imports={result['imports']}")
        print(f"    mitigations: {result['mitigations']}")
        _summarise(surf_findings, "surface findings")

        # Phase 2 — source enrichment. Runs BEFORE taint so any
        # binary-function renames the source extractor performs are
        # visible to taint's evidence emission. No-op when no source/
        # directory is present alongside the binary.
        t1b = time.time()
        src_findings = source_surface.analyze(
            session=session, binary=str(path),
            arch=result["arch"], platform=result["platform"],
        )
        result["source_time_s"] = round(time.time() - t1b, 2)
        result["source_findings"] = len(src_findings)
        if src_findings:
            print(f"  source:  {result['source_time_s']}s")
            _summarise(src_findings, "source-enrichment findings")
        else:
            print(f"  source:  no source/ directory found alongside binary")

        # Taint
        t2 = time.time()
        taint_findings = taint.analyze(session, binary=str(path),
                                       arch=result["arch"], platform=result["platform"])
        result["taint_time_s"] = round(time.time() - t2, 2)
        result["taint_findings"] = len(taint_findings)
        print(f"  taint:   {result['taint_time_s']}s")
        _summarise(taint_findings, "taint findings")

        # Heap
        t3 = time.time()
        heap_findings = heap.analyze(session, binary=str(path),
                                     arch=result["arch"], platform=result["platform"])
        result["heap_time_s"] = round(time.time() - t3, 2)
        result["heap_findings"] = len(heap_findings)
        print(f"  heap:    {result['heap_time_s']}s")
        _summarise(heap_findings, "heap findings")

        # Crypto
        t4 = time.time()
        crypto_findings = crypto.analyze(session, binary=str(path),
                                         arch=result["arch"], platform=result["platform"])
        result["crypto_time_s"] = round(time.time() - t4, 2)
        result["crypto_findings"] = len(crypto_findings)
        print(f"  crypto:  {result['crypto_time_s']}s")
        _summarise(crypto_findings, "crypto findings")

        # Obfuscation
        t5 = time.time()
        obf_findings = obfuscation.analyze(session, binary=str(path),
                                           arch=result["arch"], platform=result["platform"])
        result["obfuscation_time_s"] = round(time.time() - t5, 2)
        result["obfuscation_findings"] = len(obf_findings)
        print(f"  obfusc:  {result['obfuscation_time_s']}s")
        _summarise(obf_findings, "obfuscation findings")

        # Windows kernel drivers — IRP dispatch table extraction.
        # Emits one finding per registered handler. Cheap on non-
        # Windows-kernel targets (the platform discriminator returns
        # early).
        t6 = time.time()
        wd_findings = windows_drivers.analyze(session, binary=str(path),
                                              arch=result["arch"], platform=result["platform"])
        result["windrv_time_s"] = round(time.time() - t6, 2)
        result["windrv_findings"] = len(wd_findings)
        print(f"  windrv:  {result['windrv_time_s']}s")
        _summarise(wd_findings, "windows-driver findings")

        # Tier-2 detectors (Run 16): uninit-mem, type-confusion-candidate, TOCTOU.
        # Each is independent of taint/heap and runs cheaply.
        t7 = time.time()
        uninit_findings = uninit.analyze(session, binary=str(path),
                                         arch=result["arch"], platform=result["platform"])
        result["uninit_time_s"] = round(time.time() - t7, 2)
        result["uninit_findings"] = len(uninit_findings)
        print(f"  uninit:  {result['uninit_time_s']}s")
        _summarise(uninit_findings, "uninit findings")

        t8 = time.time()
        types_findings = types.analyze(session, binary=str(path),
                                       arch=result["arch"], platform=result["platform"])
        result["types_time_s"] = round(time.time() - t8, 2)
        result["types_findings"] = len(types_findings)
        print(f"  types:   {result['types_time_s']}s")
        _summarise(types_findings, "type-confusion findings")

        t9 = time.time()
        race_findings = race.analyze(session, binary=str(path),
                                     arch=result["arch"], platform=result["platform"])
        result["race_time_s"] = round(time.time() - t9, 2)
        result["race_findings"] = len(race_findings)
        print(f"  race:    {result['race_time_s']}s")
        _summarise(race_findings, "TOCTOU findings")

        # Run-17 detectors: Plan A (SDDL/ACE), Plan B (write-then-verify).
        t10 = time.time()
        sddl_findings = sddl.analyze(session, binary=str(path),
                                     arch=result["arch"], platform=result["platform"])
        result["sddl_time_s"] = round(time.time() - t10, 2)
        result["sddl_findings"] = len(sddl_findings)
        print(f"  sddl:    {result['sddl_time_s']}s")
        _summarise(sddl_findings, "SDDL/ACE findings")

        t11 = time.time()
        ico_findings = integrity_check_order.analyze(
            session, binary=str(path),
            arch=result["arch"], platform=result["platform"])
        result["ico_time_s"] = round(time.time() - t11, 2)
        result["ico_findings"] = len(ico_findings)
        print(f"  ico:     {result['ico_time_s']}s")
        _summarise(ico_findings, "pre-verify-write findings")

        all_findings = (list(surf_findings) + list(src_findings)
                        + list(taint_findings)
                        + list(heap_findings) + list(crypto_findings)
                        + list(obf_findings) + list(wd_findings)
                        + list(uninit_findings) + list(types_findings)
                        + list(race_findings) + list(sddl_findings)
                        + list(ico_findings))
        result["total_findings"] = len(all_findings)
        result["total_time_s"] = round(time.time() - t0, 2)

        # Top exploitability scores (after auto-scoring against mitigations)
        if all_findings:
            scored = sorted(all_findings,
                            key=lambda f: f.mitigation_weighted_exploitability,
                            reverse=True)
            print(f"  top 5 by mitigation-weighted exploitability:")
            for f in scored[:5]:
                print(f"    {f.mitigation_weighted_exploitability:.3f}  "
                      f"[{f.severity.value:8s}] {f.category:32s} "
                      f"@{f.function or '<bin>':24s}  {f.description[:64]}")

    print(f"  TOTAL: {result['total_findings']} findings  "
          f"in {result['total_time_s']}s")
    return result


def main(argv: list[str]) -> int:
    targets = [Path(p) for p in (argv[1:] or DEFAULT_TARGETS)]
    cfg = load_config()
    print(f"Argus dev/validate — binja: {cfg.binja.resolved_python_path()}")
    print(f"Targets: {len(targets)}")

    results: list[dict] = []
    for t in targets:
        try:
            results.append(validate_one(t))
        except Exception as e:
            print(f"[error] {t.name}: {type(e).__name__}: {e}")
            results.append({"path": str(t), "error": str(e)})

    print(f"\n=== summary ===")
    for r in results:
        if r.get("skipped"):
            print(f"  {Path(r['path']).name:24s}  SKIPPED")
            continue
        if r.get("error"):
            print(f"  {Path(r['path']).name:24s}  ERROR: {r['error']}")
            continue
        print(f"  {Path(r['path']).name:24s}  "
              f"funcs={r['functions']:>5}  "
              f"findings={r['total_findings']:>3}  "
              f"time={r['total_time_s']:>5}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
