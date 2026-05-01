"""Run Phase-1 detection against a known-positive cell's binaries
and persist Findings JSON for downstream Phase-4 verification.

Usage:
    python dev/run_known_positive.py CVE-2026-31431
    python dev/run_known_positive.py CVE-2026-31431 --out findings/cve-2026-31431.json

The script:
  1. Walks `vulntest/known-positive/<cell>/binary/` for *.ko, *.so,
     *.dll, *.exe, *.dylib (whatever's in the cell).
  2. Loads each via BinjaSession.
  3. Runs surface + taint + heap + crypto detectors (matches the
     Phase-1 analysis shape per `dev/validate.py`).
  4. Concatenates Findings, dedupes by Finding.id, writes the result
     as a top-level list to the output path.

Designed to be the upstream of `python -m scripts.verify.triage`:

    python dev/run_known_positive.py CVE-2026-31431 \
        --out findings/cve-2026-31431.json
    python -m scripts.verify.triage \
        --plan vulntest/known-positive/CVE-2026-31431/verification.json \
        --findings findings/cve-2026-31431.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ARGUS_ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ARGUS_ROOT / "skills" / "binary-ninja"
sys.path.insert(0, str(SKILL_DIR))

from scripts.lib import BinjaSession, load_config              # noqa: E402
from scripts.analysis import (                                  # noqa: E402
    crypto, heap, mitigations as mit, obfuscation, surface, taint,
)
from scripts.output.finding import Finding                      # noqa: E402


BINARY_EXTS = {".ko", ".so", ".dll", ".exe", ".dylib", ".elf"}


def _collect_binaries(cell_dir: Path) -> list[Path]:
    bin_dir = cell_dir / "binary"
    if not bin_dir.exists():
        return []
    return sorted(p for p in bin_dir.iterdir()
                  if p.is_file() and p.suffix.lower() in BINARY_EXTS)


def _analyse_one(path: Path) -> list[Finding]:
    print(f"\n=== {path.name} ({path.stat().st_size:,} bytes) ===", flush=True)
    findings: list[Finding] = []
    t0 = time.time()
    with BinjaSession(str(path)) as session:
        session.bv.update_analysis_and_wait()
        arch = str(session.bv.arch) if session.bv.arch else "unknown"
        plat = str(session.bv.platform) if session.bv.platform else "unknown"
        n_funcs = sum(1 for _ in session.bv.functions)
        print(f"  loaded in {time.time() - t0:.1f}s  arch={arch}  "
              f"platform={plat}  funcs={n_funcs}", flush=True)

        # Surface (also returns the mitigation profile we use to score
        # downstream taint/heap findings).
        t1 = time.time()
        profile, surf_f = surface.analyze(
            session=session, binary_path=str(path), run_heuristics=True,
        )
        print(f"  surface: {time.time() - t1:.1f}s  surf_findings={len(surf_f)}",
              flush=True)
        findings.extend(surf_f)

        for label, mod in (
            ("taint",       taint),
            ("heap",        heap),
            ("crypto",      crypto),
            ("obfuscation", obfuscation),
        ):
            t = time.time()
            try:
                got = mod.analyze(session, binary=str(path),
                                  arch=arch, platform=plat)
            except Exception as e:
                print(f"  {label:11s}: FAILED {type(e).__name__}: {e}", flush=True)
                continue
            print(f"  {label:11s}: {time.time() - t:.1f}s  findings={len(got)}",
                  flush=True)
            findings.extend(got)

    print(f"  total findings: {len(findings)}  in {time.time() - t0:.1f}s",
          flush=True)
    return findings


def _dedupe_by_id(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        if f.id not in seen:
            seen[f.id] = f
    return list(seen.values())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="run_known_positive")
    ap.add_argument("cell", help="cell name under vulntest/known-positive/")
    ap.add_argument("--out", type=Path, default=None,
                    help="output JSON path; default: findings/<cell-lower>.json")
    ap.add_argument("--vulntest-root", type=Path, default=None,
                    help="override vulntest dir; default: <repo>/vulntest")
    args = ap.parse_args(argv)

    vulntest = args.vulntest_root or (ARGUS_ROOT / "vulntest")
    cell_dir = vulntest / "known-positive" / args.cell
    if not cell_dir.exists():
        print(f"[error] cell directory missing: {cell_dir}", file=sys.stderr)
        return 2
    binaries = _collect_binaries(cell_dir)
    if not binaries:
        print(f"[error] no binaries under {cell_dir}/binary/", file=sys.stderr)
        return 2

    cfg = load_config()
    print(f"Argus run_known_positive — binja: {cfg.binja.resolved_python_path()}",
          flush=True)
    print(f"Cell: {args.cell}  binaries: {len(binaries)}", flush=True)

    findings: list[Finding] = []
    for b in binaries:
        findings.extend(_analyse_one(b))
    findings = _dedupe_by_id(findings)

    out_path = args.out
    if out_path is None:
        findings_dir = ARGUS_ROOT / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        out_path = findings_dir / f"{args.cell.lower()}.json"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\n[done] wrote {len(findings)} findings -> {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
