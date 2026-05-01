"""Run the pre-Argus legacy skills against the same control set.

The legacy scripts at `~/.claude/skills/binary-ninja/scripts/` are
the pre-rebase tooling; this harness invokes them against the same
binaries the Argus pipeline targets and records:

- findings count (or vuln count, depending on script)
- wall-clock time
- success / failure of the run

Output: list[dict] suitable for the side-by-side comparison table.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


LEGACY_DIR = Path(r"C:\Users\C2xor\.claude\skills\binary-ninja\scripts")

LEGACY_SCRIPTS = [
    ("security_audit.py", "findings"),
    ("deep_analysis.py", "data_flow_paths"),
    ("heap_analysis.py", "vulnerabilities"),
]

DEFAULT_TARGETS = [
    r"C:\Windows\System32\utilman.exe",
    r"C:\Windows\System32\sethc.exe",
    r"C:\Windows\System32\osk.exe",
]


def _binja_python_env() -> dict:
    env = os.environ.copy()
    binja_py = r"C:\Program Files\Vector35\BinaryNinja\python"
    sep = ";" if os.name == "nt" else ":"
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (binja_py + sep + existing) if existing else binja_py
    return env


def _count_findings(report: dict, key: str) -> int:
    """Each legacy script structures its report differently; normalise."""
    if key == "findings":
        # security_audit: report["findings"] is a list
        return len(report.get("findings", []))
    if key == "data_flow_paths":
        # deep_analysis: nested structure with various lists
        if "data_flow_paths" in report:
            return len(report["data_flow_paths"])
        if "summary" in report:
            return int(report["summary"].get("total_findings", 0)) \
                or int(report["summary"].get("vulnerabilities_found", 0))
        return 0
    if key == "vulnerabilities":
        # heap_analysis: report["vulnerabilities"]["total"]
        v = report.get("vulnerabilities", {})
        if isinstance(v, dict):
            return int(v.get("total", 0))
        if isinstance(v, list):
            return len(v)
        return 0
    return 0


def run_legacy(script_name: str, target: Path, env: dict) -> dict:
    script_path = LEGACY_DIR / script_name
    if not script_path.exists():
        return {"script": script_name, "skipped": True, "reason": "missing"}
    t0 = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(script_path), str(target)],
            capture_output=True, env=env, timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {"script": script_name, "error": "timeout", "elapsed": 300.0}
    elapsed = time.time() - t0

    findings_count = 0
    parse_error = None
    if proc.returncode == 0:
        try:
            report = json.loads(proc.stdout)
            key = next((k for s, k in LEGACY_SCRIPTS if s == script_name), "findings")
            findings_count = _count_findings(report, key)
        except json.JSONDecodeError as e:
            parse_error = str(e)

    return {
        "script": script_name,
        "elapsed": round(elapsed, 2),
        "returncode": proc.returncode,
        "findings": findings_count,
        "stderr_tail": proc.stderr.decode(errors="replace").splitlines()[-3:]
            if proc.stderr else [],
        "parse_error": parse_error,
    }


def main(argv: list[str]) -> int:
    targets = [Path(p) for p in (argv[1:] or DEFAULT_TARGETS)]
    env = _binja_python_env()

    print(f"Argus dev/legacy_validate — legacy dir: {LEGACY_DIR}")
    print(f"Targets: {len(targets)}")

    results: dict = {}
    for tpath in targets:
        if not tpath.exists():
            print(f"\n[skip] missing: {tpath}")
            continue
        print(f"\n=== {tpath.name} ===")
        per_script: dict = {}
        for script_name, _key in LEGACY_SCRIPTS:
            r = run_legacy(script_name, tpath, env)
            per_script[script_name] = r
            if r.get("skipped"):
                print(f"  {script_name:24s}  SKIPPED ({r['reason']})")
                continue
            if r.get("error"):
                print(f"  {script_name:24s}  ERROR ({r['error']})  elapsed={r['elapsed']}s")
                continue
            print(f"  {script_name:24s}  rc={r['returncode']:>3}  "
                  f"findings={r['findings']:>3}  elapsed={r['elapsed']}s")
            if r.get("parse_error"):
                print(f"    parse_error: {r['parse_error']}")
            if r["returncode"] != 0:
                for line in r["stderr_tail"]:
                    print(f"    stderr: {line}")
        results[tpath.name] = per_script

    print(f"\n=== summary (legacy total findings per binary) ===")
    for name, per in results.items():
        total = sum((r.get("findings", 0) for r in per.values()
                    if not r.get("error") and not r.get("skipped")))
        print(f"  {name:24s}  total_findings={total}")

    out_path = Path(__file__).parent / "legacy_validate_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
