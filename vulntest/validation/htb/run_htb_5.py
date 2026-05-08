"""Run Argus detection against the 5 HTB binary exploitation challenges.

Outputs:
  - Per-binary finding summary (category, severity, function)
  - Generated PoC scripts saved to poc/<binary_name>_poc.py
  - Pass/fail verdict against expected detection categories
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

BINJA_PYTHON      = r"C:/Program Files/Vector35/BinaryNinja/python"
BINJA_USER_PKGS   = r"C:/Users/C2xor/AppData/Roaming/Python/Python310/site-packages"
sys.path.insert(0, BINJA_PYTHON)
sys.path.insert(0, BINJA_USER_PKGS)

ARGUS_ROOT  = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = ARGUS_ROOT / "skills" / "binary-ninja"
sys.path.insert(0, str(SCRIPTS_DIR))

import binaryninja

from scripts.lib import BinjaSession
from scripts.analysis import linux_exploit
from scripts.heuristics import chains as heur_chains
from scripts.heuristics import linux_exploit as heur_linux
from scripts.triage import auto_triage
from scripts.exploit import build as build_pocs

HERE = Path(__file__).resolve().parent
EXTRACTED = HERE / "tracks" / "binary_exploitation" / "extracted"

CHALLENGES = [
    {
        "name":   "hunting",
        "binary": EXTRACTED / "a12c7341-e1a6-4079-a523-0c768202dcf6/pwn_hunting/hunting",
        "expect": ["seccomp_filter", "defensive_alarm_timer", "rwx_shellcode_exec"],
        "chain":  "chains.scan_resistant_egg_hunt",
    },
    {
        "name":   "rocket_blaster_xxx",
        "binary": EXTRACTED / "a12c7380-1e06-401a-a27b-7c4db3087492/challenge/rocket_blaster_xxx",
        "expect": ["ret2win_win_function"],
        "chain":  "chains.ret2win_rop_chain",
    },
    {
        "name":   "el_mundo",
        "binary": EXTRACTED / "a12c7359-6c52-485c-a48b-caa2fe6b7fce/challenge/el_mundo",
        "expect": ["ret2win_win_function"],
        "chain":  "chains.ret2win_rop_chain",
    },
    {
        "name":   "el_pipo",
        "binary": EXTRACTED / "a12c7367-6b1d-4b51-b669-b845cdf5b9f8/challenge/el_pipo",
        "expect": ["adjacent_variable_overwrite"],
        "chain":  "chains.variable_overwrite",
    },
    {
        "name":   "el_teteo",
        "binary": EXTRACTED / "a12c7351-2b50-4571-a968-458617b670fa/challenge/el_teteo",
        "expect": ["ret2shellcode_exec"],
        "chain":  "chains.ret2shellcode_exec",
    },
]

POC_DIR = HERE / "poc"
POC_DIR.mkdir(exist_ok=True)


def run_challenge(cfg: dict) -> dict:
    name   = cfg["name"]
    binary = cfg["binary"]
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"  {binary}")
    print(f"{'='*60}")

    result = {
        "name":      name,
        "findings":  [],
        "chains":    [],
        "pocs":      [],
        "verdict":   {},
        "poc_files": [],
    }

    with BinjaSession(str(binary)) as session:
        session.bv.update_analysis_and_wait()
        arch     = str(session.bv.arch     or "unknown")
        platform = str(session.bv.platform or "unknown")
        binary_str = str(binary)

        findings = linux_exploit.analyze(
            session, binary=binary_str,
        )

        heur_findings = heur_linux.match(
            session.bv, binary=binary_str,
            arch=arch, platform=platform,
        )
        # Merge: deduplicate by category so heuristic-layer findings don't
        # double-count categories the analysis layer already confirmed.
        seen_cats = {f.category for f in findings}
        for hf in heur_findings:
            if hf.category not in seen_cats:
                findings.append(hf)
                seen_cats.add(hf.category)

        chain_findings = heur_chains.match(
            session.bv, binary=binary_str,
            arch=arch, platform=platform,
            existing_findings=findings,
        )
        findings.extend(chain_findings)

        auto_triage(findings)

        pocs = build_pocs(
            session, findings,
            binary=binary_str, arch=arch, platform=platform,
        )

    # Print findings
    print(f"\n  {len(findings)} findings:")
    for f in findings:
        sev = getattr(f.severity, "value", str(f.severity))
        print(f"    [{sev:8s}] {f.category:35s}  fn={f.function}")
        det = getattr(f, "details", {}) or {}
        if det:
            for k, v in list(det.items())[:6]:
                print(f"               {k}: {v}")
        result["findings"].append({"category": f.category, "function": f.function})

    expected_chain = cfg.get("chain", "")
    print(f"\n  {len(pocs)} PoC(s):")
    for poc in pocs:
        print(f"    {poc.chain_name} ({len(poc.primitives)} primitives)")
        script = getattr(poc, "exploit_script", None)
        if script:
            # Primary chain saves as {name}_poc.py; others get a chain-tagged name.
            chain_tag = poc.chain_name.rsplit(".", 1)[-1]
            if poc.chain_name == expected_chain:
                out_path = POC_DIR / f"{name}_poc.py"
            else:
                out_path = POC_DIR / f"{name}_{chain_tag}_poc.py"
            out_path.write_text(script, encoding="utf-8")
            print(f"    --> exploit script -> {out_path}")
            result["poc_files"].append(str(out_path))
        result["pocs"].append(poc.chain_name)

    # Verdict
    seen_cats = {f["category"] for f in result["findings"]}
    for cat in cfg["expect"]:
        result["verdict"][cat] = "PASS" if cat in seen_cats else "FAIL"
    chain_ok = cfg["chain"] in result["pocs"]
    result["verdict"]["chain"] = "PASS" if chain_ok else f"FAIL (got {result['pocs']})"

    print(f"\n  Verdict:")
    for k, v in result["verdict"].items():
        tag = "PASS" if v == "PASS" else "FAIL"
        print(f"    {tag}  {k}: {v}")

    return result


def main():
    results = []
    for cfg in CHALLENGES:
        try:
            r = run_challenge(cfg)
        except Exception as e:
            import traceback
            print(f"\n  ERROR: {type(e).__name__}: {e}")
            traceback.print_exc()
            r = {"name": cfg["name"], "verdict": {"error": str(e)}, "poc_files": []}
        results.append(r)

    print(f"\n\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    total_pass = total_fail = 0
    for r in results:
        for k, v in r.get("verdict", {}).items():
            tag = "PASS" if v == "PASS" else "FAIL"
            print(f"  {tag}  {r['name']:25s}  {k}: {v}")
            if tag == "PASS":
                total_pass += 1
            else:
                total_fail += 1
    print(f"\n  {total_pass} pass  {total_fail} fail")
    print(f"\n  PoC files:")
    for r in results:
        for f in r.get("poc_files", []):
            print(f"    {f}")


if __name__ == "__main__":
    main()
