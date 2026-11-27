#!/usr/bin/env python3
"""hyblis check: run your PoC locally exactly as the Hyblis runner judges it, and see why it is
accepted or rejected before you submit.

It uses the same fixed runner files (runner/sol), the same task impact spec and the same verdict engine
(runner/trace_verdict.py) as the runner: two harness passes, the standalone run of your file, the
determinism and conformance checks. The only differences are where it runs: on your machine, against
your own RPC (an archive node, or an anvil fork of it) and without the runner's network sandbox. Do not
point it at a third-party RPC for an unreported bug: the provider sees every account and slot the PoC
reads.

Usage:
  python runner/check.py --task <id> --poc test/hyblis/HyblisPoC.t.sol --project <task project> \\
      --rpc <URL or IPC path> [--json] [--keep]

Needs Foundry 1.9.0 (forge, cast on PATH), the task project (the program's repo with its dependencies,
as described on the program page) and the Python packages eth-abi and eth-utils. Exit code: 0 validated,
1 rejected, 2 could not run.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen_spec  # noqa: E402
import run_submission as rs  # noqa: E402
import trace_verdict as tv  # noqa: E402


def render(v: dict) -> str:
    out = []
    if v.get("reproduced"):
        ev = v.get("evidence", {})
        out.append(f"VALIDATED  {v['impact_type']}  severity {v['measured_severity']}")
        out.append(f"  changed function : {v['changed_function']}")
        out.append(f"  changed contract : {v['changed_contract']}")
        out.append(f"  amount           : {ev.get('amount_usd')} USD (victim loss {ev.get('victim_loss_usd')}, "
                   f"your net gain {ev.get('attacker_gain_usd')}, capital {ev.get('capital_usd')})")
        for b in ev.get("broken_invariants", []):
            out.append(f"  invariant broken : {b['id']} ({b['impact']})")
        for f in ev.get("probe_flips", []):
            out.append(f"  victim blocked   : {f['id']} ({f['impact']})")
        out.append("  Your asserts and logs were not read; this is what the runner measured on the protocol.")
        return "\n".join(out)
    code = v.get("error") or "unknown"
    out.append(f"REJECTED  {code}")
    out.append("  " + (tv.explain(code) or "No explanation for this code."))
    if v.get("detail"):
        out.append(f"  detail: {v['detail']}")
    for f in v.get("policy") or []:
        out.append(f"  line {f.get('line')}: {f.get('reason')}")
    if code.startswith("policy:"):
        out.append(f"  The cheatcode was {code.split(':', 1)[1]}. Allowed: prank/startPrank of your own accounts, "
                   "forward warp/roll, label, sign with your own keys, expect*/assert*, recordLogs, and the "
                   "HyblisBase helpers (_fund, _asRole, _setPrice).")
    if code == "no_impact":
        ev = v.get("evidence") or {}
        if ev:
            out.append(f"  measured: victim loss {ev.get('victim_loss_usd')} USD, your net gain "
                       f"{ev.get('attacker_gain_usd')} USD (capital {ev.get('capital_usd')} USD subtracted)")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Check a PoC the way the Hyblis runner does.")
    ap.add_argument("--task", default="", help="task id (uses tasks/<id>/impact-spec.json and manifest.json)")
    ap.add_argument("--spec")
    ap.add_argument("--manifest")
    ap.add_argument("--poc", required=True)
    ap.add_argument("--project", required=True, help="the task's Foundry project (its dependencies installed)")
    ap.add_argument("--rpc", required=True, help="your archive RPC URL or IPC path; HYBLIS_ETH_RPC is set to it")
    ap.add_argument("--svm-dir", help="directory with solc-<version> binaries (default ~/.svm, then the runner's)")
    ap.add_argument("--forge-user", help="when run as root: the user forge runs as")
    ap.add_argument("--jobs-dir")
    ap.add_argument("--json", action="store_true", help="print the full verdict JSON")
    ap.add_argument("--keep", action="store_true", help="keep the job directory (forge outputs) for inspection")
    a = ap.parse_args()
    if not a.task and not a.spec:
        sys.exit("give --task or --spec")
    svm = [a.svm_dir] if a.svm_dir else [str(Path(os.path.expanduser("~")) / ".svm"), str(rs.DEFAULT_SVM)]
    import shutil
    opts = rs.Options(sandbox="none", forge_user=a.forge_user, idle=bool(shutil.which("chrt")), keep_job=a.keep,
                      jobs_dir=a.jobs_dir, svm_dir=svm, debug=a.keep, rlimits=bool(shutil.which("prlimit")))
    try:
        manifest, spec = rs.load_task(a.task, a.spec, a.manifest)
    except (gen_spec.SpecError, OSError, ValueError) as e:
        print(f"cannot load the task: {e}")
        sys.exit(2)
    v = rs.reproduce_with_spec(spec, Path(a.poc).read_text(), Path(a.project), a.rpc, "local-check",
                               manifest=manifest, options=opts)
    print(json.dumps(v, indent=1, default=str) if a.json else render(v))
    if v.get("error") in tv.RETRY_ERRORS:
        sys.exit(2)
    sys.exit(0 if v.get("reproduced") else 1)


if __name__ == "__main__":
    main()
