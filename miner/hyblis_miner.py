#!/usr/bin/env python3
"""Hyblis miner CLI: inspect tasks, then sign and submit a PoC.

The miner never sends funds or runs anything on-chain here; it only signs a
submission package with its hotkey and posts it to the gateway. The same
structural validation the gateway runs is run locally first, so bad packages
fail fast.

Examples:
  hyblis_miner.py tasks --gateway http://127.0.0.1:9850
  hyblis_miner.py submit --task aave-v4 --poc my_poc.t.sol \
     --title "..." --contract 0x.. --function borrow --severity high \
     --desc "short description" --wallet miner --hotkey default
  hyblis_miner.py status --gateway http://127.0.0.1:9850 <submission_id>
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "platform"))

from hyblis_platform import canonical, keys, models  # noqa: E402


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read().decode())


def _tasks(gateway: str) -> list:
    """The released programs: the site's public program list (on hyblis.com the gateway exposes
    only submit, submission and receipt), falling back to the gateway's own list for local setups."""
    try:
        return _get(f"{gateway}/data/tasks.json")
    except Exception:
        return _get(f"{gateway}/api/tasks")


def _post(url: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.reason, "body": e.read().decode()[:500]}


def cmd_tasks(a):
    print(json.dumps(_tasks(a.gateway), indent=1))


def cmd_status(a):
    print(json.dumps(_get(f"{a.gateway}/api/submission/{a.submission}"), indent=1))


def cmd_submit(a):
    import bittensor_wallet
    poc = Path(a.poc).read_text()
    pkg = {
        "v": 1, "task_id": a.task,
        "hotkey": "",  # filled below
        "nonce": secrets.token_hex(16), "ts": int(time.time()),
        "header": {"title": a.title, "contract": a.contract.lower(), "function": a.function,
                   "severity": a.severity, "description": a.desc},
        "poc": poc, "poc_sha256": canonical.sha256_hex(poc.encode()),
    }
    if a.seed:
        kp = keys.keypair_from_seed(a.seed)
    else:
        w = bittensor_wallet.Wallet(name=a.wallet, hotkey=a.hotkey)
        kp = w.hotkey
    pkg["hotkey"] = kp.ss58_address

    # local structural check (same code the gateway runs)
    tasks = {t["task_id"] for t in _tasks(a.gateway)} if not a.offline else {a.task}
    try:
        models.validate_package(pkg, tasks or {a.task})
    except models.ValidationError as e:
        raise SystemExit(f"package invalid: {e}")

    sig = keys.sign(kp, pkg)
    if a.dry_run:
        print(json.dumps({"package": pkg, "sig": sig}, indent=1))
        return
    code, resp = _post(f"{a.gateway}/api/submit", {"package": pkg, "sig": sig})
    print(code, json.dumps(resp, indent=1))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="http://127.0.0.1:9850")
    sub = ap.add_subparsers(required=True)

    sub.add_parser("tasks").set_defaults(func=cmd_tasks)
    p = sub.add_parser("status"); p.add_argument("submission"); p.set_defaults(func=cmd_status)

    p = sub.add_parser("submit")
    p.add_argument("--task", required=True)
    p.add_argument("--poc", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--contract", required=True)
    p.add_argument("--function", required=True)
    p.add_argument("--severity", required=True, choices=["low", "medium", "high", "critical"])
    p.add_argument("--desc", required=True)
    p.add_argument("--wallet", default="miner")
    p.add_argument("--hotkey", default="default")
    p.add_argument("--seed", default="", help="hex seed instead of a wallet (testing)")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--offline", action="store_true", help="skip fetching task list for validation")
    p.set_defaults(func=cmd_submit)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
