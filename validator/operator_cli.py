#!/usr/bin/env python3
"""Operator console (LOCAL ONLY, run as pinc on the platform host).

Privileged actions the owner/operator performs by hand:
  * list validated findings ready to file;
  * build the platform-ready report for one finding;
  * record that a report was filed, accepted (with bounty), or rejected;
  * compute the vault settlement (payout plan) for a set of period accruals;
  * list reports waiting on the runner, export the fork state they missed, release them;
  * (testnet) execute payouts by transfer_stake from the vault hotkey.

Platform names and bounty amounts entered here stay in the private DB.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "platform"))

from hyblis_platform import config, pipeline, publish, report_builder, settlement, store  # noqa: E402


def cmd_queue(a):
    for s in store.list_by_status(config.STATUS_VALIDATED):
        if publish.task_track(s["task_id"]) == "warmup":
            continue                                  # warm-up reproductions are never filed
        print(f"{s['submission_id'][:16]}  {s['severity_final'] or s['severity_claim']:8}  "
              f"task={s['task_id']:14}  {s['title'][:50]}")


def cmd_waiting(a):
    """Reports the runner could not finish: missing fork state, or a runner fault."""
    for s in store.list_by_status(config.STATUS_WAITING):
        n = len(json.loads(s.get("state_misses") or "[]"))
        print(f"{s['submission_id'][:16]}  task={s['task_id']:14}  reason={s.get('wait_reason') or '?':6}  "
              f"attempts={s.get('runner_attempts') or 0}  missing_state_items={n}")


def cmd_state_misses(a):
    """Write the fork state this program's waiting reports could not read, for
    `runner/state/snapshot.py extend`. The list shows where exploits look: keep it private."""
    misses = pipeline.pending_state_misses(a.task)
    text = json.dumps(misses, indent=1, sort_keys=True)
    if a.out:
        Path(a.out).write_text(text)
        print(f"{len(misses)} item(s) written to {a.out}")
    else:
        print(text)


def cmd_release(a):
    """After the snapshot was extended (or a runner fault fixed): queue the waiting reports again."""
    ids = pipeline.release_waiting(a.task, a.reason)
    print(f"released {len(ids)} report(s) of {a.task} back to the runner queue")


def cmd_report(a):
    print(report_builder.build(a.submission))


def cmd_file(a):
    pipeline.mark_filed(a.submission, a.ref)
    publish.export_all()
    print("filed", a.submission[:16], "ref(private)=", a.ref)


def cmd_accept(a):
    pipeline.platform_accepted(a.submission, a.bounty, a.period)
    publish.export_all()
    print("accepted", a.submission[:16], "bounty(private)=", a.bounty)


def cmd_reject(a):
    pipeline.platform_rejected(a.submission, a.reason)
    publish.export_all()
    print("rejected", a.submission[:16], a.reason)


def cmd_expire(a):
    n = pipeline.expire_stale()
    publish.export_all()
    print("expired", n)


def cmd_settle(a):
    accrual = json.loads(Path(a.accrual).read_text()) if a.accrual else {}
    accrual = {int(k): float(v) for k, v in accrual.items()}
    plan = settlement.plan_from_store(accrual, a.cap, a.current_period)
    out = {
        "payouts": plan.payouts, "burns": plan.burns, "carry_end": plan.carry_end,
        "by_hotkey": plan.by_hotkey, "periods": plan.periods,
    }
    print(json.dumps(out, indent=1))
    if a.out:
        Path(a.out).write_text(json.dumps(out, indent=1))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(required=True)

    sub.add_parser("queue").set_defaults(func=cmd_queue)

    p = sub.add_parser("report"); p.add_argument("submission"); p.set_defaults(func=cmd_report)
    p = sub.add_parser("file"); p.add_argument("submission"); p.add_argument("--ref", required=True); p.set_defaults(func=cmd_file)
    p = sub.add_parser("accept"); p.add_argument("submission"); p.add_argument("--bounty", type=float, required=True)
    p.add_argument("--period", type=int, default=None); p.set_defaults(func=cmd_accept)
    p = sub.add_parser("reject"); p.add_argument("submission"); p.add_argument("--reason", default="invalid"); p.set_defaults(func=cmd_reject)
    sub.add_parser("expire").set_defaults(func=cmd_expire)
    sub.add_parser("waiting").set_defaults(func=cmd_waiting)
    p = sub.add_parser("state-misses"); p.add_argument("task"); p.add_argument("--out"); p.set_defaults(func=cmd_state_misses)
    p = sub.add_parser("release"); p.add_argument("task"); p.add_argument("--reason", choices=["state", "runner"], default="state")
    p.set_defaults(func=cmd_release)
    p = sub.add_parser("settle"); p.add_argument("--accrual", help="json {period: alpha}")
    p.add_argument("--cap", type=float, default=None)
    p.add_argument("--current-period", dest="current_period", type=int, default=None,
                   help="force burns up to this settlement period even if accrual has no key there")
    p.add_argument("--out"); p.set_defaults(func=cmd_settle)

    a = ap.parse_args()
    store.init_db()
    try:
        a.func(a)
    except pipeline.IllegalTransition as e:
        raise SystemExit(f"refused: {e}")


if __name__ == "__main__":
    main()
