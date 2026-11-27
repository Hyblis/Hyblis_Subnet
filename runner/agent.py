#!/usr/bin/env python3
"""Runner daemon. RUNS ONLY ON THE SEPARATE RUNNER MACHINE.

Polls the gateway for a reproduction job, runs it through run_submission (trace-verified validation),
and posts the verdict back. The gateway is reached over the internal token-auth API. Prepared task
projects (installed dependencies, built once with the runner's foundry.toml) live under
--projects/<task_id>.

Fork state (two modes):
  --snapshots DIR (recommended): for every job the agent starts a fresh read-only fork proxy from the
      runner's state layer (runner/state/fork_proxy.serve) over DIR/<task_id>/<digest> (the snapshot the
      task manifest records as chain.snapshot_digest; DIR/<task_id> if there is no such folder), the
      program's verified snapshot, on a per-job Unix socket, and passes its handle to run_submission. Reads outside the
      snapshot come back as handle.misses(); then the verdict is state_miss and the gateway holds the
      job until the operator extends the snapshot. One proxy per job, so misses are never mixed up.
  --fork-url-template /path/{task}.ipc: an externally managed fork source with no misses (for example
      a proxy in front of a self-hosted archive node).

The dispatch token never reaches forge: run_submission gives forge a scrubbed environment.
Infrastructure failures are reported as error "runner_error", which the platform retries
(platform/hyblis_platform/config.py RUNNER_RETRY_ERRORS) instead of rejecting the proof.

Usage (as root, so forge can run in its own network namespace as --forge-user):
  HYBLIS_RUNNER=1 HYBLIS_DISPATCH_TOKEN=... agent.py --gateway http://<platform-host>:9850 \\
      --projects /opt/hyblis-tasks --snapshots /opt/hyblis-snapshots --forge-user hyblis-forge [--once]
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request
from pathlib import Path

import run_submission
import trace_verdict as tv


def _post(url: str, token: str, payload: dict, timeout: int = 1800) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "X-Hyblis-Token": token},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode() or "{}")


def run_once(gateway: str, token: str, projects: Path, args) -> bool:
    job = _post(f"{gateway}/internal/claim", token, {}, timeout=30)
    if not job:
        return False
    task, sid = job["task_id"], job["submission_id"]
    print(f"[{time.strftime('%H:%M:%S')}] claimed {sid[:12]} task={task}", flush=True)
    handle = None
    try:
        opts = run_submission.Options(sandbox=args.sandbox, forge_user=args.forge_user, idle=not args.no_idle,
                                      jobs_dir=args.jobs_dir, foundry_bin=args.foundry_bin, svm_dir=args.svm_dir,
                                      isolate=args.isolate, max_memory_gb=args.max_memory_gb)
        if args.snapshots:
            from state import fork_proxy                  # runner/state (the verified-snapshot layer)
            chain = json.loads((run_submission.TASKS_DIR / task / "manifest.json").read_text())["chain"]
            sock_dir = Path(args.socket_dir)
            sock_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            fork_url = str(sock_dir / f"fork-{os.getpid()}-{int(time.time() * 1000)}.ipc")
            # the snapshot recorded for the pin (manifest chain.snapshot_digest): DIR/<task>/<digest hex>
            # if present, else DIR/<task>; any other snapshot is refused (SnapshotError -> runner_error)
            snap_dir = Path(args.snapshots) / task
            digest = chain.get("snapshot_digest")
            if digest and (snap_dir / digest.split(":", 1)[-1]).is_dir():
                snap_dir = snap_dir / digest.split(":", 1)[-1]
            handle = fork_proxy.serve(str(snap_dir), fork_url, socket_mode=0o666, expect_digest=digest,
                                      expect_block_hash=chain["fork_block_hash"], expect_chain_id=int(chain["chain_id"]))
        else:
            fork_url = args.fork_url_template.format(task=task)
        verdict = run_submission.reproduce(task, job["poc"], projects / task, sid, fork_url=fork_url,
                                           fork=handle, options=opts)
    except Exception as e:  # never crash the daemon on one bad job; never blame the proof for it
        verdict = tv.reject_verdict(tv.Reject("runner_error", type(e).__name__), sid)
    finally:
        if handle is not None:
            handle.close()
    verdict.pop("debug", None)
    res = _post(f"{gateway}/internal/verdict", token, {"submission_id": sid, "verdict": verdict})
    print(f"  -> {verdict.get('reproduced')} {verdict.get('impact_type') or verdict.get('error')} "
          f"status={res.get('status')}", flush=True)
    return True


def main():
    if os.environ.get("HYBLIS_RUNNER") != "1":
        raise SystemExit("set HYBLIS_RUNNER=1 (run only on the isolated runner machine)")
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--projects", required=True)
    ap.add_argument("--snapshots", help="verified snapshots, one directory per task (runner/state)")
    ap.add_argument("--socket-dir", default="/run/hyblis-fork", help="where per-job proxy sockets live")
    ap.add_argument("--fork-url-template", default="/run/hyblis/{task}.ipc",
                    help="without --snapshots: an external fork source per task (no misses)")
    ap.add_argument("--forge-user", help="unprivileged user forge runs as (required when run as root)")
    ap.add_argument("--sandbox", default="netns", choices=["netns", "none"])
    ap.add_argument("--jobs-dir")
    ap.add_argument("--no-idle", action="store_true", help="forge at normal priority (dedicated runner VM)")
    ap.add_argument("--foundry-bin", help="directory with the pinned forge (default: forge on PATH)")
    ap.add_argument("--svm-dir", help="solc versions (<dir>/<ver>/solc-<ver>)")
    ap.add_argument("--isolate", action="store_true",
                    help="shared host: also hide /home, /root, /tmp and other processes from forge")
    ap.add_argument("--max-memory-gb", type=float, default=32, help="address-space limit per forge process")
    ap.add_argument("--poll", type=float, default=10.0)
    ap.add_argument("--once", action="store_true")
    a = ap.parse_args()
    token = os.environ.get("HYBLIS_DISPATCH_TOKEN") or raise_missing()
    projects = Path(a.projects)
    while True:
        try:
            did = run_once(a.gateway, token, projects, a)
        except Exception as e:
            print(f"poll error: {type(e).__name__}", flush=True)
            did = False
        if a.once:
            break
        time.sleep(0.5 if did else a.poll)


def raise_missing():
    raise SystemExit("HYBLIS_DISPATCH_TOKEN is required")


if __name__ == "__main__":
    main()
