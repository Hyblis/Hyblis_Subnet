#!/usr/bin/env python3
"""End-to-end tests of the trace-verified runner on a local toy chain (anvil over IPC).

Runs every variant in runner/tests/variants/ through run_submission (two harness passes, standalone
run, determinism, conformance) and compares the verdict with variants/expected.json; then:
  * a broken fork source (tests/flaky_proxy.py) must give "nondeterministic";
  * the run_submission.py command line (HYBLIS_RUNNER=1, --fork-url, --misses-file, static screen);
  * a non-empty misses file must give state_miss and nothing else;
  * gen_spec.py --self-check on the toy spec (and a broken spec must fail it);
  * runner/check.py, the researchers' local tool;
  * as root: forge runs in an empty network namespace; a PoC's vm.rpc to anvil's HTTP port must fail.
As pinc there is no network namespace (it needs root): the sandbox tests are reported as SKIPPED.
Usage: test_e2e.py [--only v01,v40] [--update-fixtures]
"""
from __future__ import annotations

import argparse
import json
import lzma
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER = HERE.parent
sys.path.insert(0, str(RUNNER))
sys.path.insert(0, str(HERE))
import gen_spec  # noqa: E402
import policy_check  # noqa: E402
import run_submission as rs  # noqa: E402
import toy_chain  # noqa: E402
import trace_verdict as tv  # noqa: E402

FIXTURES = ["v01_honest_theft", "v14_hidden_store_helper", "v24_grief_then_prank_sink", "v35_two_faced",
            "v36_deposit_then_freeze", "v40_steps_txboundary", "v42_setprice_liquidation"]
ROOT_MODE = os.geteuid() == 0
FAILS: list[str] = []


def check(cond, msg):
    if cond:
        print(f"ok   {msg}", flush=True)
    else:
        print(f"FAIL {msg}", flush=True)
        FAILS.append(msg)


def matches(verdict: dict, want: dict, evidence: dict | None = None) -> bool:
    return all(verdict.get(k) == v for k, v in want.items()) and \
        all((verdict.get("evidence") or {}).get(k) == v for k, v in (evidence or {}).items())


def short(v: dict) -> str:
    if v.get("reproduced"):
        return f"{v['impact_type']}/{v['measured_severity']} {v['changed_function']} {v['changed_contract'][:10]}"
    return f"REJECT {v.get('error')} ({v.get('detail')})"


def options(work: Path, keep=False) -> rs.Options:
    return rs.Options(sandbox="netns" if ROOT_MODE else "none", forge_user="pinc" if ROOT_MODE else None,
                      jobs_dir=str(work), keep_job=keep, debug=keep)


def run_variants(chain, spec, work, only, update_fixtures):
    exp = json.loads((HERE / "variants" / "expected.json").read_text())["variants"]
    manifest = json.loads((HERE / "toy" / "manifest.json").read_text())
    names = [n for n in exp if not only or any(n.startswith(o) for o in only)]
    t0 = time.time()
    for name in names:
        src = (HERE / "variants" / f"{name}.sol").read_text()
        keep = update_fixtures and name in FIXTURES
        v = rs.reproduce_with_spec(spec, src, chain.project, str(chain.ipc), name, options=options(work, keep))
        check(matches(v, exp[name]["verdict"], exp[name].get("evidence_expected")), f"{name:32s} {short(v)}")
        screen, _ = policy_check.check(manifest, src)
        if screen != exp[name]["screen"]:
            check(False, f"{name}: static screen {screen}, expected {exp[name]['screen']}")
        if keep:
            save_fixture(name, v, chain)
    print(f"     {len(names)} variants in {time.time() - t0:.0f} s", flush=True)


def save_fixture(name, v, chain):
    job = Path(v["debug"]["job"])
    fx = HERE / "fixtures"
    fx.mkdir(exist_ok=True)
    meta = {"variant": name, "rpc_url": str(chain.ipc), "salt": v["runner"]["salt"], "steps": v["runner"]["steps"],
            "expected": {k: v.get(k) for k in ("reproduced", "impact_type", "measured_severity", "changed_function",
                                               "changed_contract", "error")}}
    for part in ("pass1", "pass2", "standalone"):
        f = job / f"{part}.json"
        if f.exists() and f.stat().st_size:
            (fx / f"{name}.{part}.json.xz").write_bytes(lzma.compress(f.read_bytes(), preset=9))
    (fx / f"{name}.meta.json").write_text(json.dumps(meta, indent=1) + "\n")
    shutil.rmtree(job, ignore_errors=True)


def flaky(chain, spec, work):
    sock = work / "flaky.sock"
    cmd = toy_chain.as_user([sys.executable, "-I", "-B", str(HERE / "flaky_proxy.py"), str(sock), str(chain.ipc)])
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": os.environ.get("PYTHONPATH", "")}
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        for _ in range(50):
            if sock.exists():
                break
            time.sleep(0.1)
        src = (HERE / "variants" / "v53_flaky_fork.sol").read_text()
        v = rs.reproduce_with_spec(spec, src, chain.project, str(sock), "flaky", options=options(work))
        check(v.get("error") == "nondeterministic" and v["runner"].get("attempts") == 2,
              f"broken fork source -> {short(v)}, after {v['runner'].get('attempts')} attempts")
    finally:
        os.killpg(p.pid, 15)
        p.wait()


def cli(chain, work, spec_path):
    py = [sys.executable, "-I", "-B", str(RUNNER / "run_submission.py")]
    base = ["--task", "toy", "--spec", str(spec_path), "--manifest", str(HERE / "toy" / "manifest.json"),
            "--project", str(chain.project), "--fork-url", str(chain.ipc), "--jobs-dir", str(work)]
    base += ["--sandbox", "netns", "--forge-user", "pinc"] if ROOT_MODE else ["--sandbox", "none"]
    env = {"PATH": os.environ["PATH"], "HYBLIS_ROOT": str(RUNNER.parent)}

    def run(variant, extra=(), runner=True):
        e = dict(env, HYBLIS_RUNNER="1") if runner else env
        p = subprocess.run(py + base + ["--poc", str(HERE / "variants" / f"{variant}.sol"), "--submission", variant,
                                        *extra], capture_output=True, text=True, env=e, timeout=900)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            return p.returncode, {"_stdout": p.stdout[-500:], "_stderr": p.stderr[-500:]}

    rc, v = run("v01_honest_theft", runner=False)
    check(rc != 0 and "_stdout" in v, "run_submission.py refuses to run without HYBLIS_RUNNER=1")
    rc, v = run("v01_honest_theft")
    check(v.get("reproduced") is True and v.get("changed_function") == "withdrawFor(address,uint256)" and
          v.get("changed_contract") == "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0" and v.get("state_misses") == [],
          f"CLI honest theft -> {short(v) if 'reproduced' in v else v}")
    keys = {"submission_id", "reproduced", "deterministic", "impact_type", "measured_severity", "changed_function",
            "changed_contract", "evidence", "state_misses", "error", "detail", "attacker_set", "fingerprints", "runner"}
    check(set(v) == keys, f"verdict keys are exactly {sorted(keys)}")
    rc, v = run("v04_prank_protocol")
    check(v.get("error") == "screen" and v.get("policy") and all(isinstance(f["line"], int) for f in v["policy"]),
          f"CLI static screen -> {v.get('error')} with {len(v.get('policy') or [])} reasons and their lines")
    misses = work / "misses.json"
    misses.write_text(json.dumps([{"method": "eth_getStorageAt", "address": "0xabc", "slot": "0x1"}]))
    rc, v = run("v01_honest_theft", ["--misses-file", str(misses)])
    check(v.get("error") == "state_miss" and v.get("reproduced") is False and len(v.get("state_misses")) == 1 and
          not v.get("impact_type"), "non-empty misses file -> state_miss, nothing else decided")
    misses.write_text("")
    rc, v = run("v01_honest_theft", ["--misses-file", str(misses)])
    check(v.get("reproduced") is True, "empty misses file -> normal verdict")


def network(chain, spec, work):
    if not ROOT_MODE:
        print("SKIP network namespace tests (need root to create a network namespace)", flush=True)
        return
    src = (HERE / "variants" / "v60_network_exfil.sol").read_text().replace("9866", str(chain.port))
    v = rs.reproduce_with_spec(spec, src, chain.project, str(chain.ipc), "net", options=options(work, keep=True))
    job = Path(v["debug"]["job"])
    doc = json.loads((job / "pass1.json").read_text())
    ex = [a for k, a in list(doc.values())[0]["test_results"]["test_hyblis()"]["traces"] if k == "Execution"][0]["arena"]
    rpc = [n for n in ex if n["trace"]["address"].lower() == tv.CHEAT and n["trace"]["data"][2:10] == tv.sel("rpc(string,string,string)")]
    check(v.get("error") == "policy:rpc(string,string,string)" and rpc and not rpc[0]["trace"]["success"],
          "inside the network namespace a PoC cannot reach anvil's HTTP port (vm.rpc fails) and is rejected")
    shutil.rmtree(job, ignore_errors=True)


SNAPSHOT_VARIANTS = ["v01_honest_theft", "v02_marker_only", "v05_grief_sweep", "v06_freeze", "v25_theft_with_capital",
                     "v26_profit_in_attack_contract", "v40_steps_txboundary", "v42_setprice_liquidation",
                     "v44_asrole_allowed", "v50_sign_own_key", "v59_create2_helper"]


class _NoFresh:
    """A fork handle without fresh-account support (as before the state layer learnt them)."""
    def __init__(self, h):
        self.misses = h.misses


def snapshot_mode(chain, spec, work):
    """Option B end to end: the variants run through a collect session (Hyblis-owned code only), a snapshot
    is built and proven, then every variant runs against the read-only proxy and must give the same verdict
    with no miss. The job's salted PoC address and attacker accounts are answered as fresh accounts
    (runner/state/fresh.py); without them even an empty PoC misses."""
    from state import fork_proxy, snapshot
    exp = json.loads((HERE / "variants" / "expected.json").read_text())["variants"]
    hdr = chain.fork_header()
    mode = 0o666 if ROOT_MODE else 0o660
    sess = snapshot.CollectSession(str(chain.ipc), 31337, toy_chain.FORK_BLOCK, hdr["hash"],
                                   str(work / "collect.ipc"), socket_mode=mode)
    try:
        for n in SNAPSHOT_VARIANTS:
            rs.reproduce_with_spec(spec, (HERE / "variants" / f"{n}.sol").read_text(), chain.project,
                                   sess.socket_path, n, fork=sess, options=options(work))
    finally:
        sess.close()
    sess.write_access(str(work / "access.json"))
    snap = work / "snap"
    rc = snapshot.main(["build", "--chain-id", "31337", "--block", str(toy_chain.FORK_BLOCK), "--expect-block-hash",
                        hdr["hash"], "--access", str(work / "access.json"), "--upstream", str(chain.ipc),
                        "--out", str(snap)])
    check(rc == 0, "snapshot built from the collect session's access list")
    toy_chain.chown(work)
    h = fork_proxy.serve(str(snap), str(work / "nofresh.ipc"), expect_block_hash=hdr["hash"], socket_mode=mode)
    try:
        v = rs.reproduce_with_spec(spec, (HERE / "variants" / "v02_marker_only.sol").read_text(), chain.project,
                                   h.socket_path, "nofresh", fork=_NoFresh(h), options=options(work))
    finally:
        h.close()
    check(v.get("error") == "state_miss", f"without fresh accounts an empty PoC misses -> {short(v)}")
    t0 = time.time()
    for n in SNAPSHOT_VARIANTS:
        h = fork_proxy.serve(str(snap), str(work / f"snap-{n[:3]}.ipc"), expect_block_hash=hdr["hash"], socket_mode=mode)
        try:
            v = rs.reproduce_with_spec(spec, (HERE / "variants" / f"{n}.sol").read_text(), chain.project,
                                       h.socket_path, n, fork=h, options=options(work))
            st = h.stats()
        finally:
            h.close()
        check(matches(v, exp[n]["verdict"]) and st["misses"] == 0 and st["fresh_hits"] > 0,
              f"snapshot {n:28s} {short(v)} (fresh reads {st['fresh_hits']})")
    print(f"     {len(SNAPSHOT_VARIANTS)} variants against the snapshot in {time.time() - t0:.0f} s", flush=True)


def self_check(chain, spec_dict, work):
    p = work / "spec-ok.json"
    p.write_text(json.dumps(spec_dict))
    opts = options(work)
    res = gen_spec.self_check(p, chain.project, str(chain.ipc), options=opts)
    check(res["ok"], f"gen_spec self-check on the toy spec: {res['problems'] or 'ok'}")
    bad = json.loads(json.dumps(spec_dict))
    bad["invariants"].append({"id": "never", "class": "accounting", "holds": "not solvent"})
    bad["probes"].append({"id": "bob_withdraw_too_much", "class": "liveness", "actor": "@bob", "target": "@vault",
                          "sig": "withdraw(uint256)", "args": ["31000000000000000000"]})
    bad["fork"]["timestamp"] = int(bad["fork"]["timestamp"]) + 1
    p2 = work / "spec-bad.json"
    p2.write_text(json.dumps(bad))
    res = gen_spec.self_check(p2, chain.project, str(chain.ipc), options=opts)
    probs = " | ".join(res["problems"])
    check(not res["ok"] and "never" in probs and "bob_withdraw_too_much" in probs and "timestamp" in probs,
          "self-check reports an invariant that does not hold, a failing probe and a wrong timestamp")


def check_tool(chain, work, spec_path):
    py = [sys.executable, "-I", "-B", str(RUNNER / "check.py")]
    env = {"PATH": os.environ["PATH"], "HYBLIS_ROOT": str(RUNNER.parent)}
    common = ["--spec", str(spec_path), "--manifest", str(HERE / "toy" / "manifest.json"), "--project",
              str(chain.project), "--rpc", str(chain.ipc), "--jobs-dir", str(work)]
    if ROOT_MODE:
        common += ["--forge-user", "pinc"]
    p = subprocess.run(py + common + ["--poc", str(HERE / "variants" / "v01_honest_theft.sol")], capture_output=True,
                       text=True, env=env, timeout=900)
    check(p.returncode == 0 and "VALIDATED" in p.stdout and "withdrawFor(address,uint256)" in p.stdout,
          "hyblis check: honest theft is VALIDATED with its function")
    p = subprocess.run(py + common + ["--poc", str(HERE / "variants" / "v14_hidden_store_helper.sol")],
                       capture_output=True, text=True, env=env, timeout=900)
    check(p.returncode == 1 and "REJECTED" in p.stdout and "store(address,bytes32,bytes32)" in p.stdout and
          "cheatcode that is not allowed" in p.stdout, "hyblis check: hidden vm.store is REJECTED with a plain reason")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--update-fixtures", action="store_true")
    a = ap.parse_args()
    only = [x for x in a.only.split(",") if x]
    work = Path(tempfile.mkdtemp(prefix="hyblis-runner-test-", dir="/tmp"))
    toy_chain.chown(work)
    chain = toy_chain.ToyChain(work)
    print(f"mode: {'root (network namespace, forge as pinc)' if ROOT_MODE else 'pinc (no network namespace)'}; "
          f"work dir {work}", flush=True)
    try:
        chain.prepare_project()
        chain.start()
        chain.deploy()
        spec_dict = chain.spec_dict()
        spec = gen_spec.compile_spec(spec_dict)
        spec_path = work / "impact-spec.json"
        spec_path.write_text(json.dumps(spec_dict))
        toy_chain.chown(work)
        print(f"toy chain on {chain.ipc} (anvil HTTP 127.0.0.1:{chain.port}), fork block {toy_chain.FORK_BLOCK}",
              flush=True)
        if a.update_fixtures:
            (HERE / "fixtures").mkdir(exist_ok=True)
            (HERE / "fixtures" / "spec.compiled.json").write_text(json.dumps(spec, indent=1, sort_keys=True) + "\n")
        run_variants(chain, spec, work, only, a.update_fixtures)
        if not only:
            flaky(chain, spec, work)
            cli(chain, work, spec_path)
            network(chain, spec, work)
            self_check(chain, spec_dict, work)
            check_tool(chain, work, spec_path)
            snapshot_mode(chain, spec, work)
    finally:
        chain.stop()
        shutil.rmtree(work, ignore_errors=True)
    if a.update_fixtures and os.geteuid() == 0:
        toy_chain.chown(HERE / "fixtures")
    print()
    print("ALL E2E TESTS PASS" if not FAILS else f"{len(FAILS)} E2E TESTS FAILED")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
