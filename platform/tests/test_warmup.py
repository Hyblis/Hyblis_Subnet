"""Warm-up track (releases.json "track": "warmup"): every miner who reproduces the known exploit earns once
(a "support" event, the warm-up pool of scoring v2); a second reproduction by the same hotkey or the same
proof file from another hotkey is a duplicate; nothing reaches the filing queue; discovery programs keep
"first valid wins". In-process, temporary database."""
import atexit, json, os, pathlib, shutil, sys, tempfile, time

tmp = pathlib.Path(tempfile.mkdtemp()); atexit.register(shutil.rmtree, tmp, True)
ROOT = pathlib.Path(__file__).resolve().parents[2]
tasks = tmp / "tasks"; tasks.mkdir()
for t in ("cap", "warm1"):
    os.symlink(ROOT / "tasks" / "cap", tasks / t)
(tasks / "releases.json").write_text(json.dumps({"launch": {"intake_open": True}, "cadence": {"release_every_days": 7}, "tasks": [
    {"task_id": "cap", "label": "Cap", "status": "open", "ready": True, "severity_scope": ["medium", "low"]},
    {"task_id": "warm1", "label": "Warm", "status": "open", "ready": True, "track": "warmup", "severity_scope": ["medium", "low"]}]}))
os.environ.update(HYBLIS_DATA_DIR=str(tmp / "data"), HYBLIS_PUBLIC_DIR=str(tmp / "public"), HYBLIS_TASKS_DIR=str(tasks),
                  HYBLIS_DISPATCH_TOKEN="t")
sys.path.insert(0, str(ROOT / "platform")); sys.path.insert(0, str(ROOT / "scoring"))
from bittensor_wallet import Keypair  # noqa: E402
from hyblis_platform import canonical, config, keys, models, pipeline, publish, store  # noqa: E402
from hyblis_scoring.policy import compute_v2  # noqa: E402

store.init_db(); config.ensure_dirs()
A, B = Keypair.create_from_uri("//WarmA"), Keypair.create_from_uri("//WarmB")
GOOD = {"reproduced": True, "deterministic": True, "impact_type": "funds_loss", "measured_severity": "medium",
        "changed_function": "withdrawFor", "changed_contract": "0x1111111111111111111111111111111111111111"}
_n = [0]
fails = []


def submit(kp, task, poc):
    _n[0] += 1
    pkg = {"v": 1, "task_id": task, "hotkey": kp.ss58_address, "nonce": f"{_n[0]:032x}", "ts": int(time.time()),
           "header": {"title": "t", "contract": "0x1111111111111111111111111111111111111111", "function": "withdrawFor",
                      "severity": "medium", "description": "d"},
           "poc": poc, "poc_sha256": canonical.sha256_hex(poc.encode())}
    sid = models.submission_id(pkg)
    store.add_submission(pkg, keys.sign(kp, pkg), time.time(), sid, "raw")
    store.set_status(sid, config.STATUS_SCREENING)
    job = pipeline.claim_for_runner()
    assert job and job["submission_id"] == sid
    return sid, pipeline.on_verdict(sid, dict(GOOD))


def check(ok, msg):
    print(("ok   " if ok else "FAIL ") + msg); (None if ok else fails.append(msg))


check(publish.task_track("warm1") == "warmup" and publish.task_track("cap") == "discovery", "track read from releases.json")
a1, st = submit(A, "warm1", "// A's own reproduction\n"); check(st == config.STATUS_VALIDATED, "A's reproduction is validated")
b1, st = submit(B, "warm1", "// B's own reproduction\n"); check(st == config.STATUS_VALIDATED, "B also earns for the same exploit (no first-wins)")
a2, st = submit(A, "warm1", "// A again\n"); check(st == config.STATUS_DUPLICATE, "A's second reproduction is a duplicate")
c1, st = submit(B, "warm1", "// A's own reproduction\n")
check(st == config.STATUS_DUPLICATE, "an exact copy of an earlier proof is a duplicate")
ev = [e for e in store.load_events() if e.kind == "support"]
check(sorted(e.miner for e in ev) == sorted([A.ss58_address, B.ss58_address]) and all(e.points == 1.0 for e in ev),
      "one warm-up point each for A and B")
check(not any(e.kind == "approved" for e in store.load_events()), "warm-up never creates a discovery finding")
r = compute_v2(store.load_events(), now=store.to_day(store.now()))
check(abs(r["miners"][A.ss58_address] - 0.5) < 1e-6 and abs(r["pools"]["warmup"] - 1.0) < 1e-9,
      "scoring v2 shares the pool between the two warm-up miners")
d1, st = submit(A, "cap", "// discovery 1\n"); check(st == config.STATUS_VALIDATED, "discovery: first valid wins")
d2, st = submit(B, "cap", "// discovery 2\n"); check(st == config.STATUS_DUPLICATE, "discovery: a later same-bug report is a duplicate")
import subprocess  # noqa: E402
q = subprocess.run([sys.executable, str(ROOT / "validator" / "operator_cli.py"), "queue"], capture_output=True, text=True,
                   env={**os.environ, "PYTHONPATH": f"{ROOT / 'platform'}:{ROOT / 'scoring'}"})
check(d1[:16] in q.stdout and a1[:16] not in q.stdout and b1[:16] not in q.stdout, "the filing queue lists discovery findings only")
print("warm-up: all passed" if not fails else f"warm-up: {len(fails)} FAILED")
sys.exit(1 if fails else 0)
