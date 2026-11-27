"""Runner retries: a run that needed fork state outside the program's snapshot, or that hit a
runner fault, must never reject the report. It waits (publicly "reproducing") and goes back to
the queue. Also: duplicates are keyed on the contract and function the runner measured."""
import json
import os
import pathlib
import sys
import tempfile
import time

tmp = pathlib.Path(tempfile.mkdtemp())
os.environ["HYBLIS_DATA_DIR"] = str(tmp / "data")
os.environ["HYBLIS_PUBLIC_DIR"] = str(tmp / "public")
os.environ.setdefault("HYBLIS_DISPATCH_TOKEN", "t")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from bittensor_wallet import Keypair  # noqa: E402
from hyblis_platform import canonical, config, keys, models, pipeline, publish, store  # noqa: E402

store.init_db()
config.ensure_dirs()
KP = Keypair.create_from_uri("//RequeueTest")
POC = "// poc\n"
_n = [0]


def submit(contract="0xcccc62962d17b8914c62d74ffb843d73b2a3cccc", poc=POC):
    _n[0] += 1
    pkg = {"v": 1, "task_id": "cap", "hotkey": KP.ss58_address, "nonce": f"{_n[0]:032x}", "ts": int(time.time()),
           "header": {"title": "t", "contract": contract, "function": "redeem", "severity": "medium",
                      "description": "d"},
           "poc": poc, "poc_sha256": canonical.sha256_hex(poc.encode())}
    sid = models.submission_id(pkg)
    store.add_submission(pkg, keys.sign(KP, pkg), time.time(), sid, "raw")
    store.set_status(sid, config.STATUS_SCREENING)
    return sid


def run(sid, verdict):
    job = pipeline.claim_for_runner()
    assert job and job["submission_id"] == sid, job
    return pipeline.on_verdict(sid, verdict)


def public_status(sid):
    rows = {r["hash"]: r for r in publish.public_ledger()}
    return rows[sid]["status"]


GOOD = {"reproduced": True, "deterministic": True, "impact_type": "funds_loss", "measured_severity": "medium",
        "changed_function": "redeem", "changed_contract": "0x1111111111111111111111111111111111111111"}

# 1) state_miss -> waiting, public "reproducing", misses kept privately, no rejection
a = submit()
miss = [{"kind": "storage", "address": "0xabc", "slot": "0x1"}]
assert run(a, {"reproduced": False, "error": "state_miss", "state_misses": miss}) == config.STATUS_WAITING
assert public_status(a) == "reproducing"
assert pipeline.claim_for_runner() is None, "a waiting report must not be handed to the runner again"
assert pipeline.pending_state_misses("cap") == miss
assert "0xabc" not in json.dumps(publish.export_all()), "missing-state items must never be public"
print("ok state_miss waits, shows as reproducing, keeps the misses private")

# 2) release after the snapshot is extended -> screening -> validates normally
assert pipeline.release_waiting("cap", "state") == [a]
assert run(a, GOOD) == config.STATUS_VALIDATED
print("ok release puts it back in the queue and it validates")

# 3) runner faults: retried up to the limit, then wait for the operator; never rejected
b = submit(poc="// other poc\n")
for i in range(config.RUNNER_MAX_ATTEMPTS - 1):
    assert run(b, {"reproduced": False, "error": "runner_error"}) == config.STATUS_SCREENING
assert run(b, {"reproduced": False, "error": "runner_error"}) == config.STATUS_WAITING
assert store.get(b)["wait_reason"] == "runner"
assert pipeline.release_waiting("cap", "runner") == [b] and store.get(b)["runner_attempts"] == 0
print(f"ok runner faults retry {config.RUNNER_MAX_ATTEMPTS - 1} times, then wait; release resets the count")

# 4) a real failure is still a rejection
assert run(b, {"reproduced": False, "deterministic": True, "error": "no_impact"}) == config.STATUS_REJECTED
print("ok a proof with no measured impact is rejected")

# 5) fingerprint uses the MEASURED contract: a different header contract does not dodge 'duplicate'
c = submit(contract="0x15622c3dbbc5614e6dfa9446603c1779647f01fc", poc="// third poc\n")
assert run(c, GOOD) == config.STATUS_DUPLICATE, store.get(c)["status"]
assert store.get(c)["dup_of"] == a
print("ok the duplicate is found from the measured contract, whatever the header says")

# 6) a positive verdict without the measured contract is a runner fault, not a validation
d = submit(poc="// fourth poc\n")
bad = dict(GOOD); bad.pop("changed_contract")
assert run(d, bad) == config.STATUS_SCREENING and store.get(d)["runner_attempts"] == 1
print("ok a positive verdict without a measured contract is retried, never validated")
assert run(d, {"reproduced": False, "deterministic": True, "error": "no_impact"}) == config.STATUS_REJECTED   # drain the queue
# 7) one job cannot flood the program's extend list
e = submit(poc="// fifth poc\n")
flood = [{"kind": "storage", "address": "0xdef", "slot": hex(i)} for i in range(1000)]
assert run(e, {"reproduced": False, "error": "state_miss", "state_misses": flood}) == config.STATUS_WAITING
assert len(json.loads(store.get(e)["state_misses"])) == config.RUNNER_MAX_MISSES_PER_JOB
print(f"ok one job adds at most {config.RUNNER_MAX_MISSES_PER_JOB} missing items")
print("ALL REQUEUE TESTS PASS")
