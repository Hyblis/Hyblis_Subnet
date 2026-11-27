"""Seed a demo dataset into an isolated DB and export public JSON, so the site
and the design artifact have realistic content (fake findings credited to the
public dev keys //Miner0..8).

Both HYBLIS_DATA_DIR and HYBLIS_PUBLIC_DIR must be set to scratch directories:
without them the platform uses the real DB and public export, so the script
refuses to run unless both are set and neither is the production directory.

Usage: HYBLIS_DATA_DIR=... HYBLIS_PUBLIC_DIR=... python seed_demo.py
"""
import os, sys, time, random, pathlib
# The sample findings are filed to the testnet reference program (cap), which is released on testnet only.
# Exported with intake open unless the caller says otherwise, so the design preview shows the whole flow.
os.environ.setdefault("HYBLIS_NETWORK", "testnet")
os.environ.setdefault("HYBLIS_INTAKE_OPEN", "1")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from bittensor_wallet import Keypair
from hyblis_platform import canonical, config, keys, models, pipeline, publish, store

for var, prod in (("HYBLIS_DATA_DIR", config.ROOT / "platform" / "data"),
                  ("HYBLIS_PUBLIC_DIR", config.ROOT / "platform" / "public")):
    v = os.environ.get(var)
    if not v or pathlib.Path(v).resolve() == prod.resolve():
        sys.exit(f"seed_demo: set {var} to a scratch directory; refusing to write demo data to {prod}")

store.init_db()
random.seed(7)
NOW = time.time()
POC = (config.ROOT / "tasks" / "cap" / "poc" / "HyblisPoC.t.sol").read_text()
miners = [Keypair.create_from_uri(f"//Miner{i}") for i in range(9)]
contracts = ["0xcCcc62962d17b8914c62D74FfB843d73B2a3cccC",
             "0x15622c3dbbc5614E6DFa9446603c1779647f01FC",
             "0xcD7f45566bc0E7303fB92A93969BB4D3f6e662bb"]
funcs = ["redeem", "borrow", "liquidate", "mint", "withdraw", "settle", "poke"]
# what the runner records for a rejected proof (codes and notes from runner/trace_verdict.py); taken in
# turn, not at random, so the sample data set stays the same as before these were added
REJECTS = [{"error": "no_impact", "detail": "no measured impact"},
           {"error": "policy:store(address,bytes32,bytes32)", "detail": "cheatcode not allowed"},
           {"error": "standalone_fails", "detail": "test_exploit() fails in plain forge test"},
           {"error": "capital", "detail": "capital in USDC above the task's cap"},
           {"error": "poc_reverted", "detail": "constructor, setUp or a test/step call reverted"}]
n_rej = 0
impacts = ["funds_loss", "accounting_error", "insolvency", "griefing", "unauthorized_mint"]
sevs = ["low", "medium"]            # launch programs accept Medium and Low only
measured = ["low", "medium", "high"]


def submit(kp, days_ago, sev, contract, func):
    t = NOW - days_ago * 86400
    poc = POC + f"\n// nonce {random.random()}\n"
    pkg = {"v": 1, "task_id": "cap", "hotkey": kp.ss58_address,
           "nonce": canonical.sha256_hex(str(random.random()).encode())[:24],
           "ts": int(t),
           "header": {"title": f"{func} {sev} issue", "contract": contract, "function": func,
                      "severity": sev, "description": f"demo finding on {func}"},
           "poc": poc, "poc_sha256": canonical.sha256_hex(poc.encode())}
    sid = models.submission_id(pkg)
    store.add_submission(pkg, keys.sign(kp, pkg), t, sid)
    return sid


n_val = n_acc = 0
for i in range(42):
    kp = random.choice(miners)
    days = random.uniform(0.1, 120)
    sev = random.choice(sevs)
    sid = submit(kp, days, sev, random.choice(contracts), random.choice(funcs))
    store.set_status(sid, config.STATUS_SCREENING, policy_verdict="PASS")
    roll = random.random()
    if roll < 0.18:
        continue  # left screening
    store.set_status(sid, config.STATUS_REPRODUCING)
    if roll < 0.30:
        pipeline.on_verdict(sid, dict({"reproduced": False, "deterministic": True}, **REJECTS[n_rej % len(REJECTS)]))
        n_rej += 1
        continue
    imp = random.choice(impacts)
    v = {"reproduced": True, "deterministic": True, "impact_type": imp,
         "measured_severity": random.choice(measured), "changed_function": random.choice(funcs),
         "changed_contract": "0xcccc62962d17b8914c62d74ffb843d73b2a3cccc",
         "evidence": {"profit": str(random.randint(1000, 500000)), "invariant_broken": True}}
    st = pipeline.on_verdict(sid, v)
    if st != config.STATUS_VALIDATED:
        continue
    n_val += 1
    r2 = random.random()
    if r2 < 0.45:
        pipeline.mark_filed(sid, f"PRIVATE-REF-{i}")
        if r2 < 0.22:
            pipeline.platform_accepted(sid, bounty_usd=random.choice([750, 1000, 3000, 5000]),
                                       period=int(store.to_day(NOW) // config.SETTLEMENT_PERIOD_DAYS))
            n_acc += 1

publish.export_all(now_ts=NOW)
print(f"seeded: validated~{n_val} accepted~{n_acc}; exported to {config.PUBLIC_DIR}")
