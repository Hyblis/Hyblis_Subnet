"""Quick end-to-end smoke of the core platform modules (no HTTP, no PoC run)."""
import atexit, shutil, sys, time, tempfile, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # platform/
from bittensor_wallet import Keypair
from hyblis_platform import config, canonical, keys, models, store, dedup, settlement

d = pathlib.Path(tempfile.mkdtemp())
atexit.register(shutil.rmtree, d, True)
config.DATA_DIR = d
config.PUBLIC_DIR = d / "public"
config.DB_PATH = d / "hyblis.db"
store.init_db()

kp = Keypair.create_from_uri("//Alice")
poc = "// SPDX\ncontract X { function test_x() public {} }\n"
pkg = {
    "v": 1, "task_id": "cap", "hotkey": kp.ss58_address, "nonce": "aabbccdd00112233",
    "ts": int(time.time()),
    "header": {"title": "t", "contract": "0x15622c3dbbc5614E6DFa9446603c1779647f01FC",
               "function": "borrow", "severity": "high", "description": "desc line"},
    "poc": poc, "poc_sha256": canonical.sha256_hex(poc.encode()),
}
models.validate_package(pkg, {"cap"})
# the shared check (the miner CLI runs it too) refuses an unbounded ts, and a hotkey that is
# not SS58 format 42 of a real key: Alice's key spelled for Polkadot, and the all-zero key
for over, why in (({"ts": 10 ** 400}, "ts"), ({"ts": 2 ** 53}, "ts"), ({"ts": 1.8e9}, "ts"),
                  ({"hotkey": "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5"}, "hotkey"),
                  ({"hotkey": "5C4hrfjw9DjXZTzV3MwzrrAr9P1MJhSrvWGWqi1eSuyUpnhM"}, "hotkey")):
    try:
        models.validate_package(dict(pkg, **over), {"cap"})
        raise AssertionError(f"accepted {over}")
    except models.ValidationError as e:
        assert str(e).startswith(why), (over, e)
assert keys.is_valid_ss58("15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5")   # it does decode, to Alice's key
print("OK validation: ts bounded, hotkey must be SS58 format 42 of a real key")
sig = keys.sign(kp, pkg)
assert keys.verify(kp.ss58_address, pkg, sig), "verify failed"
assert not keys.verify(kp.ss58_address, pkg, sig[:-4] + "0000"), "bad sig accepted"
sid = models.submission_id(pkg)
store.add_submission(pkg, sig, time.time(), sid)
assert store.get(sid)["status"] == config.STATUS_RECEIVED
print("OK added", sid[:12], store.get(sid)["status"])

fp1 = dedup.fingerprint("cap", "0xABC", "Borrow", "drain")
fp2 = dedup.fingerprint("cap", "0xabc", "borrow", "drain")
assert fp1 == fp2, "fingerprint not case-insensitive"
print("OK fingerprint stable", fp1[:12])

accepted = [
    {"finding": "f1", "hotkey": "a", "bounty_usd": 3000, "period": 0},
    {"finding": "f2", "hotkey": "b", "bounty_usd": 150000, "period": 0},
    {"finding": "f3", "hotkey": "a", "bounty_usd": 750, "period": 2},
]
plan = settlement.settle({0: 30.0, 1: 30.0, 2: 30.0}, accepted, cap_alpha_per_usd=0.0, burn_after_periods=12)
pay = {p["finding"]: p["alpha"] for p in plan.payouts}
print("payouts", {k: round(v, 2) for k, v in pay.items()}, "by_hotkey",
      {k: round(v, 2) for k, v in plan.by_hotkey.items()}, "carry", round(plan.carry_end, 2))
# period 0: available 30, f1+f2 split by bounty -> f2 ~29.41, f1 ~0.59
assert abs(pay["f2"] - 30 * 150000 / 153000) < 1e-6
assert abs(pay["f1"] - 30 * 3000 / 153000) < 1e-6
# period 2: f3 alone takes all available (carry 30 from p1 + 30 accrued p2 = 60)
assert abs(pay["f3"] - 60.0) < 1e-6, pay["f3"]
assert abs(plan.carry_end) < 1e-6
print("OK settlement")

# cap test: cap 0.0001 alpha/usd -> f3 (750 usd) capped at 0.075, rest carries
plan2 = settlement.settle({0: 100.0}, [{"finding": "f3", "hotkey": "a", "bounty_usd": 750, "period": 0}],
                          cap_alpha_per_usd=0.0001, burn_after_periods=12)
assert abs(plan2.payouts[0]["alpha"] - 0.075) < 1e-9, plan2.payouts
assert abs(plan2.carry_end - 99.925) < 1e-6, plan2.carry_end
print("OK cap+carry")

# burn test: money unpaid for >=12 periods burns
plan3 = settlement.settle({0: 50.0}, [{"finding": "f", "hotkey": "a", "bounty_usd": 1, "period": 20}],
                          cap_alpha_per_usd=0.0, burn_after_periods=12)
assert any(b["accrued_period"] == 0 for b in plan3.burns), plan3.burns
print("OK burn", round(sum(b["alpha"] for b in plan3.burns), 2), "burned")
print("ALL CORE SMOKE PASS")
