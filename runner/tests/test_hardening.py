"""Hardening from the 2026-11-16 review of the state layer (run as pinc, no network, no forge):
  * a rule violation is decided even when the run also read state outside the snapshot, so such jobs
    never wait and their misses never feed a snapshot extension;
  * a request the read-only fork proxy refused rejects the job;
  * quantities are hex digits only ('0x-1' was accepted by Python's int());
  * zero-valued slots (for example added by extend) cannot add ERC-7201 roots, and roots and mapping
    bases are capped, so the fresh-account set cannot be inflated from a miss list;
  * (conformance review, F9) the Foundry pin matches the exact build: the version line and the commit line."""
import pathlib
import sqlite3
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import run_submission as rs  # noqa: E402
from state import fresh, mpt  # noqa: E402

fails = 0


def check(cond, msg):
    global fails
    print(("ok   " if cond else "FAIL ") + msg)
    fails += 0 if cond else 1


SPEC = {"spec_sha256": "x"}
MISS = [{"kind": "storage", "address": "0x" + "ab" * 20, "slot": "0x" + "00" * 31 + "01"}]

# 1) final verdict: refusals, rule violations, misses
ok_v = {"reproduced": True, "deterministic": True, "impact_type": "funds_loss", "error": None}
check(rs.finalize(ok_v, [], [], SPEC, "s") is ok_v, "nothing seen by the proxy: the engine's verdict stands")
for code in ("no_impact", "template", "harness_failed", "poc_reverted", "measurement_failed", "nondeterministic"):
    v = rs.finalize({"error": code}, MISS, [], SPEC, "s")
    check(v["error"] == "state_miss" and v["state_misses"] == MISS, f"a miss with outcome '{code}' waits for state")
v = rs.finalize({"error": "policy:store(address,bytes32,bytes32)", "detail": "d"}, MISS, [], SPEC, "s")
check(v["error"].startswith("policy:") and "state_misses" not in v, "a cheatcode rejection stands despite misses")
for code in ("impersonation", "capital", "time", "env", "screen", "poc_shape"):
    v = rs.finalize({"error": code}, MISS, [], SPEC, "s")
    check(v["error"] == code and not v.get("state_misses"), f"rule violation '{code}' is not held for state")
v = rs.finalize(ok_v, [], [{"method": "anvil_setStorageAt", "reason": "method", "count": 1}], SPEC, "s")
check(v["error"] == "fork" and not v.get("reproduced"), "a refused proxy request rejects the job")
v = rs.finalize(dict(ok_v), MISS, [{"method": "eth_sendRawTransaction", "count": 2}], SPEC, "s")
check(v["error"] == "fork" and not v.get("state_misses"), "a refused request wins over misses")
v = rs.finalize(ok_v, [], [{"method": "anvil_nodeInfo", "count": 3}], SPEC, "s")
check(v is ok_v, "forge's own anvil_nodeInfo probe is not held against the PoC")

# 2) quantities
for bad in ("0x-1", "0x 1", "0x_1", "0x1_0", "0x+5", "0x", "0xg", "0x" + "f" * 81):
    try:
        mpt.parse_quantity(bad)
        check(False, f"quantity {bad[:12]!r} refused")
    except mpt.ProofError:
        check(True, f"quantity {bad[:12]!r} refused")
check(mpt.parse_quantity("0x0a") == 10 and mpt.parse_quantity("0X1F") == 31, "normal quantities still parse")
try:
    mpt.norm_slot("0x-1")
    check(False, "slot '0x-1' refused with a ProofError (it raised OverflowError before)")
except mpt.ProofError:
    check(True, "slot '0x-1' refused with a ProofError (it raised OverflowError before)")


# 3) fresh-account discovery: zero slots add no roots; roots and bases are capped
class Snap:
    def __init__(self, rows, digest):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute('CREATE TABLE storage(address TEXT, slot TEXT, value TEXT)')
        self.conn.execute('CREATE TABLE accounts(address TEXT, "exists" INTEGER)')
        self.conn.executemany("INSERT INTO storage VALUES (?,?,?)", rows)
        self.digest = digest


def word(n):
    return "0x" + n.to_bytes(32, "big").hex()


roots_zero = [("0x" + "11" * 20, word((i + 1) << 200), word(0)) for i in range(500)]
fresh.mapping_bases(Snap(roots_zero, "zero-roots"))
st = fresh.mapping_bases.last_stats
check(st["candidates"] == len(fresh.SMALL_BASES), f"500 zero-valued namespace slots add no root candidates ({st['candidates']})")
roots_nonzero = [("0x" + "11" * 20, word((i + 1) << 200), word(1)) for i in range(500)]
fresh.mapping_bases(Snap(roots_nonzero, "many-roots"))
st = fresh.mapping_bases.last_stats
check(st["candidates"] <= len(fresh.SMALL_BASES) + 16 * fresh.MAX_ROOTS,
      f"namespace roots are capped at {fresh.MAX_ROOTS} ({st['candidates']} candidates)")
check(len(fresh.mapping_bases(Snap(roots_nonzero, "many-roots"))) <= fresh.MAX_BASES, "mapping bases are capped")

# 4) the Foundry pin is the exact build (`forge --version` of forge 1.9.0, commit 6056c58...)
GOOD = (f"forge Version: {rs.FORGE_VERSION}\nCommit SHA: {rs.FORGE_COMMIT}\n"
        "Build Timestamp: 2026-11-02T20:28:32.434285913Z (1793651312)\nBuild Profile: dist\n")
check(rs.forge_version_ok(GOOD), "the pinned forge build is accepted")
check(not rs.forge_version_ok(GOOD.replace("Version: 1.9.0\n", "Version: 1.9.0-nightly\n")), "1.9.0-nightly is refused")
check(not rs.forge_version_ok(GOOD.replace("Version: 1.9.0\n", "Version: 1.9.0-dev\n")), "1.9.0-dev is refused")
check(not rs.forge_version_ok(GOOD.replace(rs.FORGE_COMMIT, "0" * 40)), "another commit of 1.9.0 is refused")
check(not rs.forge_version_ok(GOOD.replace(rs.FORGE_COMMIT, rs.FORGE_COMMIT[:7])), "a short commit is refused")
check(not rs.forge_version_ok(f"forge Version: {rs.FORGE_VERSION}\n"), "a version without its commit line is refused")
check(not rs.forge_version_ok(f"forge {rs.FORGE_VERSION} ({rs.FORGE_COMMIT[:7]} 2026-11-02)"), "the old one-line format is refused")
check(rs.tv.FOUNDRY_VERSION == f"{rs.FORGE_VERSION}-{rs.FORGE_COMMIT[:7]}",
      "the build recorded in every verdict is the pinned version and commit")

print("ALL HARDENING TESTS PASS" if not fails else f"{fails} HARDENING TEST(S) FAILED")
sys.exit(1 if fails else 0)
