"""Unit tests of the verdict engine (runner/trace_verdict.py) and its inputs. Pure Python, no forge.

Replaces the tests of the old marker parser (runner/impact.py, removed: it trusted HYBLIS_IMPACT lines
the PoC printed itself). Covers:
  * golden fixtures: raw forge JSON of toy-chain variants (runner/tests/fixtures, made by
    runner/tests/test_e2e.py --update-fixtures) analysed again, verdicts unchanged;
  * tampered forge output (arena keys, 'ignored', node keys, values of another type, broken parent/child
    links, extra root calls, wrong attacker set, truncated or oversized JSON, failed harness, nondeterminism,
    standalone mismatches) fails closed;
  * gas: a PoC call (constructor included) that runs out of poc_gas, or gets less than it, is `limits`;
  * PoC-supplied cheatcode arguments are read as forge reads them, or rejected as policy:<sig>;
  * plain forge test: denied cheatcodes, other state-changing cheatcodes, other outcomes -> standalone_differs;
  * classification and severity on synthetic measurements (capital, thresholds, TVL share, caps,
    corroboration, unbacked mint, griefing, freeze);
  * impact-spec v2 compilation (unknown keys, draft specs, expressions, the cap and aave-v4 specs);
  * the hardened foundry.toml, the error vocabulary, the selector table.
The full end-to-end suite (forge, anvil, sandbox) is runner/tests/run.sh.
"""
import copy
import json
import lzma
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen_spec  # noqa: E402
import sanitize_foundry_toml as sft  # noqa: E402
import trace_verdict as tv  # noqa: E402

FX = HERE / "tests" / "fixtures"
SPEC = json.loads((FX / "spec.compiled.json").read_text())
TABLE = tv.load_selector_table()
n_ok = 0


def ok(cond, msg):
    global n_ok
    assert cond, msg
    n_ok += 1


def load(name, part):
    p = FX / f"{name}.{part}.json.xz"
    return json.loads(lzma.decompress(p.read_bytes())) if p.exists() else None


def meta(name):
    return json.loads((FX / f"{name}.meta.json").read_text())


def ctx(m, aset=None, spec=None):
    return tv.Ctx(spec or SPEC, m["rpc_url"], m["salt"], m["steps"], aset or [], TABLE)


def verdict_of(name, p1doc=None, p2doc=None, sdoc=None, spec=None):
    m = meta(name)
    try:
        p1 = tv.analyze_pass(p1doc or load(name, "pass1"), ctx(m, spec=spec))
        aset = [a for a in p1["attacker_order"] if a != p1["poc"]]
        p2 = tv.analyze_pass(p2doc or load(name, "pass2"), ctx(m, aset, spec=spec))
        return tv.decide(p1, p2, sdoc or load(name, "standalone"), spec or SPEC, tv.runner_info(SPEC))
    except tv.Reject as e:
        return tv.reject_verdict(e)


def expect_error(v, code, msg):
    ok(v.get("error") == code and not v.get("reproduced"), f"{msg}: got {v.get('error')} ({v.get('detail')})")


# ------------------------------------------------------------------ golden fixtures
for f in sorted(FX.glob("*.meta.json")):
    name = f.name[:-len(".meta.json")]
    want = meta(name)["expected"]
    v = verdict_of(name)
    got = {k: v.get(k) for k in want}
    ok(got == want, f"{name}: {got} != {want}")
print(f"ok golden fixtures: {len(list(FX.glob('*.meta.json')))} variants give their recorded verdicts")

# ------------------------------------------------------------------ tampered forge output fails closed
H = "v01_honest_theft"
p2 = load(H, "pass2")
SUITE = tv.SUITE


def result(doc):
    return doc[SUITE]["test_results"]["test_hyblis()"]


def arena(doc, kind="Execution"):
    return [a for k, a in result(doc)["traces"] if k == kind][0]


def mutate(fn):
    d = copy.deepcopy(p2)
    fn(d)
    return d


def p2_verdict(doc):
    m = meta(H)
    try:
        p1 = tv.analyze_pass(load(H, "pass1"), ctx(m))
        aset = [a for a in p1["attacker_order"] if a != p1["poc"]]
        pr = tv.analyze_pass(doc, ctx(m, aset))
        return tv.decide(p1, pr, load(H, "standalone"), SPEC, tv.runner_info(SPEC))
    except tv.Reject as e:
        return tv.reject_verdict(e)


ok(p2_verdict(p2)["reproduced"], "unmodified fixture validates")
expect_error(p2_verdict(mutate(lambda d: arena(d).__setitem__("ignored", {}))), "template",
             "an 'ignored' key (vm.pauseTracing) in the arena")
expect_error(p2_verdict(mutate(lambda d: arena(d).__setitem__("diagnostics", []))), "template", "unknown arena key")
expect_error(p2_verdict(mutate(lambda d: arena(d)["arena"][5].__setitem__("extra", 1))), "template", "unknown node key")
expect_error(p2_verdict(mutate(lambda d: arena(d)["arena"][5]["trace"].__setitem__("new_field", 1))), "template",
             "unknown trace key")
expect_error(p2_verdict(mutate(lambda d: d.__setitem__("test/x.t.sol:X", d[SUITE]))), "template", "a second suite")
expect_error(p2_verdict(mutate(lambda d: result(d)["traces"].append(["Execution", arena(d)]))), "template",
             "a second Execution arena")


# leading library-deployment arenas (a project with linked libraries, e.g. Cap): accepted only in their exact shape
LIB = json.loads((FX / "library_arena.json").read_text())["arena"]


def with_libs(d, n=3, fn=None):
    libs = [copy.deepcopy(LIB) for _ in range(n)]
    if fn:
        fn(libs[1])
    result(d)["traces"][:0] = [["Deployment", x] for x in libs]


ok(p2_verdict(mutate(lambda d: with_libs(d)))["reproduced"], "leading library deployments are accepted")
expect_error(p2_verdict(mutate(lambda d: with_libs(d, fn=lambda a: a["arena"][0]["trace"].__setitem__(
    "caller", "0x" + "11" * 20)))), "template", "a leading deployment from another sender")
expect_error(p2_verdict(mutate(lambda d: with_libs(d, fn=lambda a: a["arena"][1]["children"].append(1)))), "template",
             "a library deployment with a sub-call")
expect_error(p2_verdict(mutate(lambda d: with_libs(d, fn=lambda a: a["arena"][0]["trace"].__setitem__(
    "address", "0x" + "22" * 20)))), "template", "a leading deployment not through the CREATE2 factory")
expect_error(p2_verdict(mutate(lambda d: result(d)["traces"].append(["Deployment", copy.deepcopy(LIB)]))), "template",
             "a library deployment after the test contract")


def swap_root(d):
    k = arena(d)["arena"][0]["children"]
    k[4], k[5] = k[5], k[4]


expect_error(p2_verdict(mutate(swap_root)), "template", "root calls out of order")


def drop_root_child(d):
    arena(d)["arena"][0]["children"].pop()


expect_error(p2_verdict(mutate(drop_root_child)), "template", "a root call missing")
m = meta(H)
p1 = tv.analyze_pass(load(H, "pass1"), ctx(m))
aset = [a for a in p1["attacker_order"] if a != p1["poc"]]
try:
    tv.analyze_pass(p2, ctx(m, aset[:-1] if aset else ["0x" + "11" * 20]))
    ok(False, "a different attacker set must fail")
except tv.Reject as e:
    ok(e.code == "template", f"harness read a different attacker set -> {e.code}")
try:
    tv.analyze_pass(p2, tv.Ctx(SPEC, "/other.ipc", m["salt"], 0, aset, TABLE))
    ok(False, "another RPC must fail")
except tv.Reject as e:
    ok(e.code == "template", "harness read a different RPC -> template")
try:
    tv.analyze_pass(p2, tv.Ctx(SPEC, m["rpc_url"], "0x" + "22" * 32, 0, aset, TABLE))
    ok(False, "another salt must fail")
except tv.Reject as e:
    ok(e.code == "template", "harness read a different salt -> template")


def find_cheat(d, sig):
    for n in arena(d)["arena"]:
        if n["trace"]["address"].lower() == tv.CHEAT and n["trace"]["data"][2:10] == tv.sel(sig) and n["parent"] != 0:
            return n
    raise AssertionError(sig)


def prank_vault(d):
    n = find_cheat(d, "startPrank(address)")
    n["trace"]["data"] = "0x" + tv.sel("startPrank(address)") + "0" * 24 + SPEC["holders"][0]["address"][2:]


expect_error(p2_verdict(mutate(prank_vault)), "impersonation", "a PoC prank rewritten to the vault")


def label_to_store(d):
    n = find_cheat(d, "label(address,string)")
    n["trace"]["data"] = "0x" + tv.sel("store(address,bytes32,bytes32)") + "00" * 96


expect_error(p2_verdict(mutate(label_to_store)), "policy:store(address,bytes32,bytes32)",
             "a PoC cheatcode rewritten to store")


def unknown_cheat(d):
    find_cheat(d, "label(address,string)")["trace"]["data"] = "0xdeadbeef"


expect_error(p2_verdict(mutate(unknown_cheat)), "policy:unknown(0xdeadbeef)", "an unknown cheatcode selector")


def fail_harness(d):
    result(d)["status"] = "Failure"


expect_error(p2_verdict(mutate(fail_harness)), "harness_failed", "harness status Failure")


def poc_reverts(d):
    a = arena(d)["arena"]
    a[a[0]["children"][13]]["trace"]["success"] = False


expect_error(p2_verdict(mutate(poc_reverts)), "poc_reverted", "test_exploit() reverted")


# ---- values of another type, broken links: template, never a crash (a crash would be a retried runner_error)
def node(d, i):
    return arena(d)["arena"][i]


for what, fn in [
        ("a parent index given as a string", lambda d: node(d, 5).__setitem__("parent", "0")),
        ("a child index out of range", lambda d: node(d, 5)["children"].append(10 ** 6)),
        ("a child listed under two parents", lambda d: node(d, 0)["children"].append(node(d, 0)["children"][-1])),
        ("calldata that is not hex", lambda d: node(d, 5)["trace"].__setitem__("data", "0xzz")),
        ("gas_used as a string", lambda d: node(d, 5)["trace"].__setitem__("gas_used", "1")),
        ("success as a number", lambda d: node(d, 5)["trace"].__setitem__("success", 1)),
        ("an address of the wrong length", lambda d: node(d, 5)["trace"].__setitem__("caller", "0x1234")),
        ("a malformed log", lambda d: node(d, 5)["logs"].append({"address": "0x" + "11" * 20})),
        ("a malformed ordering entry", lambda d: node(d, 5)["ordering"].append({"Call": "0"})),
        ("a test status that is not a string", lambda d: result(d).__setitem__("status", 0))]:
    expect_error(p2_verdict(mutate(fn)), "template", what)


# ---- gas: every PoC call, the constructor included, is capped at poc_gas (F6-F8 of the 2026-11-16 review)
POC_GAS = SPEC["limits"]["poc_gas"]


def root_kid(d, k):
    a = arena(d)["arena"]
    return a[a[0]["children"][k]]


def test_oog(d):
    t = root_kid(d, 13)["trace"]
    t.update(success=False, status="MemoryOOG", gas_used=t["gas_limit"])


def sub_call_oog(d):
    t = root_kid(d, 13)["trace"]
    t.update(success=False, status="Revert", gas_used=t["gas_limit"] - t["gas_limit"] // 70)
    a = arena(d)["arena"]
    a[root_kid(d, 13)["children"][-1]]["trace"].update(success=False, status="OutOfGas")


def setup_starved(d):
    root_kid(d, 12)["trace"]["gas_limit"] = POC_GAS // 3


def ctor_over(d):
    a = arena(d)["arena"]
    a[root_kid(d, 10)["children"][0]]["trace"]["gas_used"] = POC_GAS + 1


def deploy_other_salt(d):
    t = root_kid(d, 10)["trace"]
    t["data"] = t["data"][:-2] + ("00" if t["data"][-2:] != "00" else "01")


expect_error(p2_verdict(mutate(test_oog)), "limits", "test_exploit() out of gas (MemoryOOG) is limits, not poc_reverted")
expect_error(p2_verdict(mutate(sub_call_oog)), "limits", "test_exploit() reverting after a sub-call took its last gas")
expect_error(p2_verdict(mutate(setup_starved)), "limits", "setUp() given less than poc_gas (total budget too small)")
expect_error(p2_verdict(mutate(ctor_over)), "limits", "a constructor that used more than poc_gas")
expect_error(p2_verdict(mutate(deploy_other_salt)), "template", "the PoC deployed with another salt")
gl = gen_spec.harness_gas_limit(SPEC)
ok(gl >= (2 + SPEC["limits"]["max_steps"]) * POC_GAS + gen_spec.HARNESS_RESERVE,
   f"the harness gas budget covers (2 + max_steps) x poc_gas plus the reserve ({gl})")


# ---- PoC-supplied cheatcode arguments: read as forge reads them, or rejected (never 'template')
def prank_dirty_victim(d):
    n = find_cheat(d, "startPrank(address)")
    n["trace"]["data"] = "0x" + tv.sel("startPrank(address)") + "01" + "00" * 11 + SPEC["holders"][3]["address"][2:]


expect_error(p2_verdict(mutate(prank_dirty_victim)), "impersonation",
             "startPrank with a dirty high byte is read as forge reads it (the victim) -> impersonation")
fake = {"trace": {"data": "0x" + tv.sel("envString(string)") + "%064x" % 32 + "%064x" % 3 + "414243" + "ff" * 29}}
try:
    tv.poc_args(fake, "envString(string)")
    ok(False, "a string with dirty padding must be rejected")
except tv.Reject as e:
    ok(e.code == "policy:envString(string)", f"non-canonical string argument -> {e.code}")


# ---- plain forge test: same entries with the same outcome, same state-changing cheatcodes, nothing denied
def sa_mutate(fn):
    d = copy.deepcopy(load(H, "standalone"))
    arenas = {k: a["arena"] for k, a in list(d.values())[0]["test_results"]["test_exploit()"]["traces"]}
    fn(arenas)
    return d


def sa_cheat(arenas, sig):
    return next(n for n in arenas["Execution"] if n["trace"]["address"].lower() == tv.CHEAT and
                n["trace"]["data"][2:10] == tv.sel(sig))


def sa_store(ar):
    sa_cheat(ar, "stopPrank()")["trace"]["data"] = "0x" + tv.sel("store(address,bytes32,bytes32)") + "00" * 96


def sa_prank_other(ar):
    sa_cheat(ar, "startPrank(address)")["trace"]["data"] = "0x" + tv.sel("startPrank(address)") + "0" * 24 + "11" * 20


def sa_entry_fails(ar):
    next(n for n in ar["Execution"] if n["trace"]["address"].lower() == SPEC["holders"][0]["address"])["trace"][
        "success"] = False


def sa_extra_warp(ar):
    sa_cheat(ar, "stopPrank()")["trace"]["data"] = "0x" + tv.sel("warp(uint256)") + "%064x" % (2 ** 40)


expect_error(verdict_of(H, sdoc=sa_mutate(sa_store)), "standalone_differs", "a denied cheatcode only in plain forge test")
expect_error(verdict_of(H, sdoc=sa_mutate(sa_prank_other)), "standalone_differs", "a prank of another account")
expect_error(verdict_of(H, sdoc=sa_mutate(sa_entry_fails)), "standalone_differs",
             "the same in-scope call, failing only in plain forge test")
expect_error(verdict_of(H, sdoc=sa_mutate(sa_extra_warp)), "standalone_differs",
             "a state-changing cheatcode (warp) the runner did not see")
ok(verdict_of(H)["reproduced"], "the unmodified standalone run still conforms")


def change_poc_data(d):
    a = arena(d)["arena"]
    n = a[a[a[0]["children"][13]]["children"][1]]
    n["trace"]["gas_used"] += 1


try:
    pr2 = tv.analyze_pass(mutate(change_poc_data), ctx(m, aset))
    vv = tv.decide(p1, pr2, load(H, "standalone"), SPEC, tv.runner_info(SPEC))
    expect_error(vv, "nondeterministic", "pass 2 PoC subtree differs from pass 1")
except tv.Reject as e:
    ok(False, f"unexpected {e}")

sd = load(H, "standalone")
sd_fail = copy.deepcopy(sd)
list(sd_fail.values())[0]["test_results"]["test_exploit()"]["status"] = "Failure"
expect_error(verdict_of(H, sdoc=sd_fail), "standalone_fails", "standalone test failed")
sd_diff = copy.deepcopy(sd)
for kind, ar in list(sd_diff.values())[0]["test_results"]["test_exploit()"]["traces"]:
    for n in ar["arena"]:
        if n["trace"]["address"].lower() == SPEC["holders"][0]["address"]:
            n["trace"]["data"] = n["trace"]["data"][:-2] + "ff"
expect_error(verdict_of(H, sdoc=sd_diff), "standalone_differs", "standalone makes a different in-scope call")

with tempfile.TemporaryDirectory() as t:
    raw = lzma.decompress((FX / f"{H}.pass2.json.xz").read_bytes())
    pth = pathlib.Path(t) / "p.json"
    pth.write_bytes(raw[: len(raw) // 2])
    try:
        tv.load_forge_json(pth, 1 << 30)
        ok(False, "truncated JSON must not parse")
    except tv.Reject as e:
        ok(e.code == "no_json", "truncated forge JSON -> no_json")
    pth.write_bytes(raw)
    try:
        tv.load_forge_json(pth, len(raw) - 1)
        ok(False, "oversized JSON must be rejected")
    except tv.Reject as e:
        ok(e.code == "limits", "forge JSON above the cap -> limits (never parsed)")
    pth.write_bytes(b"")
    try:
        tv.load_forge_json(pth, 1 << 30)
        ok(False, "empty output")
    except tv.Reject as e:
        ok(e.code == "no_json", "empty forge output (e.g. pauseTracing) -> no_json")
    pth.write_bytes(b'{"a": NaN}')
    try:
        tv.load_forge_json(pth, 1 << 30)
        ok(False, "NaN must not parse")
    except tv.Reject as e:
        ok(e.code == "no_json", "JSON constants refused")
print(f"ok tampered or failed forge output fails closed")

# a spec that lists a benign entry point / known issue changes the verdict
sp = copy.deepcopy(SPEC)
sp["benign_entry_points"] = [{"contract": SPEC["holders"][0]["address"], "selector": tv.sel("withdrawFor(address,uint256)"),
                              "function": "withdrawFor(address,uint256)"}]
expect_error(verdict_of(H, spec=sp), "out_of_scope", "impact only through a benign entry point")
sp = copy.deepcopy(SPEC)
sp["known_issues"] = [{"id": "K-1", "contract": SPEC["holders"][0]["address"], "function": "withdrawFor(address,uint256)",
                       "impact": "funds_loss"}]
expect_error(verdict_of(H, spec=sp), "known_issue", "known issue")
sp = copy.deepcopy(SPEC)
sp["in_scope_impacts"] = ["insolvency"]
expect_error(verdict_of(H, spec=sp), "out_of_scope", "impact type not in scope")
sp = copy.deepcopy(SPEC)
sp["severity"]["funds_loss"] = {"default": "medium", "high_if_usd": "40"}
sp["severity"]["max"] = "critical"
ok(verdict_of(H, spec=sp)["measured_severity"] == "high", "high_if_usd raises the severity")
sp["severity"]["max"] = "medium"
ok(verdict_of(H, spec=sp)["measured_severity"] == "medium", "severity.max caps it")
sp = copy.deepcopy(SPEC)
sp["thresholds"]["min_usd"] = "1000"
expect_error(verdict_of(H, spec=sp), "no_impact", "below the task's threshold")
print("ok program rules, thresholds and severity caps")

# ------------------------------------------------------------------ classification on synthetic measurements
TOK, ETH = SPEC["tokens"][0]["address"], SPEC["tokens"][1]["address"]
VAULT = SPEC["holders"][0]["address"]
ATT = "0x" + "aa" * 20


def synth(post_vault, base_vault=80 * 10**18, att_post=0, views_post=None, views_base=None):
    holders = [h["address"] for h in SPEC["holders"]] + [ATT]
    B = {(t, h): 0 for t in (TOK, ETH) for h in holders}
    Pst = dict(B)
    B[(TOK, VAULT)] = base_vault
    Pst[(TOK, VAULT)] = post_vault
    Pst[(TOK, ATT)] = att_post
    vb = {v["id"]: 0 for v in SPEC["views"]}
    vb.update({"solvent": True, "frozen": False, "totalDeposits": 80 * 10**18, "dep_alice": 50 * 10**18,
               "dep_bob": 30 * 10**18})
    vp = dict(vb)
    vp.update(views_post or {})
    vb.update(views_base or {})
    ac = {(c["id"], ATT): 0 for c in SPEC["attacker_claims"]}
    return {"base": B, "post": Pst, "views_base": vb, "views_post": vp, "aclaims_base": dict(ac), "aclaims_post": dict(ac)}


class N:   # a probe node stand-in
    def __init__(self, ok_):
        self.d = {"trace": {"success": ok_}}

    def __getitem__(self, k):
        return self.d[k]


def classify(meas, capital=None, flips=None, spec=SPEC):
    pp = [N(not flips)] * len(spec["probes"])
    bp = [N(True)] * len(spec["probes"])
    return tv._classify(meas, {ATT}, capital or {}, {}, pp, bp, spec)


r = classify(synth(30 * 10**18, att_post=50 * 10**18, views_post={"dep_alice": 0, "totalDeposits": 30 * 10**18}))
ok(r["impact_type"] == "funds_loss" and r["evidence"]["amount_usd"] == 50.0, f"theft: {r['impact_type']}")
r = classify(synth(30 * 10**18, att_post=50 * 10**18, views_post={"dep_alice": 0, "totalDeposits": 30 * 10**18}),
             capital={TOK: 50 * 10**18})
ok(r["impact_type"] != "funds_loss", "capital equal to the gain cancels it")
r = classify(synth(0, views_post={"solvent": False}))
ok(r["impact_type"] == "insolvency" and r["evidence"]["amount_usd"] == 80.0, f"insolvency shortfall: {r['evidence']}")
r = classify(synth(80 * 10**18, views_post={"solvent": False}))
ok(r["impact_type"] == "accounting_error" and r["measured_severity"] == "low",
   "an invariant break without any balance effect or probe flip is capped at accounting_error/low")
r = classify(synth(80 * 10**18), flips=True)
ok(r["impact_type"] == "funds_freeze" and r["evidence"]["amount_usd"] == 50.0, "a probe flip is a freeze")
r = classify(synth(30 * 10**18, views_post={"dep_alice": 0, "totalDeposits": 30 * 10**18}), flips=True)
ok(r["impact_type"] == "griefing" and r["evidence"]["probe_flips"][0]["at_risk_usd"] == 0.0,
   f"a claim that was taken (not frozen) is no freeze: theft without profit is griefing ({r['impact_type']})")
m3 = synth(0, views_post={"solvent": False, "totalDeposits": 20080 * 10**18})
m3["aclaims_post"][("vault_deposit", ATT)] = 20000 * 10**18
r = classify(m3, capital={TOK: 20000 * 10**18})
ok(r["impact_type"] == "insolvency" and r["evidence"]["amount_usd"] == 80.0,
   f"the attacker's own deposit is not part of the insolvency shortfall ({r['evidence']['amount_usd']})")
r = classify(synth(0))
ok(r["impact_type"] == "insolvency" or r["impact_type"] == "griefing", "a loss with no gain is griefing or insolvency")
sp = copy.deepcopy(SPEC)
sp["invariants"] = []
r = classify(synth(0), spec=sp)
ok(r["impact_type"] == "griefing" and r["measured_severity"] == "low", "loss without gain and no invariant: griefing")
r = classify(synth(80 * 10**18, views_base={"solvent": None}, views_post={"solvent": None}))
ok(r["impact_type"] == "" and "backing" in r["spec_health"]["invariants_not_holding"],
   "a failed view read is unknown, never broken")
sp = copy.deepcopy(SPEC)
sp["tokens"][0]["issued_by_protocol"] = True
sp["tokens"][0]["supply_view"] = "totalDeposits"
r = classify(synth(80 * 10**18, att_post=500 * 10**18, views_post={"totalDeposits": 580 * 10**18}), spec=sp)
ok(r["impact_type"] == "unauthorized_mint" and r["evidence"]["unbacked_mint"]["amount_usd"] == 500.0,
   f"unbacked mint: {r['impact_type']}")
sp["severity"]["funds_loss"] = {"default": "medium", "high_if_tvl_share": "0.0001"}
sp["severity"]["max"] = "high"
r = classify(synth(30 * 10**18, att_post=50 * 10**18, views_post={"dep_alice": 0}), spec=sp)
ok(r["measured_severity"] == "high", "high_if_tvl_share")
print("ok classification and severity on synthetic measurements")

# ------------------------------------------------------------------ impact-spec v2
toy = json.loads((HERE / "tests" / "toy" / "impact-spec.json").read_text().replace("${FORK_HASH}", "0x" + "ab" * 32)
                 .replace("${FORK_TS}", "1794853664"))
c = gen_spec.compile_spec(toy)
ok(c["spec_sha256"] and "0x7fa9385be102ac3eac297483dd6233d62b3e1496" not in c["protected"], "toy spec compiles")
sol = gen_spec.render_solidity(c)
ok("library HyblisSpec" in sol and "FORK_BLOCK = 40" in sol, "HyblisSpec.sol rendered")


def spec_err(mut, msg):
    s = copy.deepcopy(toy)
    mut(s)
    try:
        gen_spec.compile_spec(s)
        ok(False, f"{msg}: accepted")
    except gen_spec.SpecError:
        ok(True, msg)


spec_err(lambda s: s.__setitem__("surprise", 1), "unknown top-level key")
spec_err(lambda s: s["tokens"][0].__setitem__("cap", 1), "unknown token key")
spec_err(lambda s: s.__setitem__("status", "draft"), "a draft spec is refused without --allow-draft")
spec_err(lambda s: s["invariants"][0].__setitem__("holds", "__import__('os')"), "a call in an invariant expression")
spec_err(lambda s: s["invariants"][0].__setitem__("holds", "unknown_name > 0"), "an unknown name in an invariant")
spec_err(lambda s: s["views"][0].__setitem__("target", "@nobody"), "an unknown reference")
spec_err(lambda s: s["limits"].__setitem__("poc_gas", 10**10), "poc_gas above the runner maximum")
spec_err(lambda s: s["limits"].pop("horizon_basis"), "time limits without the protocol horizon they come from")
spec_err(lambda s: s["probes"][0].__setitem__("args", []), "wrong number of probe arguments")
spec_err(lambda s: s["attacker_claims"][0].__setitem__("sig", "deposits(uint256)"), "claim view not taking an address")


def with_claim(**kw):
    def mut(s):
        s["attacker_claims"][0].update(kw)
    return mut


spec_err(with_claim(sig="pos(uint256,address)", args=[7, "@account", 1]), "claim args of the wrong length")
spec_err(with_claim(sig="pos(uint256,address)", args=[7, "0x" + "11" * 20]), 'claim args without "@account"')
spec_err(with_claim(sig="pos(address,address)", args=["@account", "@account"]), 'two "@account" arguments')
spec_err(with_claim(sig="pos(uint256,address)", args=["@account", "0x" + "11" * 20]), '"@account" on a uint argument')
spec_err(with_claim(sig="pos(string,address)", args=["x", "@account"]), "a dynamic claim argument")
spec_err(lambda s: s["attacker_claims"].append(dict(s["attacker_claims"][0], id="dup")), "two claims, same call")
s2 = copy.deepcopy(toy)
s2["attacker_claims"][0].update(sig="getUserSuppliedAssets(uint256,address)", args=[7, "@account"])
s2["attacker_claims"].append(dict(s2["attacker_claims"][0], id="mid", sig="f(uint256,address,bool)",
                                  args=[3, "@account", True]))
c2 = gen_spec.compile_spec(s2)
cl, mid = c2["attacker_claims"][0], c2["attacker_claims"][-1]
who = "0x" + "ab" * 20
want = gen_spec.sel("getUserSuppliedAssets(uint256,address)") + f"{7:064x}" + "0" * 24 + "ab" * 20
ok(cl["prefix"] == want[:72] and cl["suffix"] == "" and tv._claim_calldata(cl, who).hex() == want,
   "a claim with a reserve id puts the account word after it")
ok(mid["suffix"] == f"{1:064x}" and tv._claim_calldata(mid, who).hex() ==
   gen_spec.sel("f(uint256,address,bool)") + f"{3:064x}" + "0" * 24 + "ab" * 20 + f"{1:064x}",
   "a claim with arguments after the account keeps them as the suffix")
one = c["attacker_claims"][0]
ok(one["prefix"] == one["selector"] and one["suffix"] == "" and
   tv._claim_calldata(one, who) == bytes.fromhex(one["selector"] + "0" * 24 + "ab" * 20),
   "a one-address claim reads exactly as before")
ok(tv._claim_calldata({"selector": one["selector"]}, who) == tv._claim_calldata(one, who),
   "a claim compiled without a template reads the same")
sol2 = gen_spec.render_solidity(c2)
ok(f'pre[0] = hex"{cl["prefix"]}"; post[0] = hex"";' in sol2, "HyblisSpec.sol carries the claim templates")
for task in ("cap", "aave-v4"):
    sj = json.loads((HERE.parent / "tasks" / task / "impact-spec.json").read_text())
    try:
        gen_spec.compile_spec(sj)
        ok(sj.get("status") == "verified", f"{task}: only a verified spec compiles without --allow-draft")
    except gen_spec.SpecError:
        ok(sj.get("status") != "verified", f"{task}: unverified spec refused for runs")
    if task == "cap":
        cc = gen_spec.compile_spec(sj, allow_draft=True)
        pin = json.loads((HERE.parent / "tasks" / task / "manifest.json").read_text())["chain"]
        ok(cc["severity"]["max"] == "medium" and cc["fork"]["block"] == int(pin["fork_block"]) and
           cc["fork"]["block_hash"] == pin["fork_block_hash"].lower(),
           "cap spec v2 compiles, capped at medium, and its fork section matches the manifest's pin")
print("ok impact-spec v2 compilation and validation")

# ------------------------------------------------------------------ hardened foundry.toml, vocabulary, selectors
cfg = {"profile": {"default": {"src": "contracts", "solc_version": "0.8.28", "eth_rpc_url": "http://x", "sender": "0x1",
                               "ffi": True, "fs_permissions": [{"access": "read", "path": "."}], "libraries": ["x"],
                               "remappings": ["a/=b/"], "optimizer": True},
                   "evil": {"ffi": True}}, "rpc_endpoints": {"x": "y"}}
t = sft.runner_toml(cfg, "/opt/solc")
for bad in ("eth_rpc_url", "sender", "libraries", "rpc_endpoints", "[profile.evil]", "solc_version"):
    ok(bad not in t, f"runner toml drops {bad}")
ok(f"gas_limit = {gl}" in sft.runner_toml(cfg, "/opt/solc", gl), "runner toml carries the task's harness gas budget")
ok('test = "test"' in sft.runner_toml({"profile": {"default": {"test": "tests"}}}, "/opt/solc") and
   'test = "tests"' not in sft.runner_toml({"profile": {"default": {"test": "tests"}}}, "/opt/solc"),
   "runner toml compiles test/ (the PoC's directory) whatever test directory the project names")
big = {"profile": {"default": {"optimizer_runs": 444444444444, "additional_compiler_profiles": [
    {"name": "hub", "optimizer_runs": 22300}, {"name": "tests", "optimizer_runs": 444444444444}],
    "compilation_restrictions": [{"paths": "tests/**", "optimizer_runs": 444444444444}]}}}
tb = sft.runner_toml(big, "/opt/solc")
ok("444444444444" not in tb and tb.count("optimizer_runs = 4294967295") == 3 and
   "optimizer_runs = 22300" in tb, "runner toml clamps optimizer_runs to Foundry's u32 maximum everywhere")
for good in ('ffi = false', 'fs_permissions = []', 'offline = true', 'dynamic_test_linking = false', 'isolate = true',
             'solc = "/opt/solc"', 'remappings = ["a/=b/"]', 'lint_on_build = false', 'always_use_create_2_factory = false'):
    ok(good in t, f"runner toml sets {good}")
for code in ("state_miss", "runner_error", "screen", "poc_shape", "compile", "no_json", "limits", "template",
             "harness_failed", "policy", "impersonation", "fork", "env", "time", "reentry", "capital", "helper",
             "poc_reverted", "measurement_failed", "nondeterministic", "standalone_fails", "standalone_differs",
             "no_impact", "out_of_scope", "known_issue"):
    ok(tv.explain(code), f"plain-words explanation for {code}")
ok(tv.explain("policy:store(address,bytes32,bytes32)") == tv.ERRORS["policy"], "policy:<sig> explains as policy")
ok(len(json.loads((HERE / "vm_selectors.json").read_text())["selectors"]) == 543, "543 forge-std 1.15.0 selectors")
ok(not (HERE / "impact.py").exists(), "the marker parser (impact.py) is gone")
src = (HERE / "trace_verdict.py").read_text()
ok("HYBLIS_IMPACT" not in src and "decoded_logs\"]" not in src, "the engine never reads markers or decoded logs")
import hashlib  # noqa: E402
pins = dict(line.split()[::-1] for line in (HERE / "sol" / "SHA256SUMS").read_text().splitlines() if line.strip())
for name, h in pins.items():
    ok(hashlib.sha256((HERE / "sol" / name).read_bytes()).hexdigest() == h, f"runner/sol/{name} matches SHA256SUMS")
for task in ("cap", "aave-v4"):
    ok((HERE.parent / "tasks" / task / "poc" / "HyblisBase.sol").read_bytes() == (HERE / "sol" / "HyblisBase.sol").read_bytes(),
       f"tasks/{task}/poc/HyblisBase.sol is the runner's copy")
print(f"ok hardened toml, error vocabulary, selector table")
print(f"impact tests PASS ({n_ok} checks)")
