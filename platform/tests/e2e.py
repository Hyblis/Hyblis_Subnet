"""End-to-end gateway test (in-process aiohttp TestServer; no external ports,
no forge). Exercises submit -> receipt -> screen -> claim -> verdict -> publish,
both signature schemes (CLI raw, browser wallet-v1), CORS, input hardening, an
operator accept, and the privacy of every public surface. Then the intake
hardening: resends answered with the stored receipt, the policy screen as a
separate process (reasons, time limit, no stall on hostile 256 KiB PoCs), the
per-client limit behind the proxy, same-PoC dedup, failures after a report is
stored, whole-file exports under concurrent readers, and the read-only site.
Also: the submitter's own result behind the receipt token (runner reasons in the
runner's fixed words, "waiting" without detail), the runner vocabulary the
platform reads from runner/trace_verdict.py, and the `hyblis check` bundle
(exact member list, sanitised manifest and spec, nothing private, released and
ready programs only).
"""
import asyncio
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import pathlib
import io
import re
import tarfile

# isolate data dirs BEFORE importing the package
tmp = pathlib.Path(tempfile.mkdtemp())
os.environ["HYBLIS_DATA_DIR"] = str(tmp / "data")
os.environ["HYBLIS_PUBLIC_DIR"] = str(tmp / "public")
os.environ["HYBLIS_DISPATCH_TOKEN"] = "test-token-123"
os.environ["HYBLIS_CORS_ORIGINS"] = "http://site.test"
for var in ("HYBLIS_PUBLIC_API_BASE", "HYBLIS_TRUSTED_PROXIES", "HYBLIS_SERVER_SEED", "HYBLIS_CLIENT_IP_HEADER"):
    os.environ.pop(var, None)
# The flows below file reports to the testnet reference program (cap) with intake open; launch_mode()
# at the end checks mainnet launch mode (intake closed until mainnet launch) with the real releases.json.
os.environ["HYBLIS_NETWORK"] = "testnet"
os.environ["HYBLIS_INTAKE_OPEN"] = "1"

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))  # platform/
from aiohttp.test_utils import TestServer, TestClient
from bittensor_wallet import Keypair
from hyblis_platform import canonical, config, gateway, keys, models, pipeline, publicsite, publish, runner_vocab, store

ROOT = pathlib.Path(config.ROOT)
sys.path.insert(0, str(ROOT / "runner"))
import gen_spec  # noqa: E402  (runner code: imported here only to compare with what the platform ships)
import policy_check  # noqa: E402
import trace_verdict  # noqa: E402
POC = (ROOT / "tasks" / "cap" / "poc" / "HyblisPoC.t.sol").read_text()
TOK = {"X-Hyblis-Token": "test-token-123"}
# Words that must never reach a public surface (the bundle check also uses them, see bundle_leaks).
# programs still queued for release (the private queue, when this checkout has it): their names are leaks too
QUEUED = [r["task_id"] for r in publish._releases().get("tasks", []) if isinstance(r, dict) and r.get("status") == "queued"]
QUEUED_ONE = QUEUED[0] if QUEUED else "queued-demo"
# platform names are private words too (listed in the private queue folder, when this checkout has it)
_NOTES = config.TASKS_DIR / "private-queue" / "program-notes.private.json"
PRIVATE_WORDS = tuple(json.loads(_NOTES.read_text()).get("leak_words", [])) if _NOTES.exists() else ()
LEAKS = ("15000", "private-ref", "internal_note", "queued-demo",
         "testnet dry run", "deposit", "max_rewards", "short description of the issue", "vault accounting flaw") + tuple(QUEUED) + PRIVATE_WORDS
VAULT = "0xcCcc62962d17b8914c62D74FfB843d73B2a3cccC"     # cap program contracts
LENDER = "0x15622c3dbbc5614E6DFa9446603c1779647f01FC"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"      # used by the template, not a program contract
_n = [0]


def make_pkg(kp, poc=None, **over):
    _n[0] += 1
    poc = POC if poc is None else poc
    pkg = {
        "v": 1, "task_id": "cap", "hotkey": kp.ss58_address, "nonce": f"{_n[0]:032x}", "ts": int(time.time()),
        "header": {"title": "Vault accounting flaw", "contract": VAULT,
                   "function": "redeem", "severity": "medium", "description": "short description of the issue"},
        "poc": poc, "poc_sha256": canonical.sha256_hex(poc.encode()),
    }
    pkg.update(over)
    return pkg


def signed(kp, pkg):
    return {"package": pkg, "sig": keys.sign(kp, pkg)}


def own_poc(tag):
    """The template with a comment, so the report is a different PoC from the others."""
    return POC + f"\n// {tag}\n"


async def post(client, body, **kw):
    r = await client.post("/api/submit", json=body, **kw)
    try:
        return r.status, await r.json()
    except Exception:
        return r.status, {"reason": r.reason}


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def ss58(public_key: bytes, prefix: int) -> str:
    """SS58 address of a key for any one-byte network prefix (0 Polkadot, 2 Kusama, 42 generic)."""
    data = bytes([prefix]) + public_key
    data += hashlib.blake2b(b"SS58PRE" + data, digest_size=64).digest()[:2]
    n, out = int.from_bytes(data, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


async def with_health_checks(client, coro):
    """Run coro while asking /api/health every 10 ms. Returns (result, slowest answer in s, answers)."""
    task = asyncio.ensure_future(coro)
    slowest, n = 0.0, 0
    while not task.done():
        t0 = time.perf_counter()
        r = await client.get("/api/health")
        assert r.status == 200
        slowest, n = max(slowest, time.perf_counter() - t0), n + 1
        await asyncio.sleep(0.01)
    return await task, slowest, n


class Lines(logging.Handler):
    """Collects the gateway's log lines."""
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def child_script(name, code):
    p = tmp / name
    p.write_text(code)
    return p


async def main():
    app = gateway.make_app()
    client = TestClient(TestServer(app))
    await client.start_server()
    try:
        assert (await (await client.get("/api/health")).json())["ok"]
        kp = Keypair.create_from_uri("//MinerOne")

        # ---------------- raw scheme (command-line miner) ----------------
        pkg = make_pkg(kp)
        sig = keys.sign(kp, pkg)
        st, err = await post(client, {"package": pkg, "sig": sig[:-4] + "0000"})
        assert st == 401 and "signature" in err["error"], (st, err)   # bad signature, JSON error body
        st, body = await post(client, {"package": pkg, "sig": sig})
        assert st == 201 and body["status"] == config.STATUS_SCREENING and "policy" not in body, (st, body)
        sid, token = body["submission_id"], body["receipt_token"]
        assert sid == models.submission_id(pkg)
        st, again = await post(client, {"package": pkg, "sig": sig})
        assert st == 200 and again["replayed"] is True and again["receipt_token"] == token, (st, again)  # resend
        print("raw scheme: accepted, bad signature refused, a resend gets the same receipt")

        # receipt only by the secret token, never by the public hash
        rc = await (await client.get(f"/api/receipt/{token}")).json()
        assert rc["payload"]["submission_id"] == sid
        assert (await client.get(f"/api/receipt/{sid}")).status == 404

        # ---------------- wallet-v1 scheme (browser extension) ----------------
        wk = Keypair.create_from_uri("//BrowserWallet")
        p2 = make_pkg(wk)
        sid2 = models.submission_id(p2)
        wsig = keys.sign_wallet(wk, sid2, wrap=True)            # what polkadot-js signRaw returns
        st, b2 = await post(client, {"package": p2, "sig": wsig, "sig_scheme": "wallet-v1", "submission_id": sid2})
        assert st == 201 and b2["submission_id"] == sid2, (st, b2)
        p3 = make_pkg(wk)
        st, _ = await post(client, {"package": p3, "sig": keys.sign_wallet(wk, models.submission_id(p3), wrap=False),
                                    "sig_scheme": "wallet-v1"})
        assert st == 201, st                                   # unwrapped message is accepted too
        # a wallet signature for ANOTHER package must not verify
        p4 = make_pkg(wk)
        st, _ = await post(client, {"package": p4, "sig": wsig, "sig_scheme": "wallet-v1"})
        assert st == 401, st
        # scheme confusion: each signature is only valid under its own scheme
        p5 = make_pkg(wk)
        st, _ = await post(client, {"package": p5, "sig": keys.sign(wk, p5), "sig_scheme": "wallet-v1"})
        assert st == 401, st
        st, _ = await post(client, {"package": p5, "sig": keys.sign_wallet(wk, models.submission_id(p5))})
        assert st == 401, st
        # signed by a different key than the package's hotkey
        other = Keypair.create_from_uri("//SomeoneElse")
        st, _ = await post(client, {"package": p5, "sig": keys.sign_wallet(other, models.submission_id(p5)),
                                    "sig_scheme": "wallet-v1"})
        assert st == 401, st
        st, r5 = await post(client, {"package": p5, "sig": keys.sign_wallet(wk, models.submission_id(p5)),
                                     "sig_scheme": "nope"})
        assert st == 400, st
        st, r5 = await post(client, {"package": p5, "sig": keys.sign_wallet(wk, models.submission_id(p5)),
                                     "sig_scheme": "wallet-v1", "submission_id": "00" * 32})
        assert st == 400 and "canonical" in r5["error"], (st, r5)
        print("wallet-v1 scheme: wrapped and unwrapped accepted; wrong package, wrong key, scheme confusion refused")

        # ---------------- input hardening ----------------
        bad = make_pkg(kp); bad["extra"] = 1
        assert (await post(client, {"package": bad, "sig": keys.sign(kp, bad)}))[0] == 400      # unknown key
        bad = make_pkg(kp); bad["header"]["severity"] = "critical"
        assert (await post(client, {"package": bad, "sig": keys.sign(kp, bad)}))[0] == 400      # outside the program scope
        bad = make_pkg(kp); bad["task_id"] = "aave-v4"
        assert (await post(client, {"package": bad, "sig": keys.sign(kp, bad)}))[0] == 400      # not open for intake
        bad = make_pkg(kp); bad["task_id"] = QUEUED_ONE
        st, rb = await post(client, {"package": bad, "sig": "0x00"})
        assert st == 400, st                                                                     # queued program
        bad = make_pkg(kp); bad["v"] = True
        assert (await post(client, {"package": bad, "sig": "0x00"}))[0] == 400
        # a lone surrogate must be a clean 400, never a 500
        raw = json.dumps({"package": make_pkg(kp), "sig": "0x00"}).replace("short description", "bad \\ud800 text")
        r = await client.post("/api/submit", data=raw, headers={"Content-Type": "application/json"})
        assert r.status == 400, r.status
        r = await client.post("/api/submit", data="[1,2]", headers={"Content-Type": "application/json"})
        assert r.status == 400, r.status
        print("input hardening: unknown keys, out-of-scope severity, closed programs, bad unicode refused")

        # ---------------- CORS ----------------
        r = await client.options("/api/submit", headers={"Origin": "http://site.test", "Access-Control-Request-Method": "POST"})
        assert r.status == 204 and r.headers.get("Access-Control-Allow-Origin") == "http://site.test", (r.status, dict(r.headers))
        r = await client.options("/api/submit", headers={"Origin": "http://evil.test", "Access-Control-Request-Method": "POST"})
        assert r.status == 403 and "Access-Control-Allow-Origin" not in r.headers
        r = await client.get("/api/leaderboard", headers={"Origin": "http://site.test"})
        assert r.headers.get("Access-Control-Allow-Origin") == "http://site.test"
        r = await client.get("/api/leaderboard", headers={"Origin": "http://evil.test"})
        assert "Access-Control-Allow-Origin" not in r.headers
        r = await client.post("/api/submit", json={"package": {}, "sig": "x"}, headers={"Origin": "http://site.test"})
        assert r.status == 400 and r.headers.get("Access-Control-Allow-Origin") == "http://site.test"   # errors readable by the site
        r = await client.post("/internal/claim", json={}, headers={"Origin": "http://site.test"})
        assert r.status == 401 and "Access-Control-Allow-Origin" not in r.headers
        print("CORS: site origin allowed on /api, other origins and /internal refused")

        # ---------------- public status ----------------
        ps = await (await client.get(f"/api/submission/{sid}")).json()
        assert ps["status"] == "screening" and "cap" not in str(ps), ps
        assert set(ps) == {"hash", "status", "severity", "t"}, ps                    # no program bucket
        assert (await client.get(f"/api/submission/{sid[:16]}")).status == 200        # prefix lookup
        assert (await client.get(f"/api/submission/{sid[:8]}")).status == 404         # too short to be unambiguous
        assert (await client.get("/api/submission/%25")).status == 404

        # ---------------- runner: claim + verdict ----------------
        claim = await (await client.post("/internal/claim", headers=TOK, json={})).json()
        assert claim["submission_id"] == sid, claim
        verdict = {"reproduced": True, "deterministic": True, "impact_type": "funds_loss",
                   "measured_severity": "high", "changed_function": "redeem",
                   "changed_contract": "0xcccc62962d17b8914c62d74ffb843d73b2a3cccc",
                   "evidence": {"profit": "100000", "invariant_broken": True}}
        vr = await (await client.post("/internal/verdict", headers=TOK, json={"submission_id": sid, "verdict": verdict})).json()
        assert vr["status"] == config.STATUS_VALIDATED, vr
        assert store.get(sid)["severity_final"] == "medium"       # min(claim, measured)
        assert (await client.post("/internal/claim", headers={"X-Hyblis-Token": "nope"}, json={})).status == 401

        lb = await (await client.get("/api/leaderboard")).json()
        row = [x for x in lb if x["hotkey"] == kp.ss58_address]
        assert row and row[0]["validated"] == 1 and row[0]["score"] > 0, lb

        # dedup: the wallet submission of the same bug arrives later -> duplicate
        c2 = await (await client.post("/internal/claim", headers=TOK, json={})).json()
        assert c2["submission_id"] == sid2, c2
        vr2 = await (await client.post("/internal/verdict", headers=TOK, json={"submission_id": sid2, "verdict": verdict})).json()
        assert vr2["status"] == config.STATUS_DUPLICATE, vr2
        print("pipeline: validated, then a later identical finding became a duplicate")

        # ---------------- the submitter's own result, behind the receipt token only ----------------
        r = await client.get(f"/api/receipt/{token}")
        rc = await r.json()
        assert r.status == 200 and r.headers.get("Cache-Control") == "no-store", (r.status, dict(r.headers))
        assert rc["result"] == {"status": "validated", "error": None, "explanation": "", "detail": "", "policy": [],
                                "impact_type": "funds_loss", "measured_severity": "high",
                                "changed_function": "redeem"}, rc
        rc2 = (await (await client.get(f"/api/receipt/{b2['receipt_token']}")).json())["result"]
        assert rc2["status"] == "duplicate" and rc2["error"] == "duplicate", rc2
        assert rc2["explanation"] == pipeline.PLATFORM_REASONS["duplicate"] and sid not in json.dumps(rc2)  # never which report

        async def runner_says(kp_, tag, verdict_):
            """Submit, let the runner post `verdict_`; (status, the submitter's result, the public status)."""
            st_, b_ = await post(client, signed(kp_, make_pkg(kp_, poc=own_poc(tag))))
            assert st_ == 201 and b_["status"] == "screening", (st_, b_)
            before = (await (await client.get(f"/api/receipt/{b_['receipt_token']}")).json())["result"]
            assert before is None, before                                   # nothing while in progress
            store.set_status(b_["submission_id"], config.STATUS_REPRODUCING)   # as if the runner claimed it
            vr_ = await (await client.post("/internal/verdict", headers=TOK,
                                           json={"submission_id": b_["submission_id"], "verdict": verdict_})).json()
            res_ = (await (await client.get(f"/api/receipt/{b_['receipt_token']}")).json())["result"]
            pub_ = await (await client.get(f"/api/submission/{b_['submission_id']}")).json()
            assert set(pub_) == {"hash", "status", "severity", "t"}, pub_     # the public answer is unchanged
            return vr_["status"], res_, pub_
        rr = Keypair.create_from_uri("//ResultReader")
        results = []
        st_, res, pub = await runner_says(rr, "cheat", {
            "reproduced": False, "deterministic": True, "error": "policy:store(address,bytes32,bytes32)",
            "detail": "cheatcode not allowed", "evidence": {"amount_usd": 77777.0}, "state_misses": [],
            "runner": {"version": "trace-1.0", "files": {"HyblisSpec.sol": "ab" * 32}}})
        assert st_ == "rejected" and pub["status"] == "rejected", (st_, pub)
        assert res == {"status": "rejected", "error": "policy:store(address,bytes32,bytes32)",
                       "explanation": runner_vocab.ERRORS["policy"], "detail": "cheatcode not allowed", "policy": []}, res
        results.append(res)
        st_, res, _ = await runner_says(rr, "runner screen", {
            "reproduced": False, "deterministic": True, "error": "screen", "detail": "static screen",
            "policy": [{"reason": "forbidden cheatcode vm.etch", "line": 31}, {"reason": "x", "line": "2"}]})
        assert res["error"] == "screen" and res["explanation"] == runner_vocab.ERRORS["screen"], res
        assert res["policy"] == [{"reason": "forbidden cheatcode vm.etch", "line": 31}, {"reason": "x", "line": None}], res
        results.append(res)
        # only the runner's own vocabulary is shown, and its note as one short plain line
        st_, res, _ = await runner_says(rr, "odd code", {"reproduced": False, "error": "<img src=x onerror=1>",
                                                          "detail": "<b>not a runner text</b>"})
        assert res["error"] == "not_reproduced" and res["detail"] == "", res
        assert res["explanation"] == pipeline.PLATFORM_REASONS["not_reproduced"], res
        st_, res, _ = await runner_says(rr, "long note", {"reproduced": False, "error": "no_impact",
                                                           "detail": "a\nb\x00c" + "z" * 1000})
        assert res["detail"].startswith("a b c") and len(res["detail"]) == pipeline.MAX_DETAIL, res
        assert res["explanation"] == runner_vocab.ERRORS["no_impact"]
        results.append(res)
        # waiting for the runner: public "reproducing"; the submitter sees only that it waits
        st_, res, pub = await runner_says(rr, "waiting", {
            "reproduced": False, "error": "state_miss", "detail": "1 fork reads outside the snapshot",
            "state_misses": [{"kind": "storage", "address": VAULT.lower(), "slot": "0x" + "00" * 32}]})
        assert st_ == "waiting" and res == {"status": "waiting"} and pub["status"] == "reproducing", (st_, res, pub)
        assert (await client.get("/api/receipt/not-a-token")).status == 404
        assert '"error"' not in (config.PUBLIC_DIR / "ledger.json").read_text()
        for x in results:
            assert "77777" not in json.dumps(x) and "files" not in x and "evidence" not in x, x
        print("receipt result: validated impact, duplicate without the other report, runner reasons in the runner's "
              "words (code, explanation, note, lines), unknown codes hidden, waiting without detail; no-store")

        # ---------------- operator transitions ----------------
        for fn, args in ((pipeline.platform_accepted, (sid, 15000.0, 0)), (pipeline.mark_filed, (sid2, "x"))):
            try:
                fn(*args); assert False, "illegal transition was allowed"
            except pipeline.IllegalTransition:
                pass
        pipeline.mark_filed(sid, "PRIVATE-REF-1")
        rc = (await (await client.get(f"/api/receipt/{token}")).json())["result"]
        assert rc["status"] == "under_review" and rc["impact_type"] == "funds_loss", rc       # never the platform
        pipeline.platform_accepted(sid, bounty_usd=15000.0, period=0)
        publish.export_all()
        rc = await (await client.get(f"/api/receipt/{token}")).json()
        assert rc["result"]["status"] == "accepted" and "15000" not in json.dumps(rc) and "private" not in json.dumps(rc).lower(), rc

        # ---------------- privacy of every public surface ----------------
        ledger = await (await client.get("/api/ledger")).json()
        lb2 = await (await client.get("/api/leaderboard")).json()
        tasks = await (await client.get("/api/tasks")).json()
        summary = await (await client.get("/api/summary")).json()
        prog = await (await client.get("/api/program/cap")).json()
        assert [x for x in lb2 if x["hotkey"] == kp.ss58_address][0]["accepted"] == 1
        public_files = "".join(p.read_text() for p in config.PUBLIC_DIR.rglob("*.json"))
        blob = (json.dumps([ledger, lb2, tasks, summary, prog]) + public_files).lower()
        for secret in LEAKS:
            assert secret not in blob, f"leak: {secret!r} found in a public surface"
        for bundle in (config.PUBLIC_DIR / "check").glob("*.tar.gz"):     # whatever real bundles exist now
            assert not bundle_leaks(bundle.read_bytes()), (bundle.name, bundle_leaks(bundle.read_bytes()))
        assert {t["task_id"] for t in tasks} == {"cap", "aave-v4"}, tasks                 # the queue stays private
        # a next release date exists only while programs wait in the queue (the private queue may be absent)
        assert (summary["releases"]["next_release_on"] or not QUEUED) and summary["settlement"]["next_at"] > time.time()
        assert summary["releases"]["intake_open"] is True and summary["releases"]["intake_message"] is None
        # a hotkey is attached only to credited findings
        by_hash = {r["hash"]: r for r in ledger}
        assert by_hash[sid].get("hotkey") == kp.ss58_address and by_hash[sid]["status"] == "accepted"
        assert "hotkey" not in by_hash[sid2] and by_hash[sid2]["status"] == "duplicate"
        # no program on any ledger row: a per-program id would tell which program has open findings
        for r in ledger:
            assert "program" not in r and set(r) <= {"id", "hash", "t", "status", "severity", "hotkey"}, r
        assert '"program"' not in (config.PUBLIC_DIR / "ledger.json").read_text()
        # the program page has what a researcher needs and nothing about the platform
        cap_manifest = json.loads((config.TASKS_DIR / "cap" / "manifest.json").read_text())
        assert prog["fork_block"] == cap_manifest["chain"]["fork_block"] and prog["assets"] and prog["poc_template"] and prog["poc_rules"], prog.keys()
        assert prog["poc_base"] == (ROOT / "runner" / "sol" / "HyblisBase.sol").read_text()
        assert prog["allowed_cheatcodes"] == [list(x) for x in runner_vocab.ALLOWED_CHEATCODES]
        assert prog["open_for_intake"] is True and not prog["verification_pending"]
        aave = await (await client.get("/api/program/aave-v4")).json()
        assert aave["verification_pending"] and not aave["open_for_intake"] and aave["assets"] == []
        assert aave["poc_template"] is None and aave["poc_base"]          # a scaffold template is not published
        assert (await client.get(f"/api/program/{QUEUED_ONE}")).status == 404
        assert (await client.get("/api/program/..%2Fx")).status == 404
        print("privacy: no amounts, platform, queue, program or report text on any public surface")

        # ============ intake hardening ============
        gateway._BUCKET.clear()

        # ---- only JSON bodies (a cross-site text/plain POST has no CORS preflight) ----
        env = signed(kp, make_pkg(kp, poc=own_poc("content type")))
        r = await client.post("/api/submit", data=json.dumps(env),
                              headers={"Content-Type": "text/plain", "Origin": "http://site.test"})
        assert r.status == 415 and (await r.json())["error"] and r.headers.get("Access-Control-Allow-Origin") == "http://site.test"
        r = await client.post("/api/submit", data=json.dumps(env).encode(), skip_auto_headers=("Content-Type",))
        assert r.status == 415, r.status
        assert not gateway._BUCKET, gateway._BUCKET                        # refused before any quota is charged
        r = await client.post("/api/submit", data=json.dumps(env), headers={"Content-Type": "application/json; charset=utf-8"})
        assert r.status == 201, r.status

        async def chunked_body():     # over 1 MiB, sent without a Content-Length
            yield b'{"package": "' + b"a" * (1024 * 1024) + b'", "sig": "0x00"}'
        r = await client.post("/api/submit", data=chunked_body(), headers={"Content-Type": "application/json"})
        assert r.status == 413 and "error" in await r.json(), r.status
        print("content type: text/plain and no type get 415; application/json with a charset is accepted; "
              "a chunked body over 1 MiB gets 413")

        # ---- ts: integers in a bounded range, never a 500 ----
        for ts in (10 ** 400, 2 ** 53, 1_700_000_000, 1.8e9, True, "1800000000"):
            r = await client.post("/api/submit", data=json.dumps({"package": make_pkg(kp, ts=ts), "sig": "0x00"}),
                                  headers={"Content-Type": "application/json", "Origin": "http://site.test"})
            body = await r.json()
            assert r.status == 400 and body["error"] == "package: ts must be a unix timestamp", (ts, r.status, body)
            assert r.headers.get("Access-Control-Allow-Origin") == "http://site.test"
        p = make_pkg(kp, ts=int(time.time()) + 2 * 86400)
        st, body = await post(client, signed(kp, p))
        assert st == 400 and body["error"] == "ts too far from server time", (st, body)
        print("ts: a 401-digit integer, 2**53, floats, booleans and strings are a clean 400")

        # ---- hotkey: SS58 format 42 of a real key only ----
        alice = Keypair.create_from_uri("//Alice")
        assert ss58(alice.public_key, 42) == alice.ss58_address
        dot, ksm, zero = ss58(alice.public_key, 0), ss58(alice.public_key, 2), ss58(bytes(32), 42)
        assert dot.startswith("1") and keys.is_valid_ss58(dot) and keys.is_valid_ss58(zero)   # they do decode
        for hotkey, sig_of in ((dot, lambda p: keys.sign(alice, p)), (ksm, lambda p: keys.sign(alice, p)),
                               (zero, lambda p: "0x" + "00" * 63 + "80")):
            p = make_pkg(alice, hotkey=hotkey)
            st, body = await post(client, {"package": p, "sig": sig_of(p)})
            assert st == 400 and body["error"] == "package: hotkey must be a Bittensor address (SS58 format 42)", (hotkey, st, body)
        assert keys.is_hotkey(alice.ss58_address)
        for nope in (dot, ksm, zero, None, 42, "", "5" * 48, alice.ss58_address[:-1] + "x", "0x" + "00" * 32):
            assert not keys.is_hotkey(nope), nope
        print("hotkey: Polkadot and Kusama spellings of a real key and the zero key get 400")

        # ---- contract: one the program lists ----
        p = make_pkg(kp, poc=own_poc("out of scope"))
        p["header"]["contract"] = USDC
        st, body = await post(client, signed(kp, p))
        assert st == 400 and body["error"] == "contract is not in scope for this program", (st, body)
        p = make_pkg(kp, poc=own_poc("lower-case contract"))
        p["header"]["contract"] = LENDER.lower()
        assert (await post(client, signed(kp, p)))[0] == 201
        real_program = publish.program_public
        publish.program_public = lambda tid: dict(real_program(tid), assets=[])
        try:
            st, body = await post(client, signed(kp, make_pkg(kp, poc=own_poc("no assets"))))
        finally:
            publish.program_public = real_program
        assert st == 400 and body["error"] == "this program has no contracts in scope yet, so it cannot take reports", (st, body)
        print("contract: an address the program does not list gets 400; a program listing none takes no report")

        # ---- the same signed package again: its stored receipt, nothing stored or charged ----
        gateway._BUCKET.clear()
        rk = Keypair.create_from_uri("//Resender")
        pr = make_pkg(rk, poc=own_poc("resend"))
        env = signed(rk, pr)
        st1, b1 = await post(client, env)
        assert st1 == 201, (st1, b1)
        hk_key, rows_before = f"hk:{rk.ss58_address}", len(store.all_submissions())
        st2, b2 = await post(client, env)
        assert st2 == 200 and b2 == dict(b1, status="screening", replayed=True), (b1, b2)
        st3, b3 = await post(client, {"package": pr, "sig": keys.sign_wallet(rk, b1["submission_id"]), "sig_scheme": "wallet-v1"})
        assert st3 == 200 and b3["receipt_token"] == b1["receipt_token"]  # signed again, same report
        assert (await post(client, {"package": pr, "sig": env["sig"][:-4] + "0000"}))[0] == 401
        assert len(gateway._BUCKET[hk_key]) == 1 and len(store.all_submissions()) == rows_before
        # two copies at the same moment: one stores it, the other gets the same receipt
        real_add, integrity = store.add_submission, []

        def slow_add(*a, **k):        # both copies pass the "already stored?" check before either inserts
            time.sleep(0.3)
            try:
                return real_add(*a, **k)
            except sqlite3.IntegrityError:
                integrity.append(1)
                raise
        store.add_submission = slow_add
        try:
            env = signed(rk, make_pkg(rk, poc=own_poc("race")))
            (s1, r1), (s2, r2) = await asyncio.gather(post(client, env), post(client, env))
        finally:
            store.add_submission = real_add
        assert sorted([s1, s2]) == [200, 201] and integrity == [1], (s1, r1, s2, r2, integrity)
        assert r1["receipt_token"] == r2["receipt_token"] and r1["submission_id"] == r2["submission_id"]
        assert len(gateway._BUCKET[hk_key]) == 2                       # charged once for the raced report
        assert len(store.all_submissions()) == rows_before + 1
        print("resend: 200 with the original receipt token (sequential, re-signed and racing); no new row, no quota")

        # ---- the intake screen's reasons go back to the submitter ----
        rb = Keypair.create_from_uri("//RuleBreaker")
        bad_poc = POC.replace("vm.startPrank(attacker);",
                              "vm.startPrank(attacker);\n        vm.store(LENDER, bytes32(0), bytes32(uint256(1)));")
        line = next(i for i, s in enumerate(bad_poc.splitlines(), 1) if "vm.store(LENDER" in s)
        env = signed(rb, make_pkg(rb, poc=bad_poc))
        st, body = await post(client, env)
        assert st == 201 and body["status"] == "rejected", (st, body)
        assert body["policy"] == [{"reason": "forbidden cheatcode vm.store", "line": line}], body
        res = (await (await client.get(f"/api/receipt/{body['receipt_token']}")).json())["result"]
        assert res == {"status": "rejected", "error": "screen", "explanation": runner_vocab.ERRORS["screen"],
                       "detail": "", "policy": [{"reason": "forbidden cheatcode vm.store", "line": line}]}, res
        st, again = await post(client, env)
        assert st == 200 and again["replayed"] and again["policy"] == body["policy"], again
        # the line is the line as written, also after a multi-line comment
        st, body = await post(client, signed(rb, make_pkg(rb, poc="/*\n  header\n*/\n" + bad_poc)))
        assert st == 201 and body["policy"] == [{"reason": "forbidden cheatcode vm.store", "line": line + 3}], body
        assert '"policy"' not in (config.PUBLIC_DIR / "ledger.json").read_text()
        print("policy: a rejected report's 201 lists the reasons and lines; a resend lists them too")

        # ---- hostile 256 KiB PoCs: the screen runs in its own process, the gateway keeps answering ----
        adv = Keypair.create_from_uri("//Adversary")
        for label, poc in (("one long word", "a" * 262144), ("unclosed /* repeated", "/*a" * (262144 // 3)),
                           ("vm.prank( without ;", "vm.prank(" * (262144 // 9))):
            assert len(poc.encode()) <= models.MAX_POC_BYTES
            t0 = time.perf_counter()
            (st, body), slowest, n = await with_health_checks(client, post(client, signed(adv, make_pkg(adv, poc=poc))))
            took = time.perf_counter() - t0
            assert st == 201 and body["status"] == "rejected" and body["policy"], (label, st, body)
            assert slowest < 0.1 and n >= 1, (label, slowest, n)
            assert took < 5, (label, took)
            print(f"hostile PoC ({label}): 201 rejected in {took * 1000:.0f} ms; {n} health checks, slowest {slowest * 1000:.0f} ms")

        # ---- the screen's time limit, its failure modes, and at most two at once ----
        real_check, real_limit = pipeline.POLICY_CHECK, pipeline.SCREEN_TIMEOUT_S
        screen_log = Lines()
        pipeline.log.addHandler(screen_log)
        try:
            pipeline.POLICY_CHECK, pipeline.SCREEN_TIMEOUT_S = child_script("hang.py", "import time\ntime.sleep(60)\n"), 1
            t0 = time.perf_counter()
            (st, body), slowest, n = await with_health_checks(
                client, post(client, signed(adv, make_pkg(adv, poc=own_poc("slow screen")))))
            took = time.perf_counter() - t0
            assert st == 201 and body["status"] == "rejected", (st, body)
            assert body["policy"] == [{"reason": "policy check timed out", "line": None}], body
            assert 1 <= took < 5 and slowest < 0.1 and n >= 10, (took, slowest, n)
            print(f"screen time limit: REJECT 'policy check timed out' after {took:.1f} s; "
                  f"{n} health checks meanwhile, slowest {slowest * 1000:.0f} ms")
            for code in ("raise SystemExit(5)\n", "print('not json')\n",
                         "import json\nprint(json.dumps({'verdict': 'PASS', 'findings': []}))\nraise SystemExit(2)\n"):
                pipeline.POLICY_CHECK = child_script("broken.py", code)
                assert pipeline._policy_check("cap", "x") == ("REJECT", [{"level": "REJECT", "reason": "policy check failed", "line": None}])
            # one log line each, so a broken checker cannot reject every report unnoticed
            assert [s.split(" (")[0] for s in screen_log.lines] == ["policy check timed out"] + ["policy check failed"] * 3, screen_log.lines
            assert "exit 5: no error output" in screen_log.lines[1] and "exit 2:" in screen_log.lines[3], screen_log.lines
            assert all("\n" not in s for s in screen_log.lines)
            log_file = tmp / "screens.log"
            pipeline.POLICY_CHECK, pipeline.SCREEN_TIMEOUT_S = child_script("slow.py", (
                "import json, time\n"
                f"open({str(log_file)!r}, 'a').write(f'{{time.time()}} 1\\n')\n"
                "time.sleep(0.4)\n"
                f"open({str(log_file)!r}, 'a').write(f'{{time.time()}} -1\\n')\n"
                "print(json.dumps({'verdict': 'PASS', 'findings': []}))\n")), 10
            results = []
            threads = [threading.Thread(target=lambda: results.append(pipeline._policy_check("cap", "x"))) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert results == [("PASS", [])] * 5, results
            running = most = 0
            for _, step in sorted(tuple(map(float, s.split())) for s in log_file.read_text().split("\n") if s):
                running += int(step)
                most = max(most, running)
            assert most == 2, most
            print("screen failures: a crash, garbage output or a wrong exit code is REJECT 'policy check failed'; "
                  "five screens at once run two at a time")
        finally:
            pipeline.POLICY_CHECK, pipeline.SCREEN_TIMEOUT_S = real_check, real_limit
            pipeline.log.removeHandler(screen_log)

        # ---- per-client limit behind the proxy: X-Real-IP, only from a trusted peer ----
        gateway._BUCKET.clear()
        junk = Keypair.create_from_uri("//Junk")
        for _ in range(60):          # junk signatures from one client fill only that client's bucket
            assert (await post(client, {"package": make_pkg(junk), "sig": "0x00"}, headers={"X-Real-IP": "203.0.113.7"}))[0] == 401
        assert (await post(client, {"package": make_pkg(junk), "sig": "0x00"}, headers={"X-Real-IP": "203.0.113.7"}))[0] == 429
        honest = Keypair.create_from_uri("//HonestResearcher")
        st, body = await post(client, signed(honest, make_pkg(honest, poc=own_poc("honest"))), headers={"X-Real-IP": "198.51.100.9"})
        assert st == 201, (st, body)
        assert len(gateway._BUCKET["ip:203.0.113.7"]) == 60 and len(gateway._BUCKET["ip:198.51.100.9"]) == 1
        for addr in ("2001:db8:1:2::1", "2001:db8:1:2:ffff::9"):      # one IPv6 /64 is one client
            await post(client, {"package": make_pkg(junk), "sig": "0x00"}, headers={"X-Real-IP": addr})
        assert len(gateway._BUCKET["ip:2001:db8:1:2::/64"]) == 2
        await post(client, {"package": make_pkg(junk), "sig": "0x00"}, headers={"X-Real-IP": "not-an-address"})
        await post(client, {"package": make_pkg(junk), "sig": "0x00"})
        assert len(gateway._BUCKET["ip:127.0.0.1"]) == 2               # no usable header: the peer itself
        os.environ["HYBLIS_TRUSTED_PROXIES"] = "192.0.2.1"              # this peer is not a trusted proxy
        try:
            await post(client, {"package": make_pkg(junk), "sig": "0x00"}, headers={"X-Real-IP": "203.0.113.99"})
        finally:
            del os.environ["HYBLIS_TRUSTED_PROXIES"]
        assert "ip:203.0.113.99" not in gateway._BUCKET and len(gateway._BUCKET["ip:127.0.0.1"]) == 3
        # ---- behind the Cloudflare Tunnel: the client is named in CF-Connecting-IP (HYBLIS_CLIENT_IP_HEADER) ----
        gateway._BUCKET.clear()
        os.environ["HYBLIS_CLIENT_IP_HEADER"] = "CF-Connecting-IP"
        try:
            for headers in ({"CF-Connecting-IP": "203.0.113.50"}, {"cf-connecting-ip": "2001:db8:7:8::1"},
                            {"CF-Connecting-IP": "2001:db8:7:8:abcd::2"},
                            {"X-Real-IP": "203.0.113.51"},                          # the other header no longer counts
                            {"CF-Connecting-IP": "203.0.113.52, 198.51.100.1"},       # not one address: the peer
                            {"CF-Connecting-IP": "::ffff:203.0.113.54"}):             # IPv4-mapped is the IPv4 client
                assert (await post(client, {"package": make_pkg(junk), "sig": "0x00"}, headers=headers))[0] == 401
            assert {k: len(v) for k, v in gateway._BUCKET.items()} == {
                "ip:203.0.113.50": 1, "ip:2001:db8:7:8::/64": 2, "ip:127.0.0.1": 2, "ip:203.0.113.54": 1}, gateway._BUCKET
            os.environ["HYBLIS_TRUSTED_PROXIES"] = "192.0.2.1"              # not from the tunnel: header ignored
            try:
                await post(client, {"package": make_pkg(junk), "sig": "0x00"}, headers={"CF-Connecting-IP": "203.0.113.53"})
            finally:
                del os.environ["HYBLIS_TRUSTED_PROXIES"]
            assert "ip:203.0.113.53" not in gateway._BUCKET and len(gateway._BUCKET["ip:127.0.0.1"]) == 3
            os.environ["HYBLIS_CLIENT_IP_HEADER"] = "CF Connecting IP"       # not a header name: the services refuse to start
            try:
                config.check()
                raise AssertionError("a malformed HYBLIS_CLIENT_IP_HEADER was accepted")
            except ValueError:
                pass
        finally:
            os.environ.pop("HYBLIS_CLIENT_IP_HEADER", None)
        print("rate limit: 60 junk posts block only their own client; X-Real-IP is used only from a trusted proxy; IPv6 per /64; "
              "behind the tunnel CF-Connecting-IP (HYBLIS_CLIENT_IP_HEADER) replaces it, also only from a trusted peer")

        # ---- same PoC = same bug, whatever contract the header names ----
        gateway._BUCKET.clear()
        same = {"reproduced": True, "deterministic": True, "impact_type": "funds_loss",
                "measured_severity": "medium", "changed_function": "withdraw",
                "changed_contract": VAULT.lower()}

        async def report(kp_, poc, contract):
            p = make_pkg(kp_, poc=poc)
            p["header"]["contract"] = contract
            st, body = await post(client, signed(kp_, p))
            assert st == 201 and body["status"] == "screening", (st, body)
            store.set_status(body["submission_id"], config.STATUS_REPRODUCING)   # as if the runner claimed it
            return body["submission_id"]
        first, copier = Keypair.create_from_uri("//FirstFinder"), Keypair.create_from_uri("//Copier")
        poc = own_poc("same poc")
        sa = await report(first, poc, VAULT)
        sb = await report(copier, poc, LENDER)                         # another in-scope contract, same PoC
        assert pipeline.on_verdict(sa, same) == "validated"
        assert pipeline.on_verdict(sb, same) == "duplicate" and store.get(sb)["dup_of"] == sa
        # verdicts out of order: the earlier report still wins, the later one is demoted
        other_bug = dict(same, changed_function="mint")
        poc = own_poc("same poc, out of order")
        sc = await report(first, poc, VAULT)
        sd = await report(copier, poc, LENDER)
        assert pipeline.on_verdict(sd, other_bug) == "validated"
        assert pipeline.on_verdict(sc, other_bug) == "validated"
        assert store.get(sd)["status"] == "duplicate" and store.get(sd)["dup_of"] == sc
        # a filed finding is locked: a later copy of its PoC is a duplicate
        pipeline.mark_filed(sa, "PRIVATE-REF-2")
        se = await report(copier, own_poc("same poc"), LENDER)
        assert pipeline.on_verdict(se, same) == "duplicate" and store.get(se)["dup_of"] == sa
        assert not [r for r in publish.leaderboard() if r["hotkey"] == copier.ss58_address and r["score"] > 0]
        print("dedup: the same PoC under another contract is a duplicate, also out of order and once filed")
        pipeline.platform_rejected(sc, "invalid")
        res = pipeline.researcher_result(store.get(sc))
        assert res["error"] == "not_accepted" and res["explanation"] == pipeline.PLATFORM_REASONS["not_accepted"], res
        assert res["impact_type"] == "funds_loss" and res["changed_function"] == "mint", res

        # ---- failures after a report is stored: logged, and the submitter still gets the receipt ----
        lines = Lines()
        gateway.log.addHandler(lines)
        fk = Keypair.create_from_uri("//AfterStore")
        try:
            os.environ["HYBLIS_SERVER_SEED"] = "0xzz"                   # malformed signing key
            st, body = await post(client, signed(fk, make_pkg(fk, poc=own_poc("bad seed"))))
            assert st == 201 and body["server_sig"] is None and body["receipt_token"], (st, body)
            assert (await client.get(f"/api/receipt/{body['receipt_token']}")).status == 200
            os.environ["HYBLIS_SERVER_SEED"] = "0x" + "11" * 32
            server = keys.keypair_from_seed(os.environ["HYBLIS_SERVER_SEED"])
            st, body = await post(client, signed(fk, make_pkg(fk, poc=own_poc("good seed"))))
            rc = await (await client.get(f"/api/receipt/{body['receipt_token']}")).json()
            assert st == 201 and keys.verify(server.ss58_address, rc["payload"], body["server_sig"]), (st, body)
            del os.environ["HYBLIS_SERVER_SEED"]

            def boom(*a, **k):
                raise RuntimeError("disk on fire\nsecond line")
            real_screen, pipeline.screen = pipeline.screen, boom
            try:
                st, body = await post(client, signed(fk, make_pkg(fk, poc=own_poc("screen fails"))))
            finally:
                pipeline.screen = real_screen
            assert st == 201 and body["status"] == "screening" and body["receipt_token"], (st, body)  # queued for the runner
            assert store.get(body["submission_id"])["status"] == "screening"
            real_export, publish.export_all = publish.export_all, boom
            try:
                st, body = await post(client, signed(fk, make_pkg(fk, poc=own_poc("export fails"))))
            finally:
                publish.export_all = real_export
            assert st == 201 and body["status"] == "screening" and body["receipt_token"], (st, body)
            # any other unexpected error on /api: one log line and a JSON 500 the site can read
            real_find, store.find_by_prefix = store.find_by_prefix, boom
            try:
                r = await client.get("/api/submission/" + "ab" * 8, headers={"Origin": "http://site.test"})
            finally:
                store.find_by_prefix = real_find
            assert r.status == 500 and (await r.json()) == {"error": "internal error"}
            assert r.headers.get("Access-Control-Allow-Origin") == "http://site.test"
        finally:
            os.environ.pop("HYBLIS_SERVER_SEED", None)
            gateway.log.removeHandler(lines)
        assert len(lines.lines) == 4 and all("\n" not in s for s in lines.lines), lines.lines
        assert [s.split(":")[0] for s in lines.lines] == ["receipt signing", "screen", "export", "GET /api/submission/abababababababab"], lines.lines
        assert "RuntimeError: disk on fire second line" in lines.lines[1]
        print("after-store failures: bad signing key, screen error and export error still answer 201 with the receipt; "
              "an unexpected error is one log line and a JSON 500")

        # ---- /internal token: compared as bytes ----
        r = await client.post("/internal/claim", headers={"X-Hyblis-Token": "töken"}, json={})
        assert r.status == 401, r.status

        class Req:
            headers = {"X-Hyblis-Token": "tök\udcff"}
        assert gateway._auth_internal(Req()) is False
        print("internal token: a non-ASCII token is a 401, not a 500")

        # ---- exports replace files whole: concurrent readers never see a partial file ----
        with store._conn() as c:     # volume: 1500 more ledger rows in one transaction
            c.executemany(
                """INSERT INTO submissions (submission_id, task_id, hotkey, received_at, status, severity_claim,
                   title, contract, function, description, poc_sha256, package_json, envelope_sig, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [(hashlib.sha256(b"bulk%d" % i).hexdigest(), "cap", kp.ss58_address, time.time(), "rejected",
                  "low", "t", VAULT.lower(), "f", "d", "00" * 32, "{}", "0x", time.time()) for i in range(1500)])
        ledger_file = config.PUBLIC_DIR / "ledger.json"
        stop, bad_reads, good_reads, ran = threading.Event(), [], [0], [0]

        def reader():
            while not stop.is_set():
                try:
                    json.loads(ledger_file.read_text())
                    good_reads[0] += 1
                except Exception as e:
                    bad_reads.append(repr(e)[:80])
        stop_file = tmp / "stop-reader"
        proc_reader = subprocess.Popen([sys.executable, "-I", "-c", (
            "import json, os, sys\n"
            "good = bad = 0\n"
            "print('reading', flush=True)\n"
            f"while not os.path.exists({str(stop_file)!r}):\n"
            "    try:\n"
            f"        json.loads(open({str(ledger_file)!r}).read()); good += 1\n"
            "    except Exception:\n"
            "        bad += 1\n"
            "print(json.dumps([good, bad]))\n")], stdout=subprocess.PIPE, text=True)
        real_files, failures = publish._export_files, []

        def counted(*a, **k):
            ran[0] += 1
            return real_files(*a, **k)

        def exporter(i):
            try:
                for j in range(4):
                    h = hashlib.sha256(b"fresh%d-%d" % (i, j)).hexdigest()
                    with store._conn() as c:
                        c.execute("""INSERT INTO submissions (submission_id, task_id, hotkey, received_at, status,
                                     severity_claim, title, contract, function, description, poc_sha256, package_json,
                                     envelope_sig, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                  (h, "cap", kp.ss58_address, time.time(), "rejected", "low", "t", VAULT.lower(), "f",
                                   "d", "00" * 32, "{}", "0x", time.time()))
                    publish.export_all()
                    # the export this call returned from includes the row it added just before
                    if h not in ledger_file.read_text():
                        failures.append(f"export call {i}.{j} returned before its change was published")
            except Exception as e:
                failures.append(repr(e))
        publish._export_files = counted
        try:
            assert proc_reader.stdout.readline().strip() == "reading"
            rt = threading.Thread(target=reader)
            rt.start()
            ex = [threading.Thread(target=exporter, args=(i,)) for i in range(3)]
            for t in ex:
                t.start()
            for t in ex:
                t.join()
            stop.set()
            rt.join()
        finally:
            publish._export_files = real_files
            stop_file.write_text("")
        proc_good, proc_bad = json.loads(proc_reader.communicate(timeout=60)[0])
        assert not failures, failures
        assert not bad_reads and good_reads[0] > 0, (bad_reads[:3], good_reads)
        assert proc_bad == 0 and proc_good > 0, (proc_good, proc_bad)
        assert 1 <= ran[0] <= 12, ran
        assert not [p for p in config.PUBLIC_DIR.rglob("*") if p.name.endswith(".tmp")]
        print(f"exports: 12 concurrent export calls ran {ran[0]} exports; readers made "
              f"{good_reads[0]} (thread) and {proc_good} (process) reads of a {ledger_file.stat().st_size // 1024} KiB "
              f"ledger, none partial")

        # ---- the public site: reads exported files only, never the private DB ----
        def no_db(*a, **k):
            raise AssertionError("the public site opened the private DB")
        real_conn, real_public = store._conn, config.PUBLIC_DIR
        store._conn, config.PUBLIC_DIR = no_db, tmp / "not-exported-yet"
        site = TestClient(TestServer(publicsite.make_app()))
        await site.start_server()
        try:
            for name in ("ledger", "summary", "tasks", "leaderboard", "scoring-policy"):
                r = await site.get(f"/data/{name}.json")
                assert r.status == 503 and (await r.json()) == {"error": "not published yet"}, (name, r.status)
            assert (await site.get("/data/programs/cap.json")).status == 404
            assert (await site.get("/healthz")).status == 200 and (await site.get("/")).status == 200
            config.PUBLIC_DIR = real_public                            # what the gateway exported
            r = await site.get("/data/ledger.json")
            rows = await r.json()
            assert r.status == 200 and rows and not [x for x in rows if "program" in x]
            assert (await site.get("/data/programs/cap.json")).status == 200
            # caches keep fonts and vendor files for a week, but never a 404
            r = await site.get("/assets/fonts/inter-var-latin.woff2")
            assert r.status == 200 and r.headers["Cache-Control"] == "public, max-age=604800"
            r = await site.get("/assets/vendor/not-there-yet.min.js")
            assert r.status == 404 and r.headers["Cache-Control"] == "no-store"
            r = await site.get("/assets/fonts/missing.woff2")
            assert r.status == 404 and r.headers["Cache-Control"] == "no-store"
            # where the browser finds the gateway: the local port only for a browser on this machine
            local = f"http://127.0.0.1:{config.GATEWAY_PORT}"
            for headers, want in (({}, local), ({"Host": "localhost:9851"}, local), ({"Host": "[::1]:9851"}, local),
                                  ({"Host": "hyblis.example"}, ""), ({"Host": "127.0.0.1.evil.example"}, ""),
                                  ({"Host": "127.0.0.1:9851", "X-Real-IP": "203.0.113.7"}, ""),
                                  ({"Host": "127.0.0.1:9851", "CF-Connecting-IP": "203.0.113.7"}, "")):   # via the tunnel
                r = await site.get("/config.json", headers=headers)
                csp = r.headers["Content-Security-Policy"]
                assert (await r.json())["api_base"] == want, (headers, await r.json())
                assert (f"connect-src 'self' {local};" in csp) == bool(want) and ("connect-src 'self';" in csp) == (not want), csp
            os.environ["HYBLIS_PUBLIC_API_BASE"] = "https://api.example/"
            try:
                r = await site.get("/config.json", headers={"Host": "hyblis.example"})
                assert (await r.json())["api_base"] == "https://api.example"
                assert "connect-src 'self' https://api.example;" in r.headers["Content-Security-Policy"]
            finally:
                del os.environ["HYBLIS_PUBLIC_API_BASE"]
        finally:
            store._conn, config.PUBLIC_DIR = real_conn, real_public
            await site.close()
        print("public site: 503 'not published yet' before the first export, never opens the DB; no long cache on a 404; "
              "API base by Host")

        await vocabulary_in_step()
        await check_bundles()
        await launch_mode()
        print("ALL E2E PASS")
    finally:
        await client.close()


def bundle_leaks(data: bytes) -> list[str]:
    """Leak-list words in any member of a bundle (case-insensitive). "deposit" counts unless it is part
    of a function name in the impact spec's ABI signatures (e.g. "deposit(uint256,address)",
    "depositCap(address)", "maxDeposit(address)"): the leak is the platform's report deposit, not a
    protocol's own function."""
    found = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            text = (tf.extractfile(m).read().decode("utf-8", "replace") if m.isfile() else "").lower()
            for word in LEAKS + ("planted-secret",):
                hit = re.search(r"deposit(?![a-z0-9_]*\s*\()", text) if word == "deposit" else word in text
                if hit:
                    found.append(f"{m.name}: {word}")
    return found


async def vocabulary_in_step():
    """What the platform reads from runner/trace_verdict.py without importing it equals the module's values."""
    assert runner_vocab.ERRORS == trace_verdict.ERRORS
    assert runner_vocab.RETRY_ERRORS == tuple(trace_verdict.RETRY_ERRORS)
    assert set(runner_vocab.RETRY_ERRORS) <= set(config.RUNNER_RETRY_ERRORS)
    assert runner_vocab.ALLOW == frozenset(trace_verdict.ALLOW) and runner_vocab.RULED == trace_verdict.RULED
    assert runner_vocab.EXPECT_NAMES == frozenset(trace_verdict.EXPECT_NAMES)
    assert runner_vocab.FOUNDRY_BUILD == trace_verdict.FOUNDRY_VERSION
    assert runner_vocab.explain("policy:warp(uint256)") == trace_verdict.explain("policy:warp(uint256)")
    # the cheatcodes shown on program pages are exactly the runner's allowlist
    names = {n for row in runner_vocab.ALLOWED_CHEATCODES for n in row[0].split(", ")}
    assert {n for n in names if not n.endswith("*")} == {s.split("(")[0] for s in runner_vocab.ALLOW | set(runner_vocab.RULED)}
    assert {n[:-1] for n in names if n.endswith("*")} == {"assert"} | set(runner_vocab.EXPECT_NAMES)
    print("runner vocabulary: error texts, retry codes, allowlist and Foundry version equal the runner's own")


async def check_bundles():
    """The hyblis check bundle, on a copy of the task packs: cap made verified (with a planted ABI file
    and planted private text), aave-v4 released but not ready, queued-demo queued with a full pack."""
    real_tasks = config.TASKS_DIR
    # whatever the real packs are now: bundles only for released, ready programs with a verified spec
    real = {p.name for p in (config.PUBLIC_DIR / "check").glob("*.tar.gz")}
    want = {f"{t}.tar.gz" for t in publish.ready_task_ids() if publish._verified_spec(t)}
    assert real == want, (real, want)
    repo = tmp / "fixture-repo"
    tdir = repo / "tasks"
    tdir.mkdir(parents=True)
    rel = json.loads((real_tasks / "releases.json").read_text())
    rel["tasks"].append({"task_id": "queued-demo", "label": "Queued demo", "status": "queued", "ready": False})
    (tdir / "releases.json").write_text(json.dumps(rel))
    for tid in ("cap", "aave-v4"):
        shutil.copytree(real_tasks / tid, tdir / tid, ignore=shutil.ignore_patterns("live-sources", "controls"))
    shutil.copytree(tdir / "cap", tdir / "queued-demo")                 # a queued program with a full pack
    for tid in ("cap", "queued-demo"):
        m = json.loads((tdir / tid / "manifest.json").read_text())
        m["task_id"] = tid
        m["program"]["notes"].append("planted-secret note")
        m["submission"] = {k: v.replace("tasks/cap/", f"tasks/{tid}/") if isinstance(v, str) else v
                           for k, v in m["submission"].items()}
        (tdir / tid / "manifest.json").write_text(json.dumps(m))
        spec = json.loads((tdir / tid / "impact-spec.json").read_text())
        spec.update(task_id=tid, status="verified", _note="planted-secret comment")
        spec.pop("pending_verification", None)
        spec["tokens"][0]["_cap_note"] = "planted-secret"
        (tdir / tid / "abi.json").write_text(json.dumps({"abi": [
            {"type": "function", "name": "deposit", "inputs": [{"type": "uint256"}, {"type": "address"}]},
            {"type": "function", "name": "sweep", "inputs": [{"type": "tuple[]", "components": [
                {"type": "address"}, {"type": "uint256"}]}]},
            {"type": "event", "name": "Swept", "inputs": []}]}))
        spec["in_scope"][0]["abi_file"] = str(tdir / tid / "abi.json")
        spec["in_scope"][0]["abi_note"] = "planted-secret"
        (tdir / tid / "impact-spec.json").write_text(json.dumps(spec))
    logs = Lines()
    publish.log.addHandler(logs)
    config.TASKS_DIR = tdir
    site = TestClient(TestServer(publicsite.make_app()))
    await site.start_server()
    try:
        (config.PUBLIC_DIR / "check" / "queued-demo.tar.gz").write_bytes(b"stale")       # must be swept
        publish.export_all()
        cdir = config.PUBLIC_DIR / "check"
        assert sorted(p.name for p in cdir.iterdir()) == ["cap.tar.gz"], sorted(p.name for p in cdir.iterdir())
        data = (cdir / "cap.tar.gz").read_bytes()
        prog = json.loads((config.PUBLIC_DIR / "programs" / "cap.json").read_text())
        ct = prog["check_tool"]
        assert ct == {"path": "data/check/cap.tar.gz", "file": "hyblis-check-cap.tar.gz",
                      "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                      "foundry": runner_vocab.FORGE_VERSION}, ct
        assert json.loads((config.PUBLIC_DIR / "programs" / "aave-v4.json").read_text())["check_tool"] is None
        terms = prog["runner_terms"]
        spec_actions = json.loads((tdir / "cap" / "impact-spec.json").read_text()).get("trusted_actions") or []
        assert terms["capital"] and terms["capital"][0]["symbol"] == "USDC", terms
        assert len(terms["as_role"]) == len(spec_actions) and all(
            {"role", "target", "function", "max_calls"} <= set(r) for r in terms["as_role"]), terms
        # exactly the whitelist, regular files only, in order
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            members = tf.getmembers()
            files = {m.name: tf.extractfile(m).read() for m in members}
        assert [m.name for m in members] == publish.check_bundle_members("cap"), [m.name for m in members]
        assert all(m.isfile() and m.mode == 0o644 and m.uid == 0 and not m.uname for m in members)
        assert sorted(p.name for p in (ROOT / "runner" / "sol").iterdir() if p.is_file()) == sorted(publish.CHECK_SOL_FILES)
        top = "hyblis-check-cap/"
        for n in publish.CHECK_RUNNER_FILES:
            assert files[top + "runner/" + n] == (ROOT / "runner" / n).read_bytes(), n
        for n in publish.CHECK_SOL_FILES:
            assert files[top + "runner/sol/" + n] == (ROOT / "runner" / "sol" / n).read_bytes(), n
        assert files[top + "tasks/cap/poc/HyblisBase.sol"] == (ROOT / "runner" / "sol" / "HyblisBase.sol").read_bytes()
        pins = dict(reversed(x.split()) for x in files[top + "runner/sol/SHA256SUMS"].decode().splitlines() if x.strip())
        assert all(pins[n] == hashlib.sha256(files[top + "runner/sol/" + n]).hexdigest()
                   for n in ("HyblisBase.sol", "HyblisRuntime.sol", "HyblisHarness.t.sol")), pins   # what check.py verifies
        assert files[top + "tasks/cap/poc/HyblisPoC.t.sol"] == (real_tasks / "cap" / "poc" / "HyblisPoC.t.sol").read_bytes()
        # the manifest: only what check.py reads, and the same static-screen answers as the full one
        full = json.loads((tdir / "cap" / "manifest.json").read_text())
        cut = json.loads(files[top + "tasks/cap/manifest.json"])
        assert set(cut) == {"task_id", "chain", "deployed", "submission"} and set(cut["chain"]) == {"chain_id", "fork_block"}
        assert cut["submission"] == {"poc_dir": "test/hyblis"}
        assert policy_check.in_scope_addresses(cut) == policy_check.in_scope_addresses(full)
        bad = POC.replace("vm.startPrank(attacker);", "vm.startPrank(0x15622c3dbbc5614E6DFa9446603c1779647f01FC);\n        vm.store(LENDER, bytes32(0), bytes32(uint256(1)));")
        for poc in (POC, bad):
            assert policy_check.check(cut, poc) == policy_check.check(full, poc)
        # the spec: no comments, ABI signatures inlined, compiles to exactly the same thing
        full_spec = json.loads((tdir / "cap" / "impact-spec.json").read_text())
        cut_spec = json.loads(files[top + "tasks/cap/impact-spec.json"])

        def keys(v):
            return ([k for k in v] + [x for y in v.values() for x in keys(y)]) if isinstance(v, dict) else \
                [x for y in v for x in keys(y)] if isinstance(v, list) else []
        assert not [k for k in keys(cut_spec) if k.startswith("_") or k.endswith("_note") or k == "abi_file"]
        assert gen_spec.compile_spec(cut_spec) == gen_spec.compile_spec(full_spec)
        assert "sweep((address,uint256)[])" in cut_spec["in_scope"][0]["functions"]
        readme = files[top + "README.md"].decode()
        assert f"Foundry {runner_vocab.FORGE_VERSION} exactly" in readme and "--rpc" in readme and "third-party" in readme
        # nothing private in any member (the planted text included)
        assert not bundle_leaks(data), bundle_leaks(data)
        # served by the site: right type and cache rules, only for a released, ready program
        r = await site.get("/data/check/cap.tar.gz")
        assert r.status == 200 and await r.read() == data, r.status
        assert r.headers["Content-Type"] == "application/gzip" and r.headers["Cache-Control"] == "no-cache"
        assert r.headers["Content-Disposition"] == 'attachment; filename="hyblis-check-cap.tar.gz"'
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        r = await site.get("/data/check/cap.tar.gz", headers={"If-None-Match": r.headers["ETag"]})
        assert r.status == 304, r.status
        for path in ("/data/check/queued-demo.tar.gz", "/data/check/aave-v4.tar.gz", "/data/check/queued-other.tar.gz",
                     "/data/check/..%2Fcap.tar.gz", "/data/check/CAP.tar.gz"):
            assert (await site.get(path)).status == 404, path
        (cdir / "aave-v4.tar.gz").write_bytes(data)                    # a stray file next to an unready program
        assert (await site.get("/data/check/aave-v4.tar.gz")).status == 404
        (cdir / "aave-v4.tar.gz").unlink()
        # the same packs give the same bytes; a broken pack loses only its own bundle, with one log line
        publish.export_all()
        assert (cdir / "cap.tar.gz").read_bytes() == data
        (tdir / "cap" / "poc" / "HyblisBase.sol").write_text("// stale copy\n")
        publish.export_all()
        assert not (cdir / "cap.tar.gz").exists() and json.loads((config.PUBLIC_DIR / "programs" / "cap.json").read_text())["check_tool"] is None
        assert [s.split(":")[0] for s in logs.lines] == ["check bundle for cap not published"], logs.lines
        assert (await site.get("/data/check/cap.tar.gz")).status == 404
        # a spec that is not verified gets no bundle and publishes no runner terms
        shutil.copy(ROOT / "runner" / "sol" / "HyblisBase.sol", tdir / "cap" / "poc" / "HyblisBase.sol")
        spec = json.loads((tdir / "cap" / "impact-spec.json").read_text())
        spec["status"] = "draft"
        (tdir / "cap" / "impact-spec.json").write_text(json.dumps(spec))
        publish.export_all()
        prog = json.loads((config.PUBLIC_DIR / "programs" / "cap.json").read_text())
        assert not (cdir / "cap.tar.gz").exists() and prog["check_tool"] is None and prog["runner_terms"] is None
    finally:
        config.TASKS_DIR = real_tasks
        publish.log.removeHandler(logs)
        await site.close()
        publish.export_all()
    print(f"check bundle: {len(members)} members exactly as listed ({len(data) // 1024} KiB), sanitised manifest and "
          "spec equivalent for the screen and the compiler, nothing private, served with no-cache and an ETag; "
          "no bundle for queued, unready or unverified programs, a stale file is swept")


async def launch_mode():
    """Mainnet launch mode with the real releases.json (the owner's decision: the site is live, intake
    opens at mainnet launch). Cap, the testnet reference program, is on no public surface and in no
    bundle; Aave V4 is published without dates; every submit is refused with 403 and the launch line
    before any other work; the summary says intake is closed and has no next release date."""
    rel = json.loads((config.TASKS_DIR / "releases.json").read_text())
    msg = rel["launch"]["message"]
    by_id = {r["task_id"]: r for r in rel["tasks"]}
    assert rel["launch"]["intake_open"] is False, "until mainnet launch, releases.json keeps intake closed"
    assert by_id["cap"]["networks"] == ["testnet"] and "Testnet reference" not in by_id["cap"]["tags"]
    saved = {k: os.environ.pop(k, None) for k in ("HYBLIS_NETWORK", "HYBLIS_INTAKE_OPEN", "HYBLIS_CLIENT_IP_HEADER")}
    client = site = None
    try:
        assert config.network() == "mainnet"                            # the default
        os.environ["HYBLIS_INTAKE_OPEN"] = "1"                          # a testnet-only switch: ignored on mainnet
        assert publish.launch_info() == {"intake_open": False, "message": msg}, publish.launch_info()
        del os.environ["HYBLIS_INTAKE_OPEN"]
        n_before = len(store.all_submissions())
        client = TestClient(TestServer(gateway.make_app()))            # make_app exports
        site = TestClient(TestServer(publicsite.make_app()))
        await client.start_server()
        await site.start_server()

        tasks = await (await client.get("/api/tasks")).json()
        assert [t["task_id"] for t in tasks] == ["aave-v4"], tasks
        assert tasks == await (await site.get("/data/tasks.json")).json()
        aave = tasks[0]
        assert aave["status"] == "featured" and aave["opened_at"] is None and aave["featured_until"] is None, aave
        assert aave["open_for_intake"] is False and aave["tags"] == [], aave
        summary = await (await client.get("/api/summary")).json()
        assert summary["releases"]["intake_open"] is False and summary["releases"]["intake_message"] == msg, summary
        assert summary["releases"]["next_release_on"] is None and summary["counts"]["open_programs"] == 1, summary
        assert (await (await site.get("/data/summary.json")).json())["releases"] == summary["releases"]
        prog = await (await client.get("/api/program/aave-v4")).json()
        assert prog["opened_at"] is None and prog["featured_until"] is None and not prog["open_for_intake"], prog
        assert prog["poc_template"] is None and prog["check_tool"] is None and prog["verification_pending"]
        assert publish.ready_task_ids() == set()                        # cap is not released here, aave is not ready
        for path in ("/api/program/cap",):
            assert (await client.get(path)).status == 404, path
        for path in ("/data/programs/cap.json", "/data/check/cap.tar.gz"):
            assert (await site.get(path)).status == 404, path
        # nothing of Cap anywhere public: no file, no id, no label, no scope text, no contract
        files = sorted(p.relative_to(config.PUBLIC_DIR).as_posix() for p in config.PUBLIC_DIR.rglob("*") if p.is_file())
        assert files == ["leaderboard.json", "ledger.json", "programs/aave-v4.json", "scoring-policy.json",
                         "summary.json", "tasks.json"], files
        blob = (json.dumps([tasks, summary, prog]) + "".join(
            (config.PUBLIC_DIR / f).read_text() for f in files)).lower()
        for word in ('"cap"', 'hyblis-check-cap', 'stablecoin protocol', 'cusd', VAULT.lower(), LENDER.lower(),
                     'testnet', 'draft') + LEAKS:
            assert word not in blob, f"launch mode: {word!r} on a public surface"

        # every submit is refused before any work: nothing parsed, checked, charged or stored; CORS still applies
        gateway._BUCKET.clear()
        kp = Keypair.create_from_uri("//LaunchVisitor")
        pkg = make_pkg(kp, task_id="aave-v4")
        site_origin = {"Origin": "http://site.test"}
        for kw in ({"json": signed(kp, pkg), "headers": site_origin},
                   {"json": signed(kp, make_pkg(kp)), "headers": {**site_origin, "CF-Connecting-IP": "203.0.113.9"}},
                   {"data": "not json", "headers": {**site_origin, "Content-Type": "text/plain"}},
                   {"data": b"{" * (2 * 1024 * 1024), "headers": {"Content-Type": "application/json"}}):
            r = await client.post("/api/submit", **kw)
            body = await r.json()
            assert r.status == 403 and body == {"error": msg}, (r.status, body)
            assert r.headers.get("Access-Control-Allow-Origin") == ("http://site.test" if "Origin" in kw["headers"] else None)
        assert not gateway._BUCKET and len(store.all_submissions()) == n_before
        r = await client.options("/api/submit", headers={**site_origin, "Access-Control-Request-Method": "POST"})
        assert r.status == 204 and r.headers["Access-Control-Allow-Origin"] == "http://site.test"
        assert (await client.get("/api/health")).status == 200 and (await client.get("/api/ledger")).status == 200

        # configuration typos stop the services instead of publishing the wrong programs
        os.environ["HYBLIS_NETWORK"] = "mainnet-beta"
        try:
            gateway.make_app()
            raise AssertionError("an unknown HYBLIS_NETWORK was accepted")
        except ValueError:
            pass
        finally:
            del os.environ["HYBLIS_NETWORK"]
        assert not publish._released({"status": "open", "networks": "testnet"})      # not a list: released nowhere
        assert not publish._released({"status": "open", "networks": []})
        assert publish._released({"status": "open"}) and not publish._released({"status": "queued"})
    finally:
        for c in (client, site):
            if c is not None:
                await c.close()
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        publish.export_all()
    print(f"launch mode (mainnet, real releases.json): only Aave V4, without dates; Cap on no public surface and in no "
          f"bundle; submit refused 403 '{msg}' before any work, CORS kept; summary intake_open=false, no next release")


try:
    asyncio.run(main())
finally:
    shutil.rmtree(tmp, ignore_errors=True)
