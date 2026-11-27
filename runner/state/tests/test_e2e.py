"""End-to-end test of the state layer on a local toy chain (no network).

  anvil (toy contracts) --collect--> access list --build--> snapshot v1 --serve--> forge test
  (a) every value forge reads through the proxy equals anvil's value at the pinned block
  (b) a read outside the snapshot fails the forge run and lands in the miss list
  (c) extend (repeated, like the runner's re-queue loop) fixes it; each version has a new digest
  (d) a tampered snapshot, a lying upstream and a wrong trust anchor are refused

Run through runner/state/tests/run.sh (user pinc, idle priority, anvil on 127.0.0.1:9864 or 9865 + IPC).
"""
from __future__ import annotations

import atexit
import copy
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from state import fork_proxy, mpt, snapshot, store
from state.jsonrpc import Client, RpcError, UnixRpcServer
from state.mpt import keccak, to_hex

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.dirname(HERE)
HYBLIS = os.path.abspath(os.path.join(STATE, "..", ".."))
PY = [sys.executable, "-I", "-B"]
SNAPSHOT_PY = os.path.join(STATE, "snapshot.py")
PROXY_PY = os.path.join(STATE, "fork_proxy.py")
EOA = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"   # anvil dev account 0 (unlocked)
FRESH = "0x00000000000000000000000000000000c0ffee01"
KEEP = os.environ.get("HYBLIS_STATE_KEEP") == "1"
WRITE_FIXTURES = os.environ.get("HYBLIS_STATE_WRITE_FIXTURES") == "1"


def sel(sig: str) -> str:
    return keccak(sig.encode())[:4].hex()


def word(v) -> str:
    if isinstance(v, str):
        v = int(v, 16)
    return v.to_bytes(32, "big").hex()


def log(msg: str) -> None:
    print(f"    [e2e] {msg}", file=sys.stderr, flush=True)


class Chain:
    """anvil + the toy contracts. Everything runs as the calling user (pinc), inherited idle priority."""

    def __init__(self, work: str, port: int):
        self.work = work
        self.ipc = os.path.join(work, "anvil.ipc")
        self.port = port
        self.proc = None

    def start(self):
        exe = shutil.which("anvil")
        self.log = open(os.path.join(self.work, "anvil.log"), "w")
        self.proc = subprocess.Popen([exe, "--host", "127.0.0.1", "--port", str(self.port), "--ipc", self.ipc,
                                      "--accounts", "3", "--balance", "10000", "--timestamp", "1794668000"],
                                     stdout=self.log, stderr=subprocess.STDOUT, env=clean_env(self.work))
        atexit.register(self.stop)
        for _ in range(200):
            if os.path.exists(self.ipc):
                try:
                    Client(self.ipc, timeout=2, retries=0).call("eth_chainId", [])
                    break
                except Exception:
                    pass
            if self.proc.poll() is not None:
                raise RuntimeError("anvil exited: " + open(os.path.join(self.work, "anvil.log")).read()[-500:])
            time.sleep(0.1)
        else:
            raise RuntimeError("anvil did not start")
        self.c = Client(self.ipc)

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def send(self, to, data="", value=0):
        tx = {"from": EOA, "data": "0x" + data, "value": hex(value), "gas": hex(29_000_000)}
        if to:
            tx["to"] = to
        h = self.c.call("eth_sendTransaction", [tx])
        for _ in range(300):   # automine is asynchronous
            r = self.c.call("eth_getTransactionReceipt", [h])
            if r:
                break
            time.sleep(0.02)
        assert r and r["status"] == "0x1", r
        return r

    def deploy(self, toy, name, args_hex="", value=0):
        with open(os.path.join(toy, "out", "Toy.sol", f"{name}.json")) as f:
            code = json.load(f)["bytecode"]["object"][2:]
        return self.send(None, code + args_hex, value)["contractAddress"].lower()


def clean_env(work: str, **extra) -> dict:
    env = {"PATH": os.environ["PATH"], "HOME": os.path.join(work, "home"), "FOUNDRY_FFI": "false",
           "XDG_CACHE_HOME": os.path.join(work, "cache"), "NO_COLOR": "1"}
    env.update({k: str(v) for k, v in extra.items()})
    return env


class E2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls._setup()
        except BaseException:
            cls.tearDownClass()   # unittest does not call it when setUpClass fails
            raise

    @classmethod
    def _setup(cls):
        cls.t0 = time.time()
        cls.handles = []
        cls.work = tempfile.mkdtemp(prefix="hyblis-state-e2e-")
        os.makedirs(os.path.join(cls.work, "home"))
        svm = os.path.join(HYBLIS, ".home", ".svm")
        if os.path.isdir(svm):  # cached solc 0.8.28; nothing is downloaded
            os.symlink(svm, os.path.join(cls.work, "home", ".svm"))
        cls.toy = os.path.join(cls.work, "toy")
        shutil.copytree(os.path.join(HERE, "toy"), cls.toy, ignore=shutil.ignore_patterns("out", "cache", "lib"))
        os.makedirs(os.path.join(cls.toy, "lib"))
        forge_std = os.environ.get("HYBLIS_FORGE_STD")
        if not forge_std or not os.path.isdir(os.path.join(forge_std, "src")):
            raise unittest.SkipTest("HYBLIS_FORGE_STD not set (run.sh sets it)")
        os.symlink(forge_std, os.path.join(cls.toy, "lib", "forge-std"))
        p = subprocess.run(["forge", "build", "--offline"], cwd=cls.toy, env=clean_env(cls.work),
                           capture_output=True, text=True, timeout=600)
        if p.returncode != 0:
            raise RuntimeError("forge build failed:\n" + p.stdout[-2000:] + p.stderr[-2000:])
        port = int(os.environ.get("HYBLIS_STATE_ANVIL_PORT", "9864"))
        cls.chain = Chain(cls.work, port)
        cls.chain.start()
        cls._make_state()

    @classmethod
    def tearDownClass(cls):
        for h in getattr(cls, "handles", []):
            h.close()
        if hasattr(cls, "chain"):
            cls.chain.stop()
        if not hasattr(cls, "work"):
            return
        if KEEP:
            log(f"kept work dir {cls.work}")
        else:
            shutil.rmtree(cls.work, ignore_errors=True)
        log(f"total {time.time() - getattr(cls, 't0', time.time()):.1f}s")

    # ------------------------------------------------------------------ chain setup
    @classmethod
    def _make_state(cls):
        ch, toy = cls.chain, cls.toy
        cls.token = ch.deploy(toy, "Token", word(10**24))
        cls.vault = ch.deploy(toy, "Vault", word(cls.token), value=5 * 10**18)
        cls.spray = ch.deploy(toy, "Spray")
        cls.outside = ch.deploy(toy, "Outside")
        ch.send(cls.vault, sel("set(uint256,uint256)") + word(1) + word(42))
        ch.send(cls.vault, sel("fill(uint256)") + word(150))
        ch.send(cls.token, sel("transfer(address,uint256)") + word(cls.vault) + word(1000))
        ch.send(cls.token, sel("transfer(address,uint256)") + word("0xbeef") + word(77))
        ch.send(cls.spray, sel("spray(uint256,uint256)") + word(250) + word(1), value=250)
        ch.send(cls.outside, sel("setSecret(uint256)") + word(0xC0DE))
        ch.send(cls.outside, sel("give(address,uint256)") + word(EOA) + word(555))
        ch.c.call("anvil_mine", ["0x6", "0xc"])
        cls.pin = mpt.parse_quantity(ch.c.call("eth_blockNumber", []))
        blk = ch.c.call("eth_getBlockByNumber", [hex(cls.pin), False])
        cls.pin_hash = blk["hash"]
        cls.sprayed = to_hex(keccak(bytes.fromhex(word(1) + word(7)))[12:])
        # after the pinned block: state moves on, the snapshot must not
        ch.send(cls.vault, sel("set(uint256,uint256)") + word(1) + word(99))
        ch.send(cls.outside, sel("setSecret(uint256)") + word(0xBAD))
        ch.send(cls.token, sel("transfer(address,uint256)") + word("0xbeef") + word(1))
        log(f"toy chain ready: pinned block {cls.pin} {cls.pin_hash}, head {ch.c.call('eth_blockNumber', [])}")

    def at_pin(self, method, *params):
        return self.chain.c.call(method, list(params) + [hex(self.pin)])

    def expected_env(self) -> dict:
        c, pin = self.chain.c, hex(self.pin)
        blk = c.call("eth_getBlockByNumber", [pin, False])
        bh = lambda k: c.call("eth_getBlockByNumber", [hex(self.pin - k), False])["hash"]  # noqa: E731
        sload = lambda a, s: int(self.at_pin("eth_getStorageAt", a, s), 16)  # noqa: E731
        mslot = lambda key, base: to_hex(keccak(bytes.fromhex(word(key) + word(base))))  # noqa: E731
        list_base = int.from_bytes(keccak(bytes.fromhex(word(3))), "big")
        env = {
            "PIN": self.pin, "VAULT": self.vault, "TOKEN": self.token, "EOA": EOA, "OUTSIDE": self.outside,
            "SPRAYED": self.sprayed, "FRESH": FRESH,
            "EXP_TS": int(blk["timestamp"], 16), "EXP_BASEFEE": int(blk["baseFeePerGas"], 16),
            "EXP_PREVRANDAO": int(blk["mixHash"], 16), "EXP_BH1": bh(1), "EXP_BH5": bh(5),
            "EXP_COUNTER": sload(self.vault, "0x1"), "EXP_DATA1": sload(self.vault, mslot(1, 2)),
            "EXP_DATA1010": sload(self.vault, mslot(1010, 2)), "EXP_LIST5": sload(self.vault, hex(list_base + 5)),
            "EXP_VAULT_ETH": int(self.at_pin("eth_getBalance", self.vault), 16),
            "EXP_VAULT_CODEHASH": to_hex(keccak(bytes.fromhex(self.at_pin("eth_getCode", self.vault)[2:]))),
            "EXP_VAULT_TOK": sload(self.token, mslot(int(self.vault, 16), 0)), "EXP_SUPPLY": sload(self.token, "0x2"),
            "EXP_EOA_ETH": int(self.at_pin("eth_getBalance", EOA), 16),
            "EXP_EOA_NONCE": int(self.at_pin("eth_getTransactionCount", EOA), 16),
            "EXP_SECRET": sload(self.outside, "0x0"), "EXP_CREDIT": sload(self.outside, mslot(int(EOA, 16), 1)),
            "EXP_BEEF_TOK": sload(self.token, mslot(0xBEEF, 0)), "EXP_PEEK": sload(self.vault, mslot(424242, 2)),
        }
        # sanity: the chain really moved on after the pinned block
        assert env["EXP_DATA1"] == 42 and int(c.call("eth_getStorageAt", [self.vault, mslot(1, 2), "latest"]), 16) == 99
        assert env["EXP_SECRET"] == 0xC0DE and env["EXP_CREDIT"] == 555 and env["EXP_BEEF_TOK"] == 77
        return env

    # ------------------------------------------------------------------ helpers
    def forge(self, rpc: str, contract: str, test: str | None = None) -> dict:
        args = ["forge", "test", "--offline", "--no-storage-caching", "--json", "-vv", "--match-contract", f"^{contract}$"]
        if test:
            args += ["--match-test", f"^{test}\\(\\)$"]
        t0 = time.time()
        p = subprocess.run(args, cwd=self.toy, env=clean_env(self.work, HYBLIS_ETH_RPC=rpc, **self.expected_env()),
                           capture_output=True, text=True, timeout=600)
        dt = time.time() - t0
        try:
            doc = json.loads(p.stdout)
        except ValueError:
            raise AssertionError(f"forge gave no JSON (exit {p.returncode}): {p.stderr[-1500:]}") from None
        res = {name: r for suite in doc.values() for name, r in suite["test_results"].items()}
        return {"exit": p.returncode, "results": res, "seconds": dt, "stderr": p.stderr}

    def cli(self, *args, ok=True) -> subprocess.CompletedProcess:
        p = subprocess.run(PY + list(args), capture_output=True, text=True, timeout=900, cwd=self.work,
                           env=clean_env(self.work, SOURCE_DATE_EPOCH="1794668000", PYTHONDONTWRITEBYTECODE="1"))
        if ok and p.returncode != 0:
            raise AssertionError(f"{args[:2]} exit {p.returncode}: {p.stderr[-2000:]}")
        return p

    def chain_args(self, block_hash=None):
        return ["--chain-id", "31337", "--block", str(self.pin), "--expect-block-hash", block_hash or self.pin_hash]

    def path(self, name):
        return os.path.join(self.work, name)

    def serve(self, snap_dir, name, **kw) -> fork_proxy.ProxyHandle:
        h = fork_proxy.serve(snap_dir, self.path(name), expect_block_hash=self.pin_hash, expect_chain_id=31337, **kw)
        self.handles.append(h)
        return h

    def build_v1(self):
        if not os.path.exists(self.path("snap-v1")):
            self.test_01_collect_and_build()
        return self.path("snap-v1")

    # ------------------------------------------------------------------ tests
    def test_01_collect_and_build(self):
        if os.path.exists(self.path("snap-v1")):
            return
        sock = self.path("collect.ipc")
        p = subprocess.run(PY + [SNAPSHOT_PY, "collect", "--upstream", self.chain.ipc, "--socket", sock,
                                 "--out", self.path("access.json")] + self.chain_args() + [
            "--", "forge", "test", "--offline", "--no-storage-caching", "--match-contract", "^Template$"],
            cwd=self.toy, env=clean_env(self.work, **self.expected_env()), capture_output=True, text=True, timeout=600)
        self.assertEqual(p.returncode, 0, "template must pass through the collect proxy:\n" + p.stdout[-3000:] + p.stderr[-2000:])
        with open(self.path("access.json")) as f:
            acc = json.load(f)
        self.assertIn(self.vault, acc["accounts"])
        self.assertIn(self.token, acc["accounts"])
        self.assertNotIn(self.outside, acc["accounts"])
        self.assertTrue(acc["blocks"], "blockhash reads should be recorded")
        log(f"collect: {len(acc['accounts'])} accounts, {sum(map(len, acc['accounts'].values()))} slots, "
            f"requests {acc['requests']}")
        out = self.cli(SNAPSHOT_PY, "build", "--access", self.path("access.json"), "--upstream", self.chain.ipc,
                       "--out", self.path("snap-v1"), *self.chain_args())
        m = json.loads(out.stdout)
        log(f"build v1: {m['digest']} {m['counts']}")
        self.assertTrue(m["digest"].startswith("sha256:"))
        v = self.cli(SNAPSHOT_PY, "verify", self.path("snap-v1"), "--expect-block-hash", self.pin_hash, "--chain-id", "31337")
        self.assertTrue(json.loads(v.stdout)["ok"])
        if WRITE_FIXTURES:
            self._write_fixtures()

    def _write_fixtures(self):
        blk = self.chain.c.call("eth_getBlockByNumber", [hex(self.pin), False])
        mslot = lambda key, base: to_hex(keccak(bytes.fromhex(word(key) + word(base))))  # noqa: E731
        z = lambda s: "0x" + word(s)  # noqa: E731
        items = [(self.vault, [mslot(1, 2), mslot(999999, 2), z(1)]), (self.token, [mslot(int(self.vault, 16), 0)]),
                 (EOA, [z(0)]), (FRESH, [z(5)]), (self.sprayed, [])]
        proofs = [{"address": a, "slots": s, "result": self.at_pin("eth_getProof", a, s)} for a, s in items]
        doc = {"source": "anvil 1.9.0 toy chain from runner/state/tests/test_e2e.py", "chain_id": 31337,
               "block_number": self.pin, "block_hash": self.pin_hash, "block": blk, "proofs": proofs}
        with open(os.path.join(HERE, "fixtures", "anvil_proofs.json"), "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
        log("wrote fixtures/anvil_proofs.json")

    def test_02_reads_match_anvil(self):
        """(a) forge through the proxy sees exactly anvil's state at the pinned block."""
        snap = self.build_v1()
        h = self.serve(snap, "v1-a.ipc")
        r = self.forge(h.socket_path, "Template")
        st = r["results"]["test_template()"]
        self.assertEqual(st["status"], "Success", st.get("reason"))
        self.assertEqual(h.misses(), [])
        self.assertEqual({x["method"] for x in h.refusals()}, {"anvil_nodeInfo"})
        # RPC-level cross-check: every account and slot in the snapshot equals anvil at the pinned block
        db = sqlite3.connect(os.path.join(snap, "state.sqlite"))
        px = Client(h.socket_path)
        n = 0
        tag = {"blockHash": self.pin_hash}
        for addr, in db.execute("SELECT address FROM accounts"):
            for m in ("eth_getBalance", "eth_getTransactionCount", "eth_getCode"):
                self.assertEqual(px.call(m, [addr, tag]), self.at_pin(m, addr), f"{m} {addr}")
                n += 1
        for addr, slot in db.execute("SELECT address, slot FROM storage"):
            self.assertEqual(int(px.call("eth_getStorageAt", [addr, slot, tag]), 16),
                             int(self.at_pin("eth_getStorageAt", addr, slot), 16), f"{addr}[{slot}]")
            n += 1
        for num, hh in db.execute("SELECT number, hash FROM headers"):
            mine = px.call("eth_getBlockByHash", [hh, False])
            theirs = self.chain.c.call("eth_getBlockByNumber", [hex(num), False])
            for k, kind in mpt.HEADER_FIELDS:
                if k in theirs:
                    norm = (lambda v: int(v, 16)) if kind == "int" else str.lower
                    self.assertEqual(norm(mine[k]), norm(theirs[k]), f"header {num} {k}")
            self.assertEqual(mine["hash"], theirs["hash"])
            n += 1
        px.close()
        db.close()
        direct = self.forge(self.chain.ipc, "Template")
        self.assertEqual(direct["results"]["test_template()"]["status"], "Success")
        log(f"(a) {n} values identical to anvil; forge via proxy {r['seconds']:.2f}s, direct anvil {direct['seconds']:.2f}s;"
            f" proxy stats {json.dumps({k: h.stats()[k] for k in ('requests', 'busy_ms', 'max_request_ms', 'connections_total')})}")

    def test_03_miss_then_extend_loop(self):
        """(b) reads outside the snapshot fail the run and are recorded; (c) extend fixes them."""
        snap = self.build_v1()
        digests = [json.load(open(os.path.join(snap, "manifest.json")))["digest"]]
        miss_files = []
        for rnd in range(1, 9):
            h = self.serve(snap, f"loop{rnd}.ipc", miss_file=self.path(f"misses{rnd}.json"))
            r = self.forge(h.socket_path, "OutsideRead")
            st = r["results"]["test_outside()"]
            misses = h.misses()
            h.close()
            if st["status"] == "Success":
                self.assertEqual(misses, [])
                break
            self.assertIn("hyblis-state-miss", st["reason"] or "", st["reason"])
            self.assertNotIn("unreachable", st["reason"] or "")
            self.assertTrue(misses, "a failed run must leave misses")
            with open(self.path(f"misses{rnd}.json")) as f:
                doc = json.load(f)
            self.assertEqual(doc["misses"], misses)
            self.assertEqual(doc["snapshot_digest"], digests[-1])
            if rnd == 1:
                self.assertEqual(misses, [{"kind": "account", "address": self.outside}])  # (b)
            miss_files.append(self.path(f"misses{rnd}.json"))
            nxt = self.path(f"snap-v{rnd + 1}")
            out = json.loads(self.cli(SNAPSHOT_PY, "extend", "--snapshot", snap, "--misses", miss_files[-1],
                                      "--upstream", self.chain.ipc, "--out", nxt, *self.chain_args()).stdout)
            self.assertEqual(out["parent_digest"], digests[-1])
            self.assertNotIn(out["digest"], digests)
            self.assertEqual(out["version"], rnd + 1)
            digests.append(out["digest"])
            log(f"round {rnd}: misses {misses} -> v{rnd + 1} {out['digest'][:20]}..")
            snap = nxt
        else:
            self.fail("extend loop did not converge in 8 rounds")
        self.assertGreaterEqual(len(digests), 2)
        log(f"(b)+(c) converged after {len(digests) - 1} extend round(s)")
        # content addressing: one direct build from all inputs gives the same digest as the chain of extends
        direct = self.path("snap-direct")
        args = [SNAPSHOT_PY, "build", "--access", self.path("access.json")]
        for mf in miss_files:
            args += ["--access", mf]
        m = json.loads(self.cli(*args, "--upstream", self.chain.ipc, "--out", direct, *self.chain_args()).stdout)
        self.assertEqual(m["digest"], digests[-1], "direct build and extend chain must have the same content digest")

    def test_04_deterministic_build(self):
        a, b = self.path("det-a"), self.path("det-b")
        acc = self._access()
        for d in (a, b):
            self.cli(SNAPSHOT_PY, "build", "--access", acc, "--upstream", self.chain.ipc, "--out", d, *self.chain_args())
        for name in ("manifest.json", "header.json", "state.sqlite"):
            with open(os.path.join(a, name), "rb") as f1, open(os.path.join(b, name), "rb") as f2:
                self.assertEqual(hashlib.sha256(f1.read()).hexdigest(), hashlib.sha256(f2.read()).hexdigest(), name)
        log("two builds of the same inputs are byte-identical (SOURCE_DATE_EPOCH fixed)")

    def _access(self):
        self.build_v1()
        return self.path("access.json")

    def test_05_tampered_snapshot_refused(self):
        """(d) any change to a snapshot is refused at verify/serve time."""
        src = self.build_v1()
        vault_slot = sqlite3.connect(os.path.join(src, "state.sqlite")).execute(
            "SELECT slot, value FROM storage WHERE address = ? AND value != ? LIMIT 1",
            (self.vault, "0x" + "00" * 32)).fetchone()

        def variant(name, sql=None, fix_hashes=True, manifest_edit=None, header_edit=None, file_edit=None):
            d = self.path(f"tamper-{name}")
            shutil.copytree(src, d)
            for f in os.listdir(d):
                os.chmod(os.path.join(d, f), 0o644)
            db_path = os.path.join(d, "state.sqlite")
            if sql:
                db = sqlite3.connect(db_path)
                for stmt, args in sql:
                    db.execute(stmt, args)
                db.commit()
                db.execute("VACUUM")
                db.close()
            if file_edit:
                file_edit(db_path)
            hp = os.path.join(d, "header.json")
            if header_edit:
                with open(hp) as f:
                    hdr = json.load(f)
                header_edit(hdr)
                with open(hp, "w") as f:
                    json.dump(hdr, f)
            mp = os.path.join(d, "manifest.json")
            with open(mp) as f:
                man = json.load(f)
            if fix_hashes:  # a careful attacker also fixes every hash and digest in the manifest
                with open(db_path, "rb") as f:
                    sb = f.read()
                man["state_sha256"] = man["files"]["state.sqlite"] = hashlib.sha256(sb).hexdigest()
                with open(hp, "rb") as f:
                    man["files"]["header.json"] = hashlib.sha256(f.read()).hexdigest()
                try:
                    conn = store._open_memory(sb)
                    man["digest"] = store.compute_digest(conn)
                    conn.close()
                except Exception:
                    pass
            if manifest_edit:
                manifest_edit(man)
            with open(mp, "w") as f:
                json.dump(man, f)
            return d

        z32 = "0x" + "00" * 32
        cases = {
            "storage-value": dict(sql=[("UPDATE storage SET value = ? WHERE address = ? AND slot = ?",
                                        ("0x" + "00" * 31 + "99", self.vault, vault_slot[0]))]),
            "balance": dict(sql=[("UPDATE accounts SET balance = ? WHERE address = ?", ("0x1", self.vault))]),
            "nonce": dict(sql=[("UPDATE accounts SET nonce = ? WHERE address = ?", ("0x9", EOA))]),
            "code": dict(sql=[("UPDATE accounts SET code = ? WHERE address = ?", (b"\x60\x00", self.vault))]),
            "absent-made-rich": dict(sql=[('UPDATE accounts SET "exists" = 1, balance = ? WHERE "exists" = 0', ("0x64",))]),
            "extra-slot": dict(sql=[("INSERT INTO storage VALUES (?, ?, ?)", (self.vault, "0x" + "ab" * 32, "0x" + "00" * 31 + "01"))]),
            "trie-node": dict(sql=[("UPDATE trie_nodes SET rlp = CAST(rlp || x'00' AS BLOB) WHERE hash = (SELECT MIN(hash) FROM trie_nodes)", ())]),
            "node-as-text": dict(sql=[("UPDATE trie_nodes SET rlp = 'abc' WHERE hash = (SELECT MIN(hash) FROM trie_nodes)", ())]),
            "orphan-node": dict(sql=[("INSERT INTO trie_nodes VALUES (?, ?)", (to_hex(keccak(b"\xc0")), b"\xc0"))]),
            "dropped-node": dict(sql=[("DELETE FROM trie_nodes WHERE hash = (SELECT MAX(hash) FROM trie_nodes)", ())]),
            "header-rlp": dict(sql=[("UPDATE headers SET rlp = CAST(rlp || x'00' AS BLOB) WHERE number = ?", (self.pin - 3,))]),
            "ancestor-gap": dict(sql=[("DELETE FROM headers WHERE number = ?", (self.pin - 2,))]),
            "meta-root": dict(sql=[("UPDATE meta SET value = ? WHERE key = 'state_root'", (z32,))]),
            "unhashed-file": dict(sql=[("UPDATE accounts SET balance = ? WHERE address = ?", ("0x1", self.vault))], fix_hashes=False),
            "header-json": dict(header_edit=lambda h: h.__setitem__("timestamp", hex(int(h["timestamp"], 16) + 1))),
            "manifest-ts": dict(manifest_edit=lambda m: m.__setitem__("timestamp", m["timestamp"] + 1)),
            "manifest-digest": dict(manifest_edit=lambda m: m.__setitem__("digest", "sha256:" + "0" * 64)),
            "not-sqlite": dict(file_edit=lambda p: open(p, "wb").write(b"garbage")),
        }
        for name, kw in cases.items():
            d = variant(name, **kw)
            with self.assertRaises(store.SnapshotError, msg=name) as cm:
                fork_proxy.serve(d, self.path(f"t-{name}.ipc"), expect_block_hash=self.pin_hash)
            self.assertFalse(os.path.exists(self.path(f"t-{name}.ipc")), "nothing may be served")
            p = self.cli(SNAPSHOT_PY, "verify", d, "--expect-block-hash", self.pin_hash, ok=False)
            self.assertEqual(p.returncode, 1, f"{name}: {p.stdout}")
            log(f"(d) tampered '{name}' refused: {str(cm.exception)[:90]}")
        # a genuine snapshot checked against the wrong anchor
        other = self.chain.c.call("eth_getBlockByNumber", [hex(self.pin - 1), False])["hash"]
        with self.assertRaises(store.SnapshotError):
            fork_proxy.serve(src, self.path("t-anchor.ipc"), expect_block_hash=other)
        with self.assertRaises(store.SnapshotError):
            fork_proxy.serve(src, self.path("t-chain.ipc"), expect_block_hash=self.pin_hash, expect_chain_id=1)
        p = self.cli(PROXY_PY, "serve", "--snapshot", src, "--socket", self.path("t-cli.ipc"),
                     "--expect-block-hash", other, ok=False)
        self.assertEqual(p.returncode, 2)

    def test_06_lying_upstream_refused_at_build(self):
        """(d) the build refuses wrong proofs, values, code and headers from the upstream."""
        acc = self._access()
        bump = lambda d, k: _set(d, k, hex(int(d[k], 16) + 1))  # noqa: E731
        mutations = {
            "storage-value": lambda m, r: m == "eth_getProof" and _bump_storage(r),
            "account-balance": lambda m, r: m == "eth_getProof" and bump(r, "balance"),
            "flip-node": lambda m, r: m == "eth_getProof" and _flip_last(r["accountProof"]),
            "truncate": lambda m, r: m == "eth_getProof" and len(r["accountProof"]) > 1 and bool(r["accountProof"].pop()),
            "extra-node": lambda m, r: m == "eth_getProof" and _set(r, "accountProof", r["accountProof"] + r["accountProof"][:1]),
            "drop-storage-proof": lambda m, r: m == "eth_getProof" and bool(r["storageProof"]) and bool(r["storageProof"].pop()),
            "code": lambda m, r: m == "eth_getCode" and r != "0x" and "0x60",
            "header": lambda m, r: m == "eth_getBlockByNumber" and bump(r, "timestamp"),
            "ancestor": lambda m, r: m == "eth_getBlockByHash" and bump(r, "gasUsed"),
        }
        for name, mut in mutations.items():
            liar = Liar(self.chain.ipc, mut)
            srv = UnixRpcServer(self.path(f"liar-{name}.ipc"), liar, blocking=True).start()
            try:
                out = self.path(f"liar-snap-{name}")
                p = self.cli(SNAPSHOT_PY, "build", "--access", acc, "--upstream", srv.socket_path, "--out", out,
                             *self.chain_args(), ok=False)
            finally:
                srv.close()
                liar.close()
            self.assertEqual(p.returncode, 3, f"{name}: build must be REFUSED, got {p.returncode}: {p.stderr[-500:]}")
            self.assertTrue(liar.mutated, f"{name}: mutation never applied")
            self.assertFalse(os.path.exists(out), f"{name}: no snapshot may be written")
            log(f"(d) lying upstream '{name}' refused: {p.stderr.strip().splitlines()[-1][:100]}")
        # wrong trust anchor / chain at build time (access list recorded for the same wrong anchor)
        bad = "0x" + "11" * 32
        with open(acc) as f:
            d = json.load(f)
        d["block_hash"] = bad
        with open(self.path("access-wrong-anchor.json"), "w") as f:
            json.dump(d, f)
        p = self.cli(SNAPSHOT_PY, "build", "--access", self.path("access-wrong-anchor.json"), "--upstream",
                     self.chain.ipc, "--out", self.path("x"), *self.chain_args(block_hash=bad), ok=False)
        self.assertEqual(p.returncode, 3, p.stderr)
        self.assertIn("keccak(rlp(header))", p.stderr)
        p = self.cli(SNAPSHOT_PY, "build", "--access", acc, "--upstream", self.chain.ipc, "--out", self.path("x"),
                     *self.chain_args(block_hash=bad), ok=False)
        self.assertNotEqual(p.returncode, 0)   # an access list for another block is refused too
        p = self.cli(SNAPSHOT_PY, "build", "--access", acc, "--upstream", self.chain.ipc, "--out", self.path("x"),
                     "--chain-id", "1", "--block", str(self.pin), "--expect-block-hash", self.pin_hash, ok=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse(os.path.exists(self.path("x")))

    def test_07_refusals_not_misses(self):
        snap = self.build_v1()
        h = self.serve(snap, "esc.ipc")
        r = self.forge(h.socket_path, "Escape")
        for t, why in (("test_write_method()", "not allowed"), ("test_other_block()", "only block"),
                       ("test_latest_fork()", "block tags are not served")):
            self.assertEqual(r["results"][t]["status"], "Failure", t)
            self.assertIn(why, r["results"][t]["reason"] or "", t)
        self.assertEqual(h.misses(), [])
        methods = {x["method"] for x in h.refusals()}
        self.assertIn("anvil_setBalance", methods)
        self.assertTrue(any("not the pinned block" in x["reason"] for x in h.refusals()))
        self.assertTrue(any(x["method"] == "eth_getBlockByNumber" and "tag" in x["reason"] for x in h.refusals()))
        log(f"refusals: {[(x['method'], x['reason'][:40], x['count']) for x in h.refusals()]}")

    def test_08_protocol(self):
        snap = self.build_v1()
        h = self.serve(snap, "proto.ipc")
        c = Client(h.socket_path, retries=0)
        tag = {"blockHash": self.pin_hash}
        # pinned block by number, EIP-1898 hash or number object; nothing else
        bal = self.at_pin("eth_getBalance", self.vault)
        for b in (hex(self.pin), tag, {"blockNumber": hex(self.pin)}, {"blockHash": self.pin_hash, "requireCanonical": True}):
            self.assertEqual(c.call("eth_getBalance", [self.vault, b]), bal)
        for b in ("latest", "pending", "earliest", "safe", "finalized", hex(self.pin - 1), hex(self.pin + 1),
                  {"blockHash": "0x" + "00" * 32}, None):
            with self.assertRaises(RpcError) as cm:
                c.call("eth_getBalance", [self.vault, b])
            self.assertEqual(cm.exception.code, fork_proxy.E_NOT_SERVED, b)
        for m, p in (("eth_blockNumber", []), ("eth_call", [{}, hex(self.pin)]), ("eth_sendRawTransaction", ["0x00"]),
                     ("anvil_setStorageAt", [self.vault, "0x0", "0x1"]), ("evm_mine", []), ("debug_traceCall", []),
                     ("eth_gasPrice", []), ("eth_feeHistory", [1, "latest", []])):
            with self.assertRaises(RpcError) as cm:
                c.call(m, p)
            self.assertEqual(cm.exception.code, fork_proxy.E_METHOD, m)
        self.assertEqual(c.call("eth_chainId", []), hex(31337))
        self.assertEqual(c.call("net_version", []), "31337")
        with self.assertRaises(RpcError):
            c.call("eth_getBlockByNumber", [hex(self.pin), True])
        with self.assertRaises(RpcError):
            c.call("eth_getBlockByNumber", ["latest", False])
        self.assertEqual(c.call("eth_getBlockByNumber", [hex(self.pin), False])["hash"], self.pin_hash)
        # eth_getProof answered from stored nodes verifies against the pinned state root
        root = mpt.from_hex(c.call("eth_getBlockByNumber", [hex(self.pin), False])["stateRoot"], 32)
        db = sqlite3.connect(os.path.join(snap, "state.sqlite"))
        slots = [s for (s,) in db.execute("SELECT slot FROM storage WHERE address = ? LIMIT 5", (self.vault,))]
        db.close()
        alice = snapshot.make_addr("alice")   # in the snapshot via the forge defaults, absent on the toy chain
        for addr, sl in ((self.vault, slots), (alice, ["0x" + "00" * 32]), (EOA, [])):
            pr = c.call("eth_getProof", [addr, sl, tag])
            acct, vals, _ = mpt.verify_account_result(root, addr, sl, pr)
            ref = self.at_pin("eth_getProof", addr, sl)
            for k in ("balance", "nonce", "codeHash", "storageHash"):
                self.assertEqual(int(pr[k], 16), int(ref[k], 16), f"{addr} {k}")
            self.assertEqual([int(x["value"], 16) for x in pr["storageProof"]],
                             [int(x["value"], 16) for x in ref["storageProof"]])
            if addr == alice:
                self.assertFalse(acct.exists)
        with self.assertRaises(RpcError) as cm:
            c.call("eth_getProof", [self.vault, ["0x" + "ee" * 32], tag])
        self.assertEqual(cm.exception.code, fork_proxy.E_MISS)
        self.assertIn({"kind": "storage", "address": self.vault, "slot": "0x" + "ee" * 32}, h.misses())
        # account info, absent account, storage of an absent / empty-storage account
        info = c.call("eth_getAccountInfo", [self.vault, tag])
        self.assertEqual(info["balance"], bal)
        # raw protocol: batch, notification, junk, oversize
        import socket as so
        s = so.socket(so.AF_UNIX)
        s.connect(h.socket_path)
        batch = [{"jsonrpc": "2.0", "id": i, "method": "eth_chainId"} for i in range(3)] + \
                [{"jsonrpc": "2.0", "method": "eth_chainId"}, {"bad": 1}]
        s.sendall(json.dumps(batch).encode())
        resp = _read_json(s)
        self.assertEqual([x.get("id") for x in resp], [0, 1, 2, None])
        self.assertEqual(resp[3]["error"]["code"], fork_proxy.E_INVALID)
        s.sendall(b'{"jsonrpc":"2.0","method":"eth_chainId"}{"jsonrpc":"2.0","id":9,"method":"eth_chainId"}')
        self.assertEqual(_read_json(s)["id"], 9)  # the notification got no answer
        s.sendall(b"hello")
        self.assertEqual(_read_json(s)["error"]["code"], -32700)
        s.close()
        s = so.socket(so.AF_UNIX)
        s.connect(h.socket_path)
        try:  # oversize message: the server answers -32700 and drops the connection
            s.sendall(b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":["' + b"a" * (5 << 20))
            self.assertEqual(_read_json(s)["error"]["code"], -32700)
        except (BrokenPipeError, ConnectionResetError, AssertionError):
            pass
        s.close()
        self.assertEqual(c.call("eth_chainId", []), hex(31337))   # server still healthy
        c.close()
        self.assertGreaterEqual(h.stats()["framing_errors"], 2)

    def test_09_concurrency_and_speed(self):
        snap = self.build_v1()
        h = self.serve(snap, "bench.ipc")
        db = sqlite3.connect(os.path.join(snap, "state.sqlite"))
        rows = list(db.execute("SELECT address, slot, value FROM storage"))
        accts = [a for (a,) in db.execute("SELECT address FROM accounts")]
        db.close()
        tag = {"blockHash": self.pin_hash}
        errors = []
        per_thread = 2500
        threads_n = 8

        def worker(k):
            try:
                c = Client(h.socket_path, retries=0)
                for i in range(per_thread):
                    a, s, v = rows[(i * 7 + k) % len(rows)]
                    if int(c.call("eth_getStorageAt", [a, s, tag]), 16) != int(v, 16):
                        errors.append((a, s))
                    if i % 10 == 0:
                        c.call("eth_getAccountInfo", [accts[i % len(accts)], tag])
                c.close()
            except Exception as e:  # pragma: no cover
                errors.append(repr(e))

        t0 = time.time()
        ts = [threading.Thread(target=worker, args=(k,)) for k in range(threads_n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        dt = time.time() - t0
        n = threads_n * per_thread * 1.1
        self.assertEqual(errors, [])
        st = h.stats()
        log(f"speed: {int(n)} requests over {threads_n} connections in {dt:.2f}s = {n / dt:.0f} req/s "
            f"(server busy {st['busy_ms'] / n * 1000:.1f} us/request, max {st['max_request_ms']} ms); "
            f"open connections now {st['connections_open']}")
        # connection cap: extra connections are refused, the server stays healthy
        h2 = fork_proxy.serve(snap, self.path("cap.ipc"), expect_block_hash=self.pin_hash, max_connections=2)
        self.handles.append(h2)
        import socket as so
        held = []
        for _ in range(2):
            s = so.socket(so.AF_UNIX)
            s.connect(h2.socket_path)
            held.append(s)
        s3 = so.socket(so.AF_UNIX)
        s3.connect(h2.socket_path)
        s3.settimeout(5)
        try:
            s3.sendall(b'{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}')
            self.assertEqual(s3.recv(100), b"")  # closed without an answer
        except (BrokenPipeError, ConnectionResetError):
            pass
        for s in held:
            s.close()
        time.sleep(0.2)
        self.assertEqual(Client(h2.socket_path, retries=0).call("eth_chainId", []), hex(31337))
        self.assertGreaterEqual(h2.stats()["connections_rejected"], 1)

    def test_10_cli_serve_and_miss_file(self):
        snap = self.build_v1()
        sock, mf, sf = self.path("cli.ipc"), self.path("cli-misses.json"), self.path("cli-stats.json")
        proc = subprocess.Popen(PY + [PROXY_PY, "serve", "--snapshot", snap, "--socket", sock,
                                      "--expect-block-hash", self.pin_hash, "--miss-file", mf, "--stats-file", sf],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=clean_env(self.work))
        try:
            line = proc.stdout.readline()
            self.assertIn("serving", line, proc.stderr.read() if proc.poll() is not None else line)
            r = self.forge(sock, "OutsideRead")
            self.assertEqual(r["results"]["test_outside()"]["status"], "Failure")
            for _ in range(40):   # rewritten within MISS_WRITE_INTERVAL of a new miss, before shutdown
                with open(mf) as f:
                    doc = json.load(f)
                if doc["misses"]:
                    break
                time.sleep(0.1)
            self.assertEqual(doc["format"], fork_proxy.MISS_FORMAT)
            self.assertEqual(doc["misses"][0], {"kind": "account", "address": self.outside})
        finally:
            proc.send_signal(signal.SIGTERM)
            proc.wait(20)
        with open(sf) as f:
            st = json.load(f)
        self.assertGreater(st["stats"]["requests"], 0)
        self.assertFalse(os.path.exists(sock))

    def test_11_miss_cap(self):
        """A flood of misses (e.g. vm.rpc over random slots) is capped, flagged, and extend refuses it."""
        snap = self.build_v1()
        mf = self.path("flood-misses.json")
        h = self.serve(snap, "flood.ipc", miss_file=mf, max_misses=3)
        c = Client(h.socket_path, retries=0)
        for i in range(20):
            with self.assertRaises(RpcError):
                c.call("eth_getStorageAt", [self.vault, hex(10**6 + i), {"blockHash": self.pin_hash}])
        c.close()
        self.assertEqual(len(h.misses()), 3)
        self.assertTrue(h.stats()["misses_truncated"])
        self.assertEqual(h.stats()["miss_hits"], 20)
        h.close()
        with open(mf) as f:
            self.assertTrue(json.load(f)["truncated"])
        p = self.cli(SNAPSHOT_PY, "extend", "--snapshot", snap, "--misses", mf, "--upstream", self.chain.ipc,
                     "--out", self.path("flood-v2"), *self.chain_args(), ok=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("truncated", p.stderr)
        self.assertFalse(os.path.exists(self.path("flood-v2")))

    def test_12_fresh_accounts(self):
        """Fresh accounts of a runner job (state/fresh.py): absent without a miss, mapping slots derived from
        them read zero, the snapshot always wins, nothing else is answered, clearing restores misses, and a
        collect session answers them locally without recording or forwarding them."""
        from state import fresh
        snap = self.build_v1()
        h = self.serve(snap, "fresh.ipc")
        tag = {"blockHash": self.pin_hash}
        c = Client(h.socket_path, retries=0)
        f1 = to_hex(keccak(b"hyblis-test-fresh-1")[12:])
        f2 = to_hex(keccak(b"hyblis-test-fresh-2")[12:])
        mslot = lambda key, base: to_hex(keccak(bytes.fromhex(word(key) + word(base))))  # noqa: E731
        with self.assertRaises(RpcError):
            c.call("eth_getBalance", [f1, tag])
        with self.assertRaises(RpcError):
            c.call("eth_getStorageAt", [self.token, mslot(int(f1, 16), 0), tag])
        with self.assertRaises(ValueError):       # an address that exists at the pinned block is never fresh
            h.set_fresh([f1, EOA], keys=[f1])
        st = h.set_fresh([f1, f2], keys=[f1], partners=[self.vault, self.token])
        self.assertGreater(st["slots"], 0)
        self.assertEqual(c.call("eth_getBalance", [f1, tag]), "0x0")
        self.assertEqual(c.call("eth_getTransactionCount", [f2, tag]), "0x0")
        self.assertEqual(c.call("eth_getCode", [f2, tag]), "0x")
        self.assertEqual(int(c.call("eth_getStorageAt", [self.token, mslot(int(f1, 16), 0), tag]), 16), 0)
        self.assertEqual(int(c.call("eth_getStorageAt", [f2, "0x5", tag]), 16), 0)     # a fresh account's own storage
        allowance = to_hex(keccak(bytes.fromhex(word(self.vault)) + keccak(bytes.fromhex(word(int(f1, 16)) + word(1)))))
        self.assertEqual(int(c.call("eth_getStorageAt", [self.token, allowance, tag]), 16), 0)  # nested m[f1][vault]
        # the snapshot always wins (handler level, bypassing the guard): the vault forced into a fresh set keeps
        # its real ETH balance and its real token balance
        saved = h._handler.fresh
        h._handler.fresh = fresh.FreshSet([self.vault], keys=[self.vault])
        self.assertEqual(c.call("eth_getBalance", [self.vault, tag]), self.at_pin("eth_getBalance", self.vault))
        self.assertEqual(int(c.call("eth_getStorageAt", [self.token, mslot(int(self.vault, 16), 0), tag]), 16),
                         int(self.at_pin("eth_getStorageAt", self.token, mslot(int(self.vault, 16), 0)), 16))
        self.assertNotEqual(int(c.call("eth_getBalance", [self.vault, tag]), 16), 0)
        h._handler.fresh = saved
        # anything not derived from a fresh key is still a miss
        before = len(h.misses())
        with self.assertRaises(RpcError):
            c.call("eth_getStorageAt", [self.token, mslot(int(f1, 16), 10**9), tag])
        with self.assertRaises(RpcError):
            c.call("eth_getBalance", [to_hex(keccak(b"not fresh")[12:]), tag])
        self.assertEqual(len(h.misses()), before + 2)
        self.assertEqual(h.stats()["fresh_hits"], 6)    # the vault reads came from the snapshot
        h.clear_fresh()
        with self.assertRaises(RpcError):
            c.call("eth_getBalance", [f1, tag])
        c.close()
        h.close()
        s = store.load_snapshot(snap, expect_block_hash=self.pin_hash)
        try:
            self.assertIn(0, fresh.mapping_bases(s))    # the toy token's balance mapping
        finally:
            s.close()
        sess = snapshot.CollectSession(self.chain.ipc, 31337, self.pin, self.pin_hash, self.path("fresh-collect.ipc"))
        sess.set_fresh([f1], keys=[f1])
        cc = Client(sess.socket_path, retries=0)
        self.assertEqual(cc.call("eth_getBalance", [f1, tag]), "0x0")
        self.assertEqual(cc.call("eth_getBalance", [EOA, tag]), self.at_pin("eth_getBalance", EOA))
        cc.close()
        sess.close()
        acc, _ = sess.access()
        self.assertNotIn(f1, acc)
        self.assertIn(EOA, acc)
        log(f"fresh accounts: {st}")


def _set(d, k, v):
    d[k] = v
    return True


def _bump_storage(r):
    for sp in r["storageProof"]:
        if int(sp["value"], 16):
            sp["value"] = hex(int(sp["value"], 16) + 1)
            return True
    return False


def _flip_last(proof):
    n = bytearray(bytes.fromhex(proof[-1][2:]))
    n[len(n) // 2] ^= 1
    proof[-1] = "0x" + n.hex()
    return True


def _read_json(s):
    from state.jsonrpc import JsonStreamSplitter
    sp = JsonStreamSplitter(16 << 20)
    s.settimeout(10)
    while True:
        d = s.recv(1 << 16)
        if not d:
            raise AssertionError("connection closed")
        msgs = sp.feed(d)
        if msgs:
            return json.loads(msgs[0])


class Liar:
    """An upstream that forwards to anvil and corrupts selected answers (once per kind is enough)."""

    def __init__(self, upstream, mutate):
        self.c = Client(upstream)
        self.mutate = mutate
        self.mutated = 0

    def close(self):
        self.c.close()

    def handle_message(self, raw):
        req = json.loads(raw)
        try:
            res = self.c.call(req["method"], req.get("params", []))
        except RpcError as e:
            return json.dumps({"jsonrpc": "2.0", "id": req["id"], "error": {"code": e.code, "message": e.message}}).encode()
        out = self.mutate(req["method"], res) if res is not None else False
        if isinstance(out, str):
            res = out
        if out:
            self.mutated += 1
        return json.dumps({"jsonrpc": "2.0", "id": req["id"], "result": res}).encode()


if __name__ == "__main__":
    unittest.main()
