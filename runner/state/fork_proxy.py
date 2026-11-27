#!/usr/bin/env python3
"""Read-only fork proxy: serves forge's fork reads from a verified state snapshot over a Unix socket.

Python API::

    h = serve(snapshot_dir, socket_path, expect_block_hash=..., expect_chain_id=...)
    ...  # run forge with HYBLIS_ETH_RPC=<socket_path> and --no-storage-caching (or a fresh HOME)
    h.misses()   # [{"kind": "account", "address": ...}, {"kind": "storage", "address": ..., "slot": ...}, ...]
    h.refusals() # requests that can never be served (other blocks, write methods, ...)
    h.stats()
    h.write_misses(path)
    h.close()

CLI::

    fork_proxy.py serve --snapshot DIR --socket PATH [--task-manifest M | --expect-block-hash H]
                        [--miss-file misses.json] [--stats-file stats.json]

Answers only what Foundry 1.9.0 asks for when it forks a pinned block (established by experiment,
see README.md): eth_chainId, eth_getBlockByNumber / eth_getBlockByHash (headers only, pinned block
and its stored ancestors), eth_getBalance / eth_getTransactionCount / eth_getCode / eth_getAccountInfo
/ eth_getStorageAt / eth_getProof at the pinned block, plus net_version and web3_clientVersion.
Anything not in the snapshot is a JSON-RPC error and a recorded miss; nothing is ever guessed.
Every other method (anvil_*, evm_*, eth_send*, debug_*, eth_call, eth_blockNumber, ...) is refused.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from collections import Counter, OrderedDict

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import importlib
    importlib.import_module("state")
    __package__ = "state"  # noqa: A001

from . import mpt  # noqa: E402
from .jsonrpc import UnixRpcServer  # noqa: E402
from .mpt import EMPTY_CODE_HASH, EMPTY_TRIE_ROOT, ProofError, to_hex  # noqa: E402
from .store import Snapshot, SnapshotError, load_snapshot  # noqa: E402

CLIENT_VERSION = "hyblis-fork-proxy/1"
MISS_FORMAT = "hyblis-state-misses/1"

# JSON-RPC error codes. Chosen so that alloy's retry layer does NOT retry them (it retries 429,
# -32005, and messages containing "rate limit", "header not found", ...).
E_MISS = -32001          # state not in the snapshot (recorded as a miss; fixable by `snapshot.py extend`)
E_NOT_SERVED = -32002    # a block other than the pinned block / unknown block hash (never servable)
E_METHOD = -32601        # method not allowed
E_PARAMS = -32602        # invalid params
E_UPSTREAM = -32003      # collect mode only: the upstream failed
E_INVALID = -32600

SERVED_METHODS = (
    "eth_chainId", "net_version", "web3_clientVersion",
    "eth_getBlockByNumber", "eth_getBlockByHash",
    "eth_getBalance", "eth_getTransactionCount", "eth_getCode", "eth_getAccountInfo",
    "eth_getStorageAt", "eth_getProof",
)
MAX_BATCH = 1000
MAX_PROOF_SLOTS = 1000


class RpcFail(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


class Miss(Exception):
    def __init__(self, items: list[dict]):
        super().__init__("miss")
        self.items = items


# ----------------------------------------------------------------------------------------------
# backends
# ----------------------------------------------------------------------------------------------

class SnapshotBackend:
    """Answers from a loaded, verified snapshot. Returns None for anything not in it."""

    def __init__(self, snap: Snapshot):
        self.snap = snap
        m = snap.manifest
        self.chain_id = m["chain_id"]
        self.block_number = m["block_number"]
        self.block_hash = m["block_hash"]
        self.digest = m["digest"]
        c = snap.conn
        self._headers_by_number = {n: bytes(r) for n, _, r in c.execute("SELECT number, hash, rlp FROM headers")}
        self._headers_by_hash = {h: n for n, h, _ in c.execute("SELECT number, hash, rlp FROM headers")}
        self._q_acct = 'SELECT "exists", nonce, balance, code_hash, storage_root, code FROM accounts WHERE address = ?'
        self._q_slot = "SELECT value FROM storage WHERE address = ? AND slot = ?"
        self._q_node = "SELECT rlp FROM trie_nodes WHERE hash = ?"
        self._lock = threading.Lock()   # sqlite connection shared by the event loop thread only; lock = safety

    def account(self, address: str):
        with self._lock:
            row = self.snap.conn.execute(self._q_acct, (address,)).fetchone()
        if row is None:
            return None
        ex, nonce, bal, ch, sr, code = row
        return {"exists": bool(ex), "nonce": int(nonce, 16), "balance": int(bal, 16),
                "code_hash": ch, "storage_root": sr, "code": bytes(code)}

    def has_account(self, address: str) -> bool:
        return self.account(address) is not None

    def has_slot(self, address: str, slot: str) -> bool:
        return self.storage(address, slot) is not None

    def storage(self, address: str, slot: str):
        """int value, or None if not in the snapshot. Absent accounts and empty storage roots give 0."""
        acct = self.account(address)
        if acct is None:
            return None
        if not acct["exists"] or acct["storage_root"] == to_hex(EMPTY_TRIE_ROOT):
            return 0
        with self._lock:
            row = self.snap.conn.execute(self._q_slot, (address, slot)).fetchone()
        return None if row is None else int(row[0], 16)

    def header_by_number(self, n: int):
        return self._headers_by_number.get(n)

    def header_by_hash(self, h: str):
        n = self._headers_by_hash.get(h)
        return None if n is None else self._headers_by_number[n]

    def _node(self, h: bytes) -> bytes:
        with self._lock:
            row = self.snap.conn.execute(self._q_node, (to_hex(h),)).fetchone()
        if row is None:
            raise ProofError("node missing")
        return bytes(row[0])

    def proof(self, address: str, slots: list[str]):
        """eth_getProof result rebuilt from the stored trie nodes, or raise Miss."""
        acct = self.account(address)
        missing = []
        if acct is None:
            missing.append({"kind": "account", "address": address})
            missing.extend({"kind": "storage", "address": address, "slot": s} for s in slots)
            raise Miss(missing)
        values = {}
        for s in slots:
            v = self.storage(address, s)
            if v is None:
                missing.append({"kind": "storage", "address": address, "slot": s})
            values[s] = v
        if missing:
            raise Miss(missing)
        state_root = mpt.from_hex(self.snap.manifest["state_root"], 32)
        acct_nodes: list[bytes] = []
        mpt.walk(state_root, mpt.address_key(address), self._node, on_node=lambda h, r: acct_nodes.append(r))
        sroot = mpt.from_hex(acct["storage_root"], 32)
        sp = []
        for s in slots:
            nodes: list[bytes] = []
            if acct["exists"]:
                mpt.walk(sroot, mpt.slot_key(s), self._node, on_node=lambda h, r, nodes=nodes: nodes.append(r))
            sp.append({"key": s, "value": hex(values[s]), "proof": [to_hex(x) for x in nodes]})
        return {"address": address, "balance": hex(acct["balance"]), "nonce": hex(acct["nonce"]),
                "codeHash": acct["code_hash"], "storageHash": acct["storage_root"],
                "accountProof": [to_hex(x) for x in acct_nodes], "storageProof": sp}


# ----------------------------------------------------------------------------------------------
# the request handler (shared with `snapshot.py collect`, so both modes answer identically)
# ----------------------------------------------------------------------------------------------

class Recorder:
    """Thread-safe record of misses, refusals and counters. Bounded."""

    def __init__(self, max_misses: int = 10_000, max_refusals: int = 1000, on_new_miss=None):
        self._lock = threading.Lock()
        self._misses: OrderedDict = OrderedDict()
        self._refusals: OrderedDict = OrderedDict()
        self.max_misses, self.max_refusals = max_misses, max_refusals
        self.misses_truncated = False
        self.miss_hits = 0
        self.refusal_hits = 0
        self.on_new_miss = on_new_miss

    def miss(self, item: dict) -> None:
        key = tuple(sorted(item.items()))
        new = False
        with self._lock:
            self.miss_hits += 1
            if key not in self._misses:
                if len(self._misses) < self.max_misses:
                    self._misses[key] = dict(item)
                    new = True
                else:
                    self.misses_truncated = True
        if new and self.on_new_miss:
            self.on_new_miss()

    def refuse(self, method: str, reason: str) -> None:
        key = (method, reason)
        with self._lock:
            self.refusal_hits += 1
            if key in self._refusals:
                self._refusals[key]["count"] += 1
            elif len(self._refusals) < self.max_refusals:
                self._refusals[key] = {"method": method, "reason": reason, "count": 1}

    def misses(self) -> list[dict]:
        with self._lock:
            return [dict(v) for v in self._misses.values()]

    def refusals(self) -> list[dict]:
        with self._lock:
            return [dict(v) for v in self._refusals.values()]

    # access recording (collect mode); the snapshot proxy ignores these
    def access_account(self, address: str) -> None:
        pass

    def access_storage(self, address: str, slot: str) -> None:
        pass

    def access_block(self, number: int) -> None:
        pass


class RpcHandler:
    """JSON-RPC semantics of the fork proxy. ``backend`` provides account/storage/header/proof."""

    def __init__(self, backend, recorder: Recorder):
        self.b = backend
        self.rec = recorder
        self.pinned_number = backend.block_number
        self.pinned_hash = backend.block_hash.lower()
        self.chain_id = backend.chain_id
        self.started = time.time()
        self._lock = threading.Lock()
        self.by_method: Counter = Counter()
        self.requests = 0
        self.batches = 0
        self.errors = 0
        self.busy_s = 0.0
        self.max_ms = 0.0
        self.fresh = None            # fresh.FreshSet of the current job (runner-registered), or None
        self.fresh_hits = 0

    # -- framing level --
    def handle_message(self, raw: bytes) -> bytes | None:
        t0 = time.perf_counter()
        try:
            msg = json.loads(raw)
        except ValueError:
            return _dump({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
        if isinstance(msg, list):
            with self._lock:
                self.batches += 1
            if not msg or len(msg) > MAX_BATCH:
                out = {"jsonrpc": "2.0", "id": None, "error": {"code": E_INVALID, "message": "bad batch size"}}
            else:
                out = [r for m in msg for r in [self.handle(m)] if not _is_notification(m)]
                if not out:
                    out = None
        else:
            out = self.handle(msg)
            if _is_notification(msg):
                out = None  # a valid notification is never answered, not even with an error
        dt = time.perf_counter() - t0
        with self._lock:
            self.busy_s += dt
            self.max_ms = max(self.max_ms, dt * 1000)
        return None if out is None else _dump(out)

    def handle(self, req) -> dict | None:
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or not isinstance(req.get("method"), str):
            return {"jsonrpc": "2.0", "id": req.get("id") if isinstance(req, dict) else None,
                    "error": {"code": E_INVALID, "message": "invalid request"}}
        rid = req.get("id")
        method = req["method"]
        params = req.get("params", [])
        with self._lock:
            self.requests += 1
            self.by_method[method if method in SERVED_METHODS else "(refused)"] += 1
        try:
            if method not in SERVED_METHODS:
                self.rec.refuse(method[:64], "method not allowed")
                raise RpcFail(E_METHOD, f"hyblis-fork-proxy: method {method[:64]} is not allowed (read-only, pinned block)")
            if not isinstance(params, list):
                raise RpcFail(E_PARAMS, "params must be a list")
            result = getattr(self, "_m_" + method)(params)
        except Miss as m:
            for item in m.items:
                self.rec.miss(item)
            with self._lock:
                self.errors += 1
            what = ", ".join(_miss_text(i) for i in m.items[:3])
            return _err(rid, E_MISS, f"hyblis-state-miss: not in snapshot: {what}")
        except RpcFail as e:
            with self._lock:
                self.errors += 1
            return _err(rid, e.code, e.message)
        except ProofError as e:
            with self._lock:
                self.errors += 1
            return _err(rid, E_PARAMS, f"invalid params: {e}")
        except (TypeError, ValueError, KeyError, IndexError, AttributeError, ArithmeticError) as e:
            with self._lock:
                self.errors += 1
            return _err(rid, E_PARAMS, f"invalid params ({type(e).__name__})")
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    # -- parameter helpers --
    def _block_param(self, method: str, p) -> None:
        """State reads are served only at the pinned block (by number, EIP-1898 hash or number object)."""
        ok = False
        what = repr(p)[:80]
        if isinstance(p, str) and p.startswith(("0x", "0X")):
            ok = mpt.parse_quantity(p, "block") == self.pinned_number
        elif isinstance(p, dict) and set(p) <= {"blockHash", "requireCanonical"} and "blockHash" in p:
            ok = mpt.norm_hash(p["blockHash"]) == self.pinned_hash
        elif isinstance(p, dict) and set(p) == {"blockNumber"}:
            ok = mpt.parse_quantity(p["blockNumber"], "block") == self.pinned_number
        if not ok:
            self.rec.refuse(method, f"block {what} is not the pinned block")
            raise RpcFail(E_NOT_SERVED, f"hyblis-fork-proxy: only block {self.pinned_number} ({self.pinned_hash}) is served")

    @staticmethod
    def _n(params, lo, hi):
        if not (lo <= len(params) <= hi):
            raise RpcFail(E_PARAMS, f"expected {lo}..{hi} params")

    def _fresh_account(self, address: str) -> bool:
        """A fresh account of the current job that the backend does not hold (see state/fresh.py)."""
        fs = self.fresh
        if fs is None or not fs.has_account(address) or self.b.has_account(address):
            return False
        with self._lock:
            self.fresh_hits += 1
        return True

    def _fresh_slot(self, address: str, slot: str) -> bool:
        fs = self.fresh
        if fs is None or not (fs.has_account(address) or fs.has_slot(slot)) or self.b.has_slot(address, slot):
            return False
        with self._lock:
            self.fresh_hits += 1
        return True

    def _account(self, address: str) -> dict:
        if self._fresh_account(address):
            return {"exists": False, "nonce": 0, "balance": 0, "code_hash": to_hex(EMPTY_CODE_HASH),
                    "storage_root": to_hex(EMPTY_TRIE_ROOT), "code": b""}
        self.rec.access_account(address)
        a = self.b.account(address)
        if a is None:
            raise Miss([{"kind": "account", "address": address}])
        return a

    def _block_obj(self, enc: bytes) -> dict:
        h = mpt.decode_header(enc)
        h["transactions"] = []
        h["uncles"] = []
        return h

    # -- methods --
    def _m_eth_chainId(self, params):
        return hex(self.chain_id)

    def _m_net_version(self, params):
        return str(self.chain_id)

    def _m_web3_clientVersion(self, params):
        return CLIENT_VERSION

    def _full_flag(self, method, params):
        full = params[1] if len(params) > 1 else False
        if full is not False:
            self.rec.refuse(method, "full transaction bodies are not served")
            raise RpcFail(E_NOT_SERVED, "hyblis-fork-proxy: only headers are served (full=false)")

    def _m_eth_getBlockByNumber(self, params):
        self._n(params, 1, 2)
        self._full_flag("eth_getBlockByNumber", params)
        p = params[0]
        if not (isinstance(p, str) and p.startswith(("0x", "0X"))):
            self.rec.refuse("eth_getBlockByNumber", f"block tag {str(p)[:20]}")
            raise RpcFail(E_NOT_SERVED, "hyblis-fork-proxy: block tags are not served; ask for the pinned number")
        n = mpt.parse_quantity(p, "block")
        if n > self.pinned_number:
            self.rec.refuse("eth_getBlockByNumber", "block above the pinned block")
            raise RpcFail(E_NOT_SERVED, f"hyblis-fork-proxy: block {n} is after the pinned block")
        self.rec.access_block(n)
        enc = self.b.header_by_number(n)
        if enc is None:
            raise Miss([{"kind": "block", "number": n}])
        return self._block_obj(enc)

    def _m_eth_getBlockByHash(self, params):
        self._n(params, 1, 2)
        self._full_flag("eth_getBlockByHash", params)
        h = mpt.norm_hash(params[0])
        enc = self.b.header_by_hash(h)
        if enc is None:
            self.rec.refuse("eth_getBlockByHash", "unknown block hash")
            raise RpcFail(E_NOT_SERVED, "hyblis-fork-proxy: unknown block hash (only the pinned block and its stored ancestors)")
        self.rec.access_block(mpt.parse_quantity(mpt.decode_header(enc)["number"]))
        return self._block_obj(enc)

    def _m_eth_getBalance(self, params):
        self._n(params, 2, 2)
        a = mpt.norm_address(params[0])
        self._block_param("eth_getBalance", params[1])
        return hex(self._account(a)["balance"])

    def _m_eth_getTransactionCount(self, params):
        self._n(params, 2, 2)
        a = mpt.norm_address(params[0])
        self._block_param("eth_getTransactionCount", params[1])
        return hex(self._account(a)["nonce"])

    def _m_eth_getCode(self, params):
        self._n(params, 2, 2)
        a = mpt.norm_address(params[0])
        self._block_param("eth_getCode", params[1])
        return to_hex(self._account(a)["code"])

    def _m_eth_getAccountInfo(self, params):
        self._n(params, 2, 2)
        a = mpt.norm_address(params[0])
        self._block_param("eth_getAccountInfo", params[1])
        acct = self._account(a)
        return {"balance": hex(acct["balance"]), "nonce": hex(acct["nonce"]), "code": to_hex(acct["code"])}

    def _m_eth_getStorageAt(self, params):
        self._n(params, 3, 3)
        a = mpt.norm_address(params[0])
        s = mpt.norm_slot(params[1])
        self._block_param("eth_getStorageAt", params[2])
        if self._fresh_slot(a, s):
            return "0x" + "00" * 32
        self.rec.access_storage(a, s)
        v = self.b.storage(a, s)
        if v is None:
            raise Miss([{"kind": "storage", "address": a, "slot": s}])
        return "0x" + v.to_bytes(32, "big").hex()

    def _m_eth_getProof(self, params):
        self._n(params, 3, 3)
        a = mpt.norm_address(params[0])
        if not isinstance(params[1], list) or len(params[1]) > MAX_PROOF_SLOTS:
            raise RpcFail(E_PARAMS, "storage keys must be a list (max 1000)")
        slots = [mpt.norm_slot(s) for s in params[1]]
        self._block_param("eth_getProof", params[2])
        self.rec.access_account(a)
        for s in slots:
            self.rec.access_storage(a, s)
        return self.b.proof(a, slots)

    def stats(self) -> dict:
        with self._lock:
            return {"requests": self.requests, "batches": self.batches, "errors": self.errors,
                    "fresh_hits": self.fresh_hits,
                    "by_method": dict(sorted(self.by_method.items())),
                    "busy_ms": round(self.busy_s * 1000, 3), "max_request_ms": round(self.max_ms, 3),
                    "uptime_s": round(time.time() - self.started, 3)}


def _miss_text(i: dict) -> str:
    if i["kind"] == "storage":
        return f"storage {i['address']}[{i['slot']}]"
    if i["kind"] == "account":
        return f"account {i['address']}"
    return f"block {i.get('number', i.get('hash'))}"


def _is_notification(m) -> bool:
    return isinstance(m, dict) and "id" not in m and m.get("jsonrpc") == "2.0" and isinstance(m.get("method"), str)


def _err(rid, code, message) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def _dump(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode()


# ----------------------------------------------------------------------------------------------
# public API
# ----------------------------------------------------------------------------------------------

class ProxyHandle:
    def __init__(self, server: UnixRpcServer, handler: RpcHandler, recorder: Recorder, snap: Snapshot | None,
                 miss_file: str | None = None):
        self._server, self._handler, self._rec, self._snap = server, handler, recorder, snap
        self.socket_path = server.socket_path
        self.miss_file = miss_file
        self._wlock = threading.Lock()
        self._closed = False
        self._last_write = 0.0
        self._dirty = False
        self._timer: threading.Timer | None = None

    MISS_WRITE_INTERVAL = 0.5   # seconds; a PoC looping vm.rpc over random slots cannot force O(n^2) rewrites

    def _miss_changed(self) -> None:
        """Called on each new unique miss: rewrite the miss file at most every MISS_WRITE_INTERVAL."""
        with self._wlock:
            self._dirty = True
            wait = self._last_write + self.MISS_WRITE_INTERVAL - time.monotonic()
            if wait > 0:
                if self._timer is None:
                    self._timer = threading.Timer(wait, self._flush)
                    self._timer.daemon = True
                    self._timer.start()
                return
        self._flush()

    def _flush(self) -> None:
        with self._wlock:
            self._timer = None
            if not self._dirty:
                return
        self.write_misses()

    @property
    def digest(self) -> str | None:
        return self._snap.digest if self._snap else None

    def set_fresh(self, accounts, keys=(), partners=(), label: str = "") -> dict:
        """Register the current job's fresh accounts (runner-derived from the job's secret; see
        state/fresh.py). Replaces any earlier registration. Returns the FreshSet's stats."""
        from .fresh import FreshSet, mapping_bases
        backend = self._handler.b
        real = [a for a in accounts if (row := backend.account(a.lower())) is not None and row["exists"]]
        if real:   # a fresh address cannot exist at the pinned block: a runner bug, never answer for it
            raise ValueError(f"set_fresh: {len(real)} address(es) exist in the snapshot, e.g. {real[0]}")
        bases = mapping_bases(self._snap) if self._snap is not None else []
        fs = FreshSet(accounts, keys, partners, bases, label=label)
        self._handler.fresh = fs
        out = dict(fs.stats)
        out["discovery"] = dict(getattr(mapping_bases, "last_stats", {}) or {})
        return out

    def clear_fresh(self) -> None:
        self._handler.fresh = None

    def misses(self) -> list[dict]:
        """Unique misses in first-seen order: {"kind": "account", "address"} |
        {"kind": "storage", "address", "slot"} | {"kind": "block", "number"}."""
        return self._rec.misses()

    def refusals(self) -> list[dict]:
        """Requests that can never be served: [{"method", "reason", "count"}]."""
        return self._rec.refusals()

    def miss_document(self) -> dict:
        h = self._handler
        return {"format": MISS_FORMAT, "snapshot_digest": self.digest, "chain_id": h.chain_id,
                "block_number": h.pinned_number, "block_hash": h.pinned_hash,
                "misses": self.misses(), "truncated": self._rec.misses_truncated}

    def write_misses(self, path: str | None = None) -> str:
        path = path or self.miss_file
        if not path:
            raise ValueError("no miss file path")
        with self._wlock:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.miss_document(), f, indent=1, sort_keys=True)
                f.write("\n")
            os.replace(tmp, path)
            self._last_write = time.monotonic()
            self._dirty = False
        return path

    def stats(self) -> dict:
        s = self._handler.stats()
        s.update({"misses": len(self._rec.misses()), "miss_hits": self._rec.miss_hits,
                  "misses_truncated": self._rec.misses_truncated,
                  "refusals": self._rec.refusal_hits,
                  "connections_total": self._server.conn_total, "connections_open": self._server.open_connections,
                  "connections_rejected": self._server.conn_rejected, "framing_errors": self._server.framing_errors,
                  "bytes_in": self._server.bytes_in, "bytes_out": self._server.bytes_out,
                  "snapshot_digest": self.digest, "block_number": self._handler.pinned_number})
        return s

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._server.close()
        with self._wlock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        if self.miss_file:
            self.write_misses()
        if self._snap is not None:
            self._snap.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def serve(snapshot_dir: str, socket_path: str, *, expect_block_hash: str | None = None,
          expect_chain_id: int | None = None, expect_digest: str | None = None, miss_file: str | None = None,
          max_connections: int = 64, socket_mode: int = 0o660, max_misses: int = 10_000) -> ProxyHandle:
    """Verify ``snapshot_dir`` completely, then serve it read-only on ``socket_path``.

    Raises SnapshotError if the snapshot does not verify (nothing is served)."""
    snap = load_snapshot(snapshot_dir, expect_block_hash=expect_block_hash, expect_chain_id=expect_chain_id,
                         expect_digest=expect_digest)
    try:
        backend = SnapshotBackend(snap)
        handle_ref: list[ProxyHandle] = []
        rec = Recorder(max_misses=max_misses,
                       on_new_miss=(lambda: handle_ref[0]._miss_changed()) if miss_file else None)
        handler = RpcHandler(backend, rec)
        server = UnixRpcServer(socket_path, handler, max_connections=max_connections, socket_mode=socket_mode)
        handle = ProxyHandle(server, handler, rec, snap, miss_file)
        handle_ref.append(handle)
        if miss_file:
            handle.write_misses()
        server.start()
    except BaseException:
        snap.close()
        raise
    return handle


def _task_chain(path: str) -> tuple[int, int, str]:
    with open(path) as f:
        ch = json.load(f)["chain"]
    return int(ch["chain_id"]), int(ch["fork_block"]), ch["fork_block_hash"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="serve a snapshot on a Unix socket until SIGINT/SIGTERM")
    s.add_argument("--snapshot", required=True)
    s.add_argument("--socket", required=True)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--task-manifest", help="tasks/<id>/manifest.json (chain.fork_block_hash is the trust anchor)")
    g.add_argument("--expect-block-hash")
    s.add_argument("--expect-digest")
    s.add_argument("--miss-file", help="miss list JSON, rewritten on every new miss and at exit")
    s.add_argument("--stats-file", help="stats JSON written at exit")
    s.add_argument("--max-connections", type=int, default=64)
    a = ap.parse_args(argv)
    chain_id = None
    block_hash = a.expect_block_hash
    if a.task_manifest:
        chain_id, _, block_hash = _task_chain(a.task_manifest)
    try:
        h = serve(a.snapshot, a.socket, expect_block_hash=block_hash, expect_chain_id=chain_id,
                  expect_digest=a.expect_digest, miss_file=a.miss_file, max_connections=a.max_connections)
    except SnapshotError as e:
        print(f"fork_proxy: snapshot refused: {e}", file=sys.stderr)
        return 2
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    print(json.dumps({"serving": h.socket_path, "digest": h.digest}), flush=True)
    stop.wait()
    h.close()
    st = h.stats()
    if a.stats_file:
        with open(a.stats_file, "w") as f:
            json.dump({"stats": st, "refusals": h.refusals()}, f, indent=1, sort_keys=True)
    print(json.dumps({"stopped": True, "misses": st["misses"], "requests": st["requests"]}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
