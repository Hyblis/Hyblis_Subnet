#!/usr/bin/env python3
"""Operator-side tools for per-program verified state snapshots (owner decision: option B).

  collect   recording JSON-RPC proxy in front of an upstream RPC. Run ONLY Hyblis-owned code through it
            (the program's PoC template, Hyblis controls, spec self-checks), never a miner's PoC.
            It answers exactly like the runner's fork proxy and writes an access list.
  build     fetch every account in one or more access lists with eth_getProof (all its slots in the
            same call, chunked), plus eth_getCode, the pinned header and its ancestors; verify all of
            it against the pinned block hash; write the snapshot.
  extend    add the items of a runner job's miss list (fetched and verified the same way) and write a
            new snapshot version (new digest).
  verify    re-verify a snapshot offline against the pinned block hash.
  info      print a snapshot's manifest summary.

The pinned block hash is the only trust anchor; pass --task-manifest tasks/<id>/manifest.json
(chain.chain_id, chain.fork_block, chain.fork_block_hash) or the three values explicitly.
The upstream may be an http(s) URL or a Unix-socket path. Only its host is written to the manifest.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import importlib
    importlib.import_module("state")
    __package__ = "state"  # noqa: A001

import rlp  # noqa: E402

from . import mpt  # noqa: E402
from .fork_proxy import MISS_FORMAT, Recorder, RpcFail, RpcHandler, E_UPSTREAM  # noqa: E402
from .jsonrpc import Client, RpcError, TransportError, UnixRpcServer, endpoint_label  # noqa: E402
from .mpt import EMPTY_CODE_HASH, ProofError, from_hex, keccak, norm_address, norm_slot, to_hex  # noqa: E402
from .store import Content, SnapshotError, load_content, load_snapshot, write_snapshot  # noqa: E402

ACCESS_FORMAT = "hyblis-access-list/1"
DEFAULT_ANCESTORS = 256
PROOF_CHUNK = 256

HISTORY_CONTRACT = "0x0000f90827f1c53a10cb7a02335b175320002935"   # EIP-2935 (Prague)
HISTORY_RING = 8191
BEACON_ROOTS = "0x000f3df6d732807ef1319fb7b8bb8522d0beac02"       # EIP-4788 (Cancun)
FOUNDRY_TEST_CONTRACT = "0x7fa9385be102ac3eac297483dd6233d62b3e1496"
FOUNDRY_DEFAULT_SENDER = "0x1804c8ab1f12e6bbf3894d4083f33e07309d1f38"
CHEATCODES = "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d"
CHEATCODES_FAILED_SLOT = "0x" + b"failed".hex() + "00" * 26   # forge-std reads it on every test
CONSOLE = "0x000000000000000000636f6e736f6c652e6c6f67"
CREATE2_DEPLOYER = "0x4e59b44847b379578588920ca78fbf26c0b4956c"
HYBLIS_FAUCET = "0x" + keccak(b"hyblis.faucet")[-20:].hex()     # etched by the runner harness (fixed address)
# Verified prefetch for a contract that first enters a snapshot: low slots and the EIP-1967 slots,
# and the implementation/beacon account they point to. Generic slots: reveals nothing new to the RPC.
EIP1967_IMPL = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
EIP1967_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
PREFETCH_SLOTS = frozenset([norm_slot(hex(i)) for i in range(32)] + [EIP1967_IMPL, EIP1967_ADMIN, EIP1967_BEACON])
# makeAddr(label) accounts researchers commonly create; proven absent/present so they do not miss
MAKEADDR_LABELS = [
    "attacker", "alice", "bob", "carol", "charlie", "dave", "eve", "frank", "user", "user1", "user2", "user3",
    "victim", "hacker", "exploiter", "owner", "admin", "whale", "depositor", "borrower", "lender",
    "liquidator", "receiver", "recipient", "treasury", "keeper", "feeRecipient", "minter", "staker",
    "trader", "deployer", "sender", "beneficiary", "operator", "malicious", "random", "someone", "test",
]


# ----------------------------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------------------------

# How far below the pinned block an extend may fetch headers (the EIP-2935 history window).
HEADER_WINDOW = 8191

def create_address(sender: str, nonce: int) -> str:
    return to_hex(keccak(rlp.encode([from_hex(sender, 20), nonce]))[12:])


def make_addr(label: str) -> str:
    """forge-std makeAddr(label): vm.addr(uint256(keccak256(bytes(label))))."""
    from eth_keys import keys  # in the venv; only needed for the defaults list
    return "0x" + keys.PrivateKey(keccak(label.encode())).public_key.to_canonical_address().hex()


def forge_default_targets() -> dict[str, set[str]]:
    """Accounts Foundry touches in almost every fork test, plus common makeAddr actors and the
    contracts they deploy first. All of them reveal nothing about a finding."""
    t: dict[str, set[str]] = {}
    add = lambda a, *s: t.setdefault(norm_address(a), set()).update(norm_slot(x) for x in s)  # noqa: E731
    for a in (FOUNDRY_TEST_CONTRACT, FOUNDRY_DEFAULT_SENDER, CONSOLE, CREATE2_DEPLOYER, HISTORY_CONTRACT,
              BEACON_ROOTS, HYBLIS_FAUCET, "0x" + "00" * 20):
        add(a)
    add(CHEATCODES, CHEATCODES_FAILED_SLOT)
    for i in list(range(1, 0x12)) + [0x100]:  # precompiles
        add("0x" + i.to_bytes(20, "big").hex())
    for n in range(1, 17):
        add(create_address(FOUNDRY_TEST_CONTRACT, n))
    for n in range(0, 4):
        add(create_address(FOUNDRY_DEFAULT_SENDER, n))
    for label in MAKEADDR_LABELS:
        a = make_addr(label)
        add(a)
        for n in range(0, 2):
            add(create_address(a, n))
    return t


def _chain_args(a) -> tuple[int, int, str]:
    if a.task_manifest:
        with open(a.task_manifest) as f:
            ch = json.load(f)["chain"]
        return int(ch["chain_id"]), int(ch["fork_block"]), mpt.norm_hash(ch["fork_block_hash"])
    if a.chain_id is None or a.block is None or not a.expect_block_hash:
        raise SystemExit("give --task-manifest, or all of --chain-id, --block and --expect-block-hash")
    return int(a.chain_id), int(a.block), mpt.norm_hash(a.expect_block_hash)


def _log(msg: str) -> None:
    print(f"[state] {msg}", file=sys.stderr, flush=True)


def check_upstream(client: Client, chain_id: int, number: int, block_hash: str) -> tuple[dict, bytes]:
    """The upstream must be on the right chain and have the pinned block. Returns (block, header rlp)."""
    got = mpt.parse_quantity(client.call("eth_chainId", []), "chain id")
    if got != chain_id:
        raise SystemExit(f"upstream chain id {got} != expected {chain_id}")
    blk = client.call("eth_getBlockByNumber", [hex(number), False])
    if not isinstance(blk, dict):
        raise SystemExit(f"upstream does not have block {number}")
    enc = mpt.verify_header(blk, block_hash)
    if mpt.parse_quantity(blk["number"], "number") != number:
        raise ProofError("pinned header has the wrong number")
    return blk, enc


# ----------------------------------------------------------------------------------------------
# collect
# ----------------------------------------------------------------------------------------------

class AccessRecorder(Recorder):
    def __init__(self):
        super().__init__()
        self.accounts: dict[str, set[str]] = {}
        self.blocks: set[int] = set()
        self._alock = threading.Lock()

    def access_account(self, address: str) -> None:
        with self._alock:
            self.accounts.setdefault(address, set())

    def access_storage(self, address: str, slot: str) -> None:
        with self._alock:
            self.accounts.setdefault(address, set()).add(slot)

    def access_block(self, number: int) -> None:
        with self._alock:
            self.blocks.add(number)


class UpstreamBackend:
    """collect mode: the same questions as SnapshotBackend, answered by the upstream at the pinned block.
    Values are not proof-checked here (build does that); answers are cached so a session is consistent."""

    def __init__(self, client: Client, chain_id: int, number: int, block_hash: str, pinned_rlp: bytes):
        self.c = client
        self.chain_id, self.block_number, self.block_hash = chain_id, number, block_hash
        self.tag = hex(number)
        self._acct: dict[str, dict] = {}
        self._slot: dict[tuple[str, str], int] = {}
        self._hdr_n: dict[int, bytes] = {number: pinned_rlp}
        self._hdr_h: dict[str, bytes] = {block_hash: pinned_rlp}

    def _call(self, method, params):
        try:
            return self.c.call(method, params)
        except (RpcError, TransportError) as e:
            raise RpcFail(E_UPSTREAM, f"upstream {method} failed: {e}") from None

    def account(self, address: str):
        a = self._acct.get(address)
        if a is None:
            bal = mpt.parse_quantity(self._call("eth_getBalance", [address, self.tag]))
            nonce = mpt.parse_quantity(self._call("eth_getTransactionCount", [address, self.tag]))
            code = from_hex(self._call("eth_getCode", [address, self.tag]))
            a = {"exists": True, "nonce": nonce, "balance": bal, "code": code,
                 "code_hash": to_hex(keccak(code)), "storage_root": None}
            self._acct[address] = a
        return a

    def has_account(self, address: str) -> bool:
        return False          # nothing is local: a fresh account is never sent upstream

    def has_slot(self, address: str, slot: str) -> bool:
        return False

    def storage(self, address: str, slot: str):
        k = (address, slot)
        if k not in self._slot:
            self._slot[k] = mpt.parse_quantity(self._call("eth_getStorageAt", [address, slot, self.tag]))
        return self._slot[k]

    def header_by_number(self, n: int):
        if n not in self._hdr_n:
            blk = self._call("eth_getBlockByNumber", [hex(n), False])
            if not isinstance(blk, dict):
                return None
            enc = mpt.verify_header(blk, blk.get("hash", ""))
            self._hdr_n[n] = enc
            self._hdr_h[to_hex(keccak(enc))] = enc
        return self._hdr_n[n]

    def header_by_hash(self, h: str):
        if h not in self._hdr_h:
            blk = self._call("eth_getBlockByHash", [h, False])
            if not isinstance(blk, dict):
                return None
            enc = mpt.verify_header(blk, h)
            if mpt.parse_quantity(blk["number"]) > self.block_number:
                return None
            self._hdr_h[h] = enc
            self._hdr_n[mpt.parse_quantity(blk["number"])] = enc
        return self._hdr_h[h]

    def proof(self, address: str, slots: list[str]):
        return self._call("eth_getProof", [address, slots, self.tag])


def access_document(chain_id, number, block_hash, accounts: dict[str, set[str]], blocks, refusals=None,
                    requests=None) -> dict:
    return {"format": ACCESS_FORMAT, "chain_id": chain_id, "block_number": number, "block_hash": block_hash,
            "accounts": {a: sorted(accounts[a]) for a in sorted(accounts)},
            "blocks": sorted(blocks), "refusals": refusals or [], "requests": requests or {}}


def read_targets(paths: list[str], chain_id: int, number: int, block_hash: str
                 ) -> tuple[dict[str, set[str]], set[int]]:
    """Union of access lists and miss lists -> ({address: slots}, {block numbers})."""
    accounts: dict[str, set[str]] = {}
    blocks: set[int] = set()
    for p in paths:
        with open(p) as f:
            d = json.load(f)
        if d.get("block_number") != number or mpt.norm_hash(d.get("block_hash", "0x" + "00" * 32)) != block_hash \
                or d.get("chain_id") != chain_id:
            raise SystemExit(f"{p}: recorded for a different chain/block")
        if d.get("format") == ACCESS_FORMAT:
            for a, slots in d["accounts"].items():
                accounts.setdefault(norm_address(a), set()).update(norm_slot(s) for s in slots)
            blocks.update(int(b) for b in d.get("blocks", []))
        elif d.get("format") == MISS_FORMAT:
            if d.get("truncated"):
                raise SystemExit(f"{p}: miss list was truncated at the proxy's cap; review the job before extending")
            for m in d["misses"]:
                if m["kind"] == "account":
                    accounts.setdefault(norm_address(m["address"]), set())
                elif m["kind"] == "storage":
                    accounts.setdefault(norm_address(m["address"]), set()).add(norm_slot(m["slot"]))
                elif m["kind"] == "block" and "number" in m:
                    blocks.add(int(m["number"]))
                else:
                    raise SystemExit(f"{p}: unknown miss {m!r:.100}")
        else:
            raise SystemExit(f"{p}: unknown format {d.get('format')!r}")
    return accounts, blocks


class PrefilledBackend(UpstreamBackend):
    """collect mode over a verified snapshot of the same block: items the snapshot holds are answered from
    it (proven values); everything else comes from the upstream, as in plain collect. The access recorder
    still records every item, so the access list is complete; `extend` then fetches only the new ones."""

    def __init__(self, snap, client: Client, chain_id: int, number: int, block_hash: str, pinned_rlp: bytes):
        from .fork_proxy import SnapshotBackend
        super().__init__(client, chain_id, number, block_hash, pinned_rlp)
        if snap.manifest["block_number"] != number or snap.manifest["block_hash"] != block_hash:
            raise SystemExit("prefill snapshot is for another block")
        self.local = SnapshotBackend(snap)
        self.local_hits = 0

    def account(self, address: str):
        a = self.local.account(address)
        if a is not None:
            self.local_hits += 1
            return a
        return super().account(address)

    def storage(self, address: str, slot: str):
        v = self.local.storage(address, slot)
        if v is not None:
            self.local_hits += 1
            return v
        return super().storage(address, slot)

    def header_by_number(self, n: int):
        return self.local.header_by_number(n) or super().header_by_number(n)

    def header_by_hash(self, h: str):
        return self.local.header_by_hash(h) or super().header_by_hash(h)


class CollectSession:
    """In-process recording proxy (the same request handler as `collect`), for running Hyblis-owned code
    through runner/run_submission.py: it offers the fork-handle interface the runner uses
    (``set_fresh``, ``misses``, ``refusals``, ``close``). Fresh accounts of a job (state/fresh.py) are
    answered locally and never recorded or sent upstream; mapping slots derived from them are recorded
    (they are proven zero at build; harmless). Usage::

        s = CollectSession(upstream, chain_id, number, block_hash, socket_path)
        ... run_submission.reproduce_with_spec(..., fork_url=s.socket_path, fork=s) ...
        s.close(); s.write_access(path, append=True)
    """

    def __init__(self, upstream: str, chain_id: int, number: int, block_hash: str, socket_path: str,
                 socket_mode: int = 0o660, prefill=None):
        self.chain_id, self.number, self.block_hash = chain_id, number, mpt.norm_hash(block_hash)
        self.client = Client(upstream)
        _, pinned_rlp = check_upstream(self.client, chain_id, number, self.block_hash)
        self.rec = AccessRecorder()
        if prefill is not None:   # a loaded, verified Snapshot of the same block
            self.backend = PrefilledBackend(prefill, self.client, chain_id, number, self.block_hash, pinned_rlp)
        else:
            self.backend = UpstreamBackend(self.client, chain_id, number, self.block_hash, pinned_rlp)
        self.handler = RpcHandler(self.backend, self.rec)
        self.server = UnixRpcServer(socket_path, self.handler, blocking=True, socket_mode=socket_mode).start()
        self.socket_path = self.server.socket_path
        self._closed = False

    def set_fresh(self, accounts, keys=(), partners=(), label: str = "") -> dict:
        from .fresh import FreshSet
        fs = FreshSet(accounts, keys, partners, [], label=label)
        self.handler.fresh = fs
        return dict(fs.stats)

    def clear_fresh(self) -> None:
        self.handler.fresh = None

    def misses(self) -> list:
        return []             # the upstream answers everything; nothing is missing in collect mode

    def refusals(self) -> list:
        return self.rec.refusals()

    def stats(self) -> dict:
        st = self.handler.stats()
        st["local_hits"] = getattr(self.backend, "local_hits", 0)
        st["upstream_calls"] = self.client.calls
        return st

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self.server.close()
            self.client.close()

    def access(self) -> tuple[dict[str, set[str]], set[int]]:
        return {k: set(v) for k, v in self.rec.accounts.items()}, set(self.rec.blocks) - {self.number}

    def write_access(self, path: str, append: bool = False) -> dict:
        accounts, blocks = self.access()
        if append and os.path.exists(path):
            old_a, old_b = read_targets([path], self.chain_id, self.number, self.block_hash)
            for k, v in old_a.items():
                accounts.setdefault(k, set()).update(v)
            blocks |= old_b
        doc = access_document(self.chain_id, self.number, self.block_hash, accounts, blocks, self.rec.refusals(),
                              self.handler.stats()["by_method"])
        with open(path, "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
        return doc


def cmd_collect(a) -> int:
    chain_id, number, block_hash = _chain_args(a)
    client = Client(a.upstream)
    _, pinned_rlp = check_upstream(client, chain_id, number, block_hash)
    rec = AccessRecorder()
    handler = RpcHandler(UpstreamBackend(client, chain_id, number, block_hash, pinned_rlp), rec)
    server = UnixRpcServer(a.socket, handler, blocking=True).start()
    _log(f"collect: serving block {number} on {server.socket_path}")
    rc = 0
    try:
        if a.command:
            cmd = a.command[1:] if a.command[0] == "--" else a.command
            env = dict(os.environ, HYBLIS_ETH_RPC=server.socket_path)
            rc = subprocess.run(cmd, env=env).returncode
        else:
            stop = threading.Event()
            for sig in (signal.SIGINT, signal.SIGTERM):
                signal.signal(sig, lambda *_: stop.set())
            stop.wait()
    finally:
        server.close()
        client.close()
    accounts = {k: set(v) for k, v in rec.accounts.items()}
    blocks = set(rec.blocks) - {number}
    if a.append and os.path.exists(a.out):
        old_a, old_b = read_targets([a.out], chain_id, number, block_hash)
        for k, v in old_a.items():
            accounts.setdefault(k, set()).update(v)
        blocks |= old_b
    doc = access_document(chain_id, number, block_hash, accounts, blocks, rec.refusals(), handler.stats()["by_method"])
    with open(a.out, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    _log(f"collect: {len(accounts)} accounts, {sum(len(v) for v in accounts.values())} slots, "
         f"{len(rec.refusals())} refused request kinds -> {a.out}")
    return rc


# ----------------------------------------------------------------------------------------------
# build / extend
# ----------------------------------------------------------------------------------------------

class Fetcher:
    """Fetches and verifies accounts, slots and headers into a Content. Every value is proof-checked."""

    def __init__(self, upstream: str, content: Content, jobs: int = 1, prefetch: bool = True):
        self.upstream = upstream
        self.content = content
        self.jobs = max(1, jobs)
        self.prefetch = prefetch
        self._local = threading.local()
        self._lock = threading.Lock()
        self.calls = 0

    def client(self) -> Client:
        c = getattr(self._local, "c", None)
        if c is None:
            c = self._local.c = Client(self.upstream)
        return c

    def call(self, method, params):
        with self._lock:
            self.calls += 1
        return self.client().call(method, params)

    def headers(self, lowest: int) -> None:
        """Extend the stored header chain down to ``lowest`` by following parentHash links."""
        c = self.content
        n = min(c.headers)
        while n > max(lowest, 0):
            parent = mpt.decode_header(c.headers[n])["parentHash"]
            blk = self.call("eth_getBlockByHash", [parent, False])
            if not isinstance(blk, dict):
                raise ProofError(f"upstream does not have block {parent}")
            enc = mpt.verify_header(blk, parent)
            if mpt.parse_quantity(blk["number"]) != n - 1:
                raise ProofError(f"block {parent} has the wrong number")
            c.headers[n - 1] = enc
            n -= 1

    def _proofs(self, address: str, slots, acct):
        c = self.content
        want = sorted(slots)
        chunks = [want[i:i + PROOF_CHUNK] for i in range(0, len(want), PROOF_CHUNK)] or [[]]
        for ch in chunks:
            res = self.call("eth_getProof", [address, ch, hex(c.block_number)])
            got, values, nodes = mpt.verify_account_result(c.state_root, address, ch, res)
            if acct is not None and got != acct:
                raise ProofError(f"{address}: account differs between proof calls")
            acct = got
            with self._lock:
                c.add_nodes(nodes)
                if got.exists and got.storage_root != mpt.EMPTY_TRIE_ROOT:
                    for s, v in values.items():
                        c.add_slot(address, s, v)
        return acct

    def account(self, address: str, slots: set[str], prefetch: bool | None = None) -> list[str]:
        """Fetch + verify one account and the given slots. Returns addresses worth following
        (EIP-1967 implementation/beacon) when a new contract was prefetched."""
        c = self.content
        tag = hex(c.block_number)
        is_new = address not in c.accounts
        acct = self._proofs(address, slots, None)
        follow: list[str] = []
        prefetch = self.prefetch if prefetch is None else prefetch
        if prefetch and is_new and acct.exists and acct.code_hash != EMPTY_CODE_HASH \
                and acct.storage_root != mpt.EMPTY_TRIE_ROOT:
            extra = PREFETCH_SLOTS - set(slots)
            if extra:
                self._proofs(address, extra, acct)
            for s in (EIP1967_IMPL, EIP1967_BEACON):
                v = c.storage.get((address, s), 0)
                if v and v < (1 << 160):
                    follow.append(to_hex(v.to_bytes(20, "big")))
        code = b""
        if acct.exists and acct.code_hash != EMPTY_CODE_HASH:
            known = c.accounts.get(address)
            if known is not None and known[0] == acct:
                code = known[1]
            else:
                code = from_hex(self.call("eth_getCode", [address, tag]), None, "code")
                if keccak(code) != acct.code_hash:
                    raise ProofError(f"{address}: eth_getCode does not match the proven code hash")
        with self._lock:
            c.add_account(acct, code)
        return follow

    def accounts(self, targets: dict[str, set[str]]) -> None:
        items = sorted(targets.items())
        follow: set[str] = set()
        done = 0
        if self.jobs == 1:
            results = (self.account(a, s) for a, s in items)
        else:
            ex = ThreadPoolExecutor(self.jobs)
            results = ex.map(lambda kv: self.account(*kv), items)
        for f in results:
            follow.update(f)
            done += 1
            if done % 100 == 0:
                _log(f"  {done}/{len(items)} accounts")
        if self.jobs != 1:
            ex.shutdown()
        for a in sorted(follow - set(self.content.accounts)):   # one hop, no further prefetch
            self.account(a, set(), prefetch=False)

    def history_ring(self, mode: str) -> int:
        """Add every EIP-2935 ring slot (vm.roll reads them) if the contract exists at the pinned block."""
        if mode == "off":
            return 0
        c = self.content
        if HISTORY_CONTRACT not in c.accounts:
            self.account(HISTORY_CONTRACT, set())
        acct, code = c.accounts[HISTORY_CONTRACT]
        if not acct.exists or not code:
            if mode == "on":
                raise SystemExit("--history-ring on, but the EIP-2935 contract has no code at the pinned block")
            return 0
        have = {s for (a, s) in c.storage if a == HISTORY_CONTRACT}
        ring = {norm_slot(hex(i)) for i in range(HISTORY_RING)} - have
        if ring:
            self.account(HISTORY_CONTRACT, ring)
        return len(ring)


def _content_from_upstream(client_upstream: str, chain_id: int, number: int, block_hash: str
                           ) -> tuple[Content, Client]:
    client = Client(client_upstream)
    blk, enc = check_upstream(client, chain_id, number, block_hash)
    content = Content(chain_id=chain_id, block_number=number, block_hash=from_hex(block_hash, 32),
                      state_root=from_hex(blk["stateRoot"], 32), block_object=blk)
    content.headers[number] = enc
    return content, client


def cmd_build(a) -> int:
    chain_id, number, block_hash = _chain_args(a)
    targets, blocks = read_targets(a.access, chain_id, number, block_hash)
    if a.forge_defaults:
        for k, v in forge_default_targets().items():
            targets.setdefault(k, set()).update(v)
    for p in a.extra_accounts or []:
        with open(p) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    targets.setdefault(norm_address(line), set())
    content, client = _content_from_upstream(a.upstream, chain_id, number, block_hash)
    client.close()
    blk = content.block_object
    targets.setdefault(norm_address(blk["miner"]), set())  # forge pays the coinbase
    f = Fetcher(a.upstream, content, a.jobs, a.prefetch)
    lowest = min([number - a.ancestors] + [b for b in blocks if b <= number])
    f.headers(lowest)
    _log(f"build: {len(content.headers)} headers; fetching {len(targets)} accounts, "
         f"{sum(len(v) for v in targets.values())} slots")
    f.accounts(targets)
    ring = f.history_ring(a.history_ring)
    notes = {"ancestors": a.ancestors, "history_ring_slots_added": ring, "forge_defaults": bool(a.forge_defaults),
             "prefetch": bool(a.prefetch),
             "inputs": [os.path.basename(p) for p in a.access], "rpc_calls": f.calls + 2}
    m = write_snapshot(content, a.out, version=1, parent_digest=None, source_rpc=endpoint_label(a.upstream),
                       notes=notes)
    print(json.dumps({"snapshot": a.out, "digest": m["digest"], "counts": m["counts"]}, sort_keys=True))
    return 0


def cmd_extend(a) -> int:
    exp_chain, _, exp_hash = _chain_args(a)
    snap = load_snapshot(a.snapshot, expect_block_hash=exp_hash, expect_chain_id=exp_chain)
    try:
        content = load_content(snap)
        old = snap.manifest
    finally:
        snap.close()
    chain_id, number, block_hash = content.chain_id, content.block_number, to_hex(content.block_hash)
    targets, blocks = read_targets(a.misses, chain_id, number, block_hash)
    # only what is actually missing: new accounts, and new slots of existing accounts
    need: dict[str, set[str]] = {}
    for addr, slots in targets.items():
        have = content.accounts.get(addr)
        if have is None:
            need[addr] = set(slots)
        elif have[0].exists and have[0].storage_root != mpt.EMPTY_TRIE_ROOT:
            new = {s for s in slots if (addr, s) not in content.storage}
            if new:
                need[addr] = new
    # BLOCKHASH reaches at most 256 blocks back, and after vm.roll the EIP-2935 ring (8191 blocks,
    # already in every snapshot) answers; a header further below the pin is never legitimately
    # needed, so such misses are not fetched (one entry must not mean millions of RPC calls).
    lowest_ok = max(0, number - HEADER_WINDOW)
    need_blocks = sorted(b for b in blocks if lowest_ok <= b < min(content.headers))
    unservable = sorted(b for b in blocks if b > number or b < lowest_ok)
    header_calls = (min(content.headers) - need_blocks[0]) if need_blocks else 0
    n_items = len(need) + sum(len(v) for v in need.values()) + header_calls
    if n_items > a.max_items:
        raise SystemExit(f"extend: {n_items} items > --max-items {a.max_items}; review the miss list first")
    if not need and not need_blocks:
        _log("extend: nothing to add (every miss is already covered)")
    f = Fetcher(a.upstream, content, a.jobs, a.prefetch)
    before = set(content.accounts)
    if need_blocks:
        f.headers(need_blocks[0])
    f.accounts(need)
    notes = dict(old.get("notes", {}))
    notes.update({"extended_from": old["digest"], "added_accounts": len(set(content.accounts) - before),
                  "added_items": n_items, "unservable_blocks": unservable,
                  "inputs": [os.path.basename(p) for p in a.misses], "rpc_calls": f.calls})
    m = write_snapshot(content, a.out, version=int(old.get("version", 1)) + 1, parent_digest=old["digest"],
                       source_rpc=endpoint_label(a.upstream), notes=notes)
    print(json.dumps({"snapshot": a.out, "digest": m["digest"], "parent_digest": old["digest"],
                      "version": m["version"], "added_items": n_items, "counts": m["counts"]}, sort_keys=True))
    return 0


def cmd_verify(a) -> int:
    if a.task_manifest:
        chain_id, _, block_hash = _chain_args(a)
    elif a.expect_block_hash:
        chain_id, block_hash = a.chain_id, mpt.norm_hash(a.expect_block_hash)
    else:
        raise SystemExit("verify needs --task-manifest or --expect-block-hash (the trust anchor)")
    try:
        snap = load_snapshot(a.snapshot, expect_block_hash=block_hash, expect_chain_id=chain_id)
    except SnapshotError as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        return 1
    print(json.dumps({"ok": True, "digest": snap.digest, "version": snap.manifest.get("version"),
                      "block_number": snap.report["block_number"], "counts": snap.report["counts"]}, sort_keys=True))
    snap.close()
    return 0


def cmd_info(a) -> int:
    with open(os.path.join(a.snapshot, "manifest.json")) as f:
        m = json.load(f)
    keep = ("format", "digest", "version", "parent_digest", "chain_id", "block_number", "block_hash", "state_root",
            "timestamp", "created_at", "source_rpc", "counts", "ancestors", "notes")
    print(json.dumps({k: m.get(k) for k in keep}, indent=1, sort_keys=True))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    def chain(p, required=True):
        p.add_argument("--task-manifest")
        p.add_argument("--chain-id", type=int)
        p.add_argument("--block", type=int)
        p.add_argument("--expect-block-hash")

    p = sub.add_parser("collect", help="recording proxy; run Hyblis-owned code only")
    chain(p)
    p.add_argument("--upstream", required=True)
    p.add_argument("--socket", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--append", action="store_true", help="merge into an existing access list")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- command to run with HYBLIS_ETH_RPC set")
    p.set_defaults(fn=cmd_collect)

    p = sub.add_parser("build", help="fetch + verify + write a snapshot")
    chain(p)
    p.add_argument("--access", action="append", required=True)
    p.add_argument("--upstream", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--ancestors", type=int, default=DEFAULT_ANCESTORS)
    p.add_argument("--history-ring", choices=("auto", "on", "off"), default="auto")
    p.add_argument("--forge-defaults", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--extra-accounts", action="append", help="file with one address per line")
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--prefetch", action=argparse.BooleanOptionalAction, default=True,
                   help="for each new contract also fetch slots 0..31, EIP-1967 slots and the implementation")
    p.set_defaults(fn=cmd_build)

    p = sub.add_parser("extend", help="add a runner job's misses; writes a new snapshot version")
    chain(p)
    p.add_argument("--snapshot", required=True)
    p.add_argument("--misses", action="append", required=True)
    p.add_argument("--upstream", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--max-items", type=int, default=5000)
    p.add_argument("--jobs", type=int, default=1)
    p.add_argument("--prefetch", action=argparse.BooleanOptionalAction, default=True)
    p.set_defaults(fn=cmd_extend)

    p = sub.add_parser("verify", help="re-verify a snapshot offline")
    p.add_argument("snapshot")
    chain(p)
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("info", help="print a snapshot's manifest summary")
    p.add_argument("snapshot")
    p.set_defaults(fn=cmd_info)

    a = ap.parse_args(argv)
    try:
        return a.fn(a)
    except (ProofError, SnapshotError) as e:
        print(f"snapshot: REFUSED: {e}", file=sys.stderr)
        return 3
    except (RpcError, TransportError) as e:
        print(f"snapshot: upstream error: {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
