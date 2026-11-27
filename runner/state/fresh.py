"""Fresh accounts: per-job addresses the runner derives from a secret generated after the pinned block.

Why the proxy may answer them without a snapshot entry (and why this is not a guess)
-------------------------------------------------------------------------------
The runner deploys each PoC at a CREATE2 address salted with a 32-byte secret drawn for that job, and
hands out attacker keys derived from the same secret (runner/sol/HyblisRuntime.sol). Every such
address, every contract those addresses create, and every storage slot computed as
keccak256(abi.encode(<fresh address>, x)) is unknown to anyone before the job starts, so long after
the pinned block. Nothing on chain could have written to them at the pinned block, short of a keccak
collision. So, for a fresh address f:

  * its account is absent at the pinned block (balance 0, nonce 0, no code, no storage);
  * a slot keccak(pad32(f) . x) of ANY contract, and keccak(pad32(y) . keccak(pad32(f) . x)) (nested
    mappings such as allowances), held zero at the pinned block, for every x and y.

That holds for every x, so which bases x are precomputed only decides how many reads are covered,
never whether an answer is right. Reads that are not covered stay misses, as before.

Without this, every runner job misses: the harness measures the token balances of its own salted PoC
address and attacker accounts, which can never be in a snapshot built before the job.

The snapshot always wins: a fresh answer is given only for an item the snapshot does not hold.

API (used by fork_proxy and snapshot.collect sessions)::

    bases = mapping_bases(snapshot)                  # discovered once per snapshot digest (cached)
    fs = FreshSet(accounts, keys, partners, bases)   # per job
    fs.has_account(addr); fs.has_slot(slot_hex)
"""
from __future__ import annotations

import threading
import time

from .mpt import keccak

HISTORY_CONTRACT = "0x0000f90827f1c53a10cb7a02335b175320002935"
SMALL_BASES = range(64)          # plain Solidity layouts: mappings in the first 64 slots
SMALL_STRUCT = 4                 # struct fields covered after keccak(key . small base)
FOUND_STRUCT = 16                # struct fields covered after keccak(key . discovered base)
NEST_SMALL = range(16)           # small bases also tried for nested (allowance-like) mappings
MAX_KEYS_FLAT = 256              # fresh addresses whose first-level mapping slots are precomputed
MAX_KEYS_NESTED = 24             # fresh addresses whose nested mapping slots are precomputed
MAX_PARTNERS = 256
DISCOVERY_BUDGET = 8_000_000     # keccak evaluations at most per snapshot (about 25 s); logged
MAX_ROOTS = 64                   # ERC-7201 namespace roots considered per snapshot
MAX_BASES = 256                  # mapping bases kept per snapshot (bounds FreshSet cost per job)

_cache: dict[str, list[int]] = {}
_cache_lock = threading.Lock()


def _pad_addr(a: str) -> bytes:
    return bytes(12) + bytes.fromhex(a[2:])


def _w(v: int) -> bytes:
    return v.to_bytes(32, "big")


def mapping_bases(snap, budget: int = DISCOVERY_BUDGET) -> list[int]:
    """Bases of address-keyed mappings found in a verified snapshot.

    A base b is found when keccak(pad32(k) . b) + i (i < 8) is a stored slot for some known address k
    (any account of the snapshot, or an address-like stored value). Candidates are the small slots
    0..63 and, for ERC-7201 namespaced storage, root + 0..15 for every root r (a stored slot r + j with
    j < 16 whose low byte is j). Results only widen coverage; correctness never depends on them."""
    digest = snap.digest
    with _cache_lock:
        if digest in _cache:
            return list(_cache[digest])
    t0 = time.time()
    conn = snap.conn
    slots: set[int] = set()
    roots: set[int] = set()
    for addr, slot, value in conn.execute("SELECT address, slot, value FROM storage"):
        if addr == HISTORY_CONTRACT:
            continue
        s = int(slot, 16)
        slots.add(s)
        # A namespace root needs a non-zero slot: zero slots (for example added by extend from a
        # miss list) prove no layout and must not grow the candidate set.
        if s >= 1 << 128 and (s & 0xFF) < 16 and int(value, 16) != 0:
            roots.add(s & ~0xFF)
    roots = set(sorted(roots)[:MAX_ROOTS])
    keys: set[str] = {a for a, ex in conn.execute('SELECT address, "exists" FROM accounts') if ex}
    for (v,) in conn.execute("SELECT value FROM storage"):
        x = int(v, 16)
        if (1 << 144) <= x < (1 << 160):
            keys.add("0x" + x.to_bytes(20, "big").hex())
    cands = sorted(set(SMALL_BASES) | {r + j for r in roots for j in range(16)})
    keys_l = sorted(keys)
    if len(keys_l) * len(cands) > budget:
        keys_l = keys_l[: max(1, budget // max(1, len(cands)))]
    found: set[int] = set()
    cw = [_w(b) for b in cands]
    for k in keys_l:
        pk = _pad_addr(k)
        for b, wb in zip(cands, cw):
            if b in found:
                continue
            h = int.from_bytes(keccak(pk + wb), "big")
            for i in range(8):
                if h + i in slots:
                    found.add(b)
                    break
    out = sorted(found)[:MAX_BASES]
    with _cache_lock:
        _cache[digest] = out
    snap_stats = {"keys": len(keys_l), "candidates": len(cands), "found": len(out), "seconds": round(time.time() - t0, 2)}
    mapping_bases.last_stats = snap_stats   # type: ignore[attr-defined]
    return list(out)


mapping_bases.last_stats = {}   # type: ignore[attr-defined]


class FreshSet:
    """The fresh accounts of one job and the mapping slots derived from them (see the module doc)."""

    def __init__(self, accounts, keys=(), partners=(), bases=(), label: str = ""):
        t0 = time.time()
        self.label = label
        self.accounts = frozenset(_norm(a) for a in accounts)
        keys = [_norm(k) for k in keys]
        if not set(keys) <= self.accounts:
            raise ValueError("every fresh key must also be a fresh account")
        bases = sorted(set(int(b) for b in bases))
        flat_keys = keys[:MAX_KEYS_FLAT]
        nest_keys = keys[:MAX_KEYS_NESTED]
        others = sorted({_norm(p) for p in partners} - set(nest_keys))[:MAX_PARTNERS]
        partners = list(nest_keys) + others
        z: set[int] = set()
        small_w = [(_w(b), SMALL_STRUCT) for b in SMALL_BASES]
        found_w = [(_w(b), FOUND_STRUCT) for b in bases if b not in SMALL_BASES]
        for f in flat_keys:
            pf = _pad_addr(f)
            for wb, n in small_w + found_w:
                h = int.from_bytes(keccak(pf + wb), "big")
                z.update(h + i for i in range(n))
        nest_bases = sorted(set(NEST_SMALL) | set(bases) | {b + d for b in bases for d in (1, 2, 3)})
        nb_w = [_w(b) for b in nest_bases]
        inner_p = {p: [keccak(_pad_addr(p) + wb) for wb in nb_w] for p in partners}
        for f in nest_keys:
            pf = _pad_addr(f)
            inner_f = [keccak(pf + wb) for wb in nb_w]
            for p in partners:
                pp = _pad_addr(p)
                for i_f, i_p in zip(inner_f, inner_p[p]):
                    z.add(int.from_bytes(keccak(pp + i_f), "big"))     # m[f][p], e.g. allowance(f, p)
                    z.add(int.from_bytes(keccak(pf + i_p), "big"))     # m[p][f], e.g. allowance(p, f)
        self.slots = frozenset(z)
        self.stats = {"accounts": len(self.accounts), "keys": len(flat_keys), "nested_keys": len(nest_keys),
                      "partners": len(partners), "bases": len(bases), "slots": len(self.slots),
                      "seconds": round(time.time() - t0, 2)}

    def has_account(self, address: str) -> bool:
        return address in self.accounts

    def has_slot(self, slot: str) -> bool:
        return int(slot, 16) in self.slots


def _norm(a: str) -> str:
    a = a.lower()
    if not (a.startswith("0x") and len(a) == 42):
        raise ValueError(f"not an address: {a!r}")
    int(a, 16)
    return a
