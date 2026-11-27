"""The verified state snapshot: on-disk format, deterministic writer, loader and offline verifier.

A snapshot is a directory::

    manifest.json   identity and header fields, counts, sha256 of the other files, content digest
    header.json     the pinned block object as fetched (header fields verified; body lists informational)
    state.sqlite    meta, headers, accounts, storage, trie_nodes (see README.md)

Trust model: only the pinned block hash (from the task manifest) is trusted. Everything else is
re-derived from it on every load: header hash -> state root -> Merkle walks over the stored trie
nodes -> each account and slot; code by keccak; ancestor headers by the parentHash chain. A
snapshot that fails any check is refused as a whole.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field

import rlp

from . import mpt
from .mpt import (EMPTY_CODE_HASH, EMPTY_TRIE_ROOT, Account, ProofError, from_hex, keccak, to_hex)

FORMAT = "hyblis-state-snapshot/1"
STATE_FILE = "state.sqlite"
MANIFEST_FILE = "manifest.json"
HEADER_FILE = "header.json"

SCHEMA = [
    "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID",
    "CREATE TABLE headers (number INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, rlp BLOB NOT NULL)",
    'CREATE TABLE accounts (address TEXT PRIMARY KEY, "exists" INTEGER NOT NULL, nonce TEXT NOT NULL, '
    "balance TEXT NOT NULL, code_hash TEXT NOT NULL, storage_root TEXT NOT NULL, code BLOB NOT NULL) WITHOUT ROWID",
    "CREATE TABLE storage (address TEXT NOT NULL, slot TEXT NOT NULL, value TEXT NOT NULL, "
    "PRIMARY KEY (address, slot)) WITHOUT ROWID",
    "CREATE TABLE trie_nodes (hash TEXT PRIMARY KEY, rlp BLOB NOT NULL) WITHOUT ROWID",
]


class SnapshotError(Exception):
    """The snapshot is malformed, tampered with, or does not belong to the expected block."""


def _canon_json(obj) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=1, ensure_ascii=True) + "\n").encode()


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _word(v: int) -> str:
    return "0x" + v.to_bytes(32, "big").hex()


# ----------------------------------------------------------------------------------------------
# in-memory content (what build/extend assemble before writing)
# ----------------------------------------------------------------------------------------------

@dataclass
class Content:
    chain_id: int
    block_number: int
    block_hash: bytes
    state_root: bytes
    block_object: dict                                         # pinned block as fetched (header.json)
    headers: dict[int, bytes] = field(default_factory=dict)    # number -> header RLP (pinned + ancestors)
    accounts: dict[str, tuple[Account, bytes]] = field(default_factory=dict)  # address -> (account, code)
    storage: dict[tuple[str, str], int] = field(default_factory=dict)        # (address, slot32) -> value
    nodes: dict[bytes, bytes] = field(default_factory=dict)    # keccak -> RLP node (proof evidence)

    def add_nodes(self, raw_nodes) -> None:
        for raw in raw_nodes:
            self.nodes[keccak(raw)] = raw

    def add_account(self, acct: Account, code: bytes) -> None:
        """Add a verified account. Refuses to replace a different version of the same account."""
        if acct.exists and keccak(code) != acct.code_hash:
            raise ProofError(f"code of {acct.address} does not match its code hash")
        if not acct.exists and code:
            raise ProofError(f"absent account {acct.address} with code")
        old = self.accounts.get(acct.address)
        if old is not None and old[0] != acct:
            raise ProofError(f"account {acct.address} differs from the version already in the snapshot")
        self.accounts[acct.address] = (acct, code)

    def add_slot(self, address: str, slot: str, value: int) -> None:
        key = (address, mpt.norm_slot(slot))
        old = self.storage.get(key)
        if old is not None and old != value:
            raise ProofError(f"slot {key} differs from the version already in the snapshot")
        self.storage[key] = value


# ----------------------------------------------------------------------------------------------
# writer
# ----------------------------------------------------------------------------------------------

def _write_sqlite(content: Content, path: str) -> None:
    if os.path.exists(path):
        os.unlink(path)
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        conn.execute("PRAGMA page_size = 4096")
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA user_version = 1")
        conn.execute("BEGIN")
        for stmt in SCHEMA:
            conn.execute(stmt)
        meta = {
            "format": FORMAT,
            "chain_id": str(content.chain_id),
            "block_number": str(content.block_number),
            "block_hash": to_hex(content.block_hash),
            "state_root": to_hex(content.state_root),
            "proofs_verified": "1",
        }
        conn.executemany("INSERT INTO meta VALUES (?, ?)", sorted(meta.items()))
        conn.executemany("INSERT INTO headers VALUES (?, ?, ?)",
                         [(n, to_hex(keccak(r)), r) for n, r in sorted(content.headers.items())])
        rows = []
        for addr in sorted(content.accounts):
            a, code = content.accounts[addr]
            rows.append((addr, 1 if a.exists else 0, hex(a.nonce), hex(a.balance), to_hex(a.code_hash),
                         to_hex(a.storage_root), code))
        conn.executemany('INSERT INTO accounts VALUES (?, ?, ?, ?, ?, ?, ?)', rows)
        conn.executemany("INSERT INTO storage VALUES (?, ?, ?)",
                         [(a, s, _word(v)) for (a, s), v in sorted(content.storage.items())])
        conn.executemany("INSERT INTO trie_nodes VALUES (?, ?)",
                         [(to_hex(h), r) for h, r in sorted(content.nodes.items())])
        conn.execute("COMMIT")
        conn.execute("VACUUM")
    finally:
        conn.close()


def write_snapshot(content: Content, out_dir: str, *, version: int = 1, parent_digest: str | None = None,
                   source_rpc: str = "", created_at: str | None = None, notes: dict | None = None) -> dict:
    """Write ``content`` to ``out_dir`` (must not exist), verify what was written, return the manifest.

    Deterministic: the same content gives a byte-identical state.sqlite (same SQLite library) and
    the same digest. ``created_at`` defaults to $SOURCE_DATE_EPOCH if set, else now.
    """
    if os.path.exists(out_dir):
        raise FileExistsError(f"{out_dir} already exists")
    parent = os.path.dirname(os.path.abspath(out_dir))
    tmp = tempfile.mkdtemp(prefix=".snapshot-tmp-", dir=parent)
    try:
        _drop_unreferenced_nodes(content)
        _write_sqlite(content, os.path.join(tmp, STATE_FILE))
        header_bytes = _canon_json(content.block_object)
        with open(os.path.join(tmp, HEADER_FILE), "wb") as f:
            f.write(header_bytes)
        with open(os.path.join(tmp, STATE_FILE), "rb") as f:
            state_bytes = f.read()
        conn = _open_memory(state_bytes)
        try:
            report = _verify_db(conn, to_hex(content.block_hash), content.chain_id)
            digest = compute_digest(conn)
        finally:
            conn.close()
        if created_at is None:
            sde = os.environ.get("SOURCE_DATE_EPOCH")
            ts = int(sde) if sde and sde.isdigit() else int(time.time())
            created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
        hdr = mpt.decode_header(content.headers[content.block_number])
        q = lambda k: int(hdr[k], 16) if k in hdr else None  # noqa: E731
        manifest = {
            "format": FORMAT,
            "digest": digest,
            "version": version,
            "parent_digest": parent_digest,
            "chain_id": content.chain_id,
            "block_number": content.block_number,
            "block_hash": to_hex(content.block_hash),
            "state_root": to_hex(content.state_root),
            "parent_hash": hdr["parentHash"],
            "timestamp": q("timestamp"),
            "base_fee_per_gas": q("baseFeePerGas"),
            "gas_limit": q("gasLimit"),
            "gas_used": q("gasUsed"),
            "coinbase": hdr["miner"],
            "difficulty": q("difficulty"),
            "prev_randao": hdr["mixHash"],
            "blob_gas_used": q("blobGasUsed"),
            "excess_blob_gas": q("excessBlobGas"),
            "parent_beacon_block_root": hdr.get("parentBeaconBlockRoot"),
            "withdrawals_root": hdr.get("withdrawalsRoot"),
            "requests_hash": hdr.get("requestsHash"),
            "header": hdr,
            "created_at": created_at,
            "source_rpc": source_rpc,
            "counts": report["counts"],
            "ancestors": report["ancestors"],
            "files": {STATE_FILE: _sha256(state_bytes), HEADER_FILE: _sha256(header_bytes)},
            "state_sha256": _sha256(state_bytes),
            "proofs_verified": True,
            "notes": notes or {},
        }
        with open(os.path.join(tmp, MANIFEST_FILE), "wb") as f:
            f.write(_canon_json(manifest))
        for name in (STATE_FILE, HEADER_FILE, MANIFEST_FILE):
            os.chmod(os.path.join(tmp, name), 0o444)
        os.chmod(tmp, 0o755)   # public chain data; the files themselves are read-only
        os.rename(tmp, out_dir)
        return manifest
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def _drop_unreferenced_nodes(content: Content) -> None:
    """Keep exactly the trie nodes that the stored accounts and slots need (canonical node set)."""
    used: set[bytes] = set()
    get = _node_getter(content.nodes, used)
    for addr, (acct, _) in content.accounts.items():
        mpt.walk(content.state_root, mpt.address_key(addr), get)
    for (addr, slot) in content.storage:
        acct = content.accounts[addr][0]
        mpt.walk(acct.storage_root, mpt.slot_key(slot), get)
    for h in [h for h in content.nodes if h not in used]:
        del content.nodes[h]


def _node_getter(nodes: dict[bytes, bytes], used: set[bytes]):
    def get(h: bytes) -> bytes:
        raw = nodes.get(h)
        if raw is None:
            raise ProofError(f"trie node {to_hex(h)} missing from the snapshot")
        used.add(h)
        return raw
    return get


def _decoded_getter(nodes: dict[bytes, bytes], used: set[bytes]):
    """Like _node_getter, but decodes each (hash-checked) node once and caches the result."""
    cache: dict[bytes, object] = {}

    def get(h: bytes):
        d = cache.get(h)
        if d is None:
            raw = nodes.get(h)
            if raw is None:
                raise ProofError(f"trie node {to_hex(h)} missing from the snapshot")
            used.add(h)
            d = cache[h] = mpt._decode_node(raw)
        return d
    return get


# ----------------------------------------------------------------------------------------------
# reader / verifier
# ----------------------------------------------------------------------------------------------

def _open_memory(state_bytes: bytes) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    try:
        conn.deserialize(state_bytes)
    except sqlite3.DatabaseError as e:
        conn.close()
        raise SnapshotError(f"state file is not a valid SQLite database: {e}") from None
    conn.execute("PRAGMA query_only = ON")
    return conn


def compute_digest(conn: sqlite3.Connection) -> str:
    """Content digest: sha256 over a canonical, sorted serialisation of every row (SQLite-version
    independent). Excludes created_at, version and other bookkeeping."""
    h = hashlib.sha256()
    h.update(FORMAT.encode() + b"\n")
    for k, v in conn.execute("SELECT key, value FROM meta ORDER BY key"):
        h.update(f"M {k} {v}\n".encode())
    for n, hh, r in conn.execute("SELECT number, hash, rlp FROM headers ORDER BY number"):
        h.update(f"H {n} {hh} {bytes(r).hex()}\n".encode())
    for row in conn.execute('SELECT address, "exists", nonce, balance, storage_root, code_hash, code '
                            "FROM accounts ORDER BY address"):
        a, e, n, b, sr, ch, code = row
        h.update(f"A {a} {e} {n} {b} {sr} {ch} {to_hex(keccak(bytes(code)))}\n".encode())
    for a, s, v in conn.execute("SELECT address, slot, value FROM storage ORDER BY address, slot"):
        h.update(f"S {a} {s} {v}\n".encode())
    for (hh,) in conn.execute("SELECT hash FROM trie_nodes ORDER BY hash"):
        h.update(f"N {hh}\n".encode())
    return "sha256:" + h.hexdigest()


def _hex_field(v: str, n: int, what: str) -> bytes:
    if not isinstance(v, str) or v != v.lower():
        raise SnapshotError(f"{what}: not lower-case hex")
    try:
        return from_hex(v, n, what)
    except ProofError as e:
        raise SnapshotError(str(e)) from None


def _qty(v: str, what: str) -> int:
    if not isinstance(v, str) or not v.startswith("0x") or v != hex(int(v, 16)):
        raise SnapshotError(f"{what}: not a canonical hex quantity")
    return int(v, 16)


def _verify_db(conn: sqlite3.Connection, expect_block_hash: str, expect_chain_id: int | None) -> dict:
    """Full verification of an opened state DB. Returns a report with counts; raises SnapshotError."""
    try:
        return _verify_db_inner(conn, expect_block_hash, expect_chain_id)
    except SnapshotError:
        raise
    except ProofError as e:
        raise SnapshotError(f"proof check failed: {e}") from None
    except sqlite3.DatabaseError as e:
        raise SnapshotError(f"state DB unreadable or wrong schema: {e}") from None
    except Exception as e:  # wrong column types, malformed values, ...: refuse, never serve
        raise SnapshotError(f"malformed snapshot: {type(e).__name__}: {e}") from None


def _verify_db_inner(conn, expect_block_hash, expect_chain_id) -> dict:
    tables = {r[0]: r[1] for r in conn.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table'")}
    want = {s.split()[2]: s for s in SCHEMA}
    if set(tables) != set(want) or any(tables[k] != want[k] for k in want):
        raise SnapshotError("state DB schema differs from the expected schema")
    meta = dict(conn.execute("SELECT key, value FROM meta"))
    if meta.get("format") != FORMAT:
        raise SnapshotError(f"unknown snapshot format {meta.get('format')!r}")
    if meta.get("proofs_verified") != "1":
        raise SnapshotError("snapshot is not marked proofs_verified")
    if set(meta) != {"format", "chain_id", "block_number", "block_hash", "state_root", "proofs_verified"}:
        raise SnapshotError("unexpected meta keys")
    block_hash = _hex_field(meta["block_hash"], 32, "meta.block_hash")
    exp = mpt.from_hex(expect_block_hash, 32, "expected block hash")
    if block_hash != exp:
        raise SnapshotError(f"snapshot is for block {meta['block_hash']}, expected {to_hex(exp)}")
    chain_id = int(meta["chain_id"])
    if expect_chain_id is not None and chain_id != int(expect_chain_id):
        raise SnapshotError(f"snapshot chain id {chain_id} != expected {expect_chain_id}")
    number = int(meta["block_number"])

    # headers: pinned header hashes to the pinned hash; ancestors form an unbroken parent chain
    headers = list(conn.execute("SELECT number, hash, rlp FROM headers ORDER BY number"))
    if not headers or headers[-1][0] != number:
        raise SnapshotError("pinned header missing")
    prev = None
    for n, hh, r in headers:
        r = bytes(r)
        if to_hex(keccak(r)) != hh:
            raise SnapshotError(f"header {n}: stored hash does not match its RLP")
        hdr = mpt.decode_header(r)
        if int(hdr["number"], 16) != n:
            raise SnapshotError(f"header {n}: number field differs")
        if rlp.encode(rlp.decode(r)) != r:
            raise SnapshotError(f"header {n}: non-canonical RLP")
        if prev is not None:
            if prev[0] != n - 1 or hdr["parentHash"] != prev[1]:
                raise SnapshotError(f"header {n}: parent chain broken")
        prev = (n, hh)
    pinned = mpt.decode_header(bytes(headers[-1][2]))
    if from_hex(pinned["hash"], 32) != block_hash:
        raise SnapshotError("pinned header does not hash to the pinned block hash")
    state_root = _hex_field(meta["state_root"], 32, "meta.state_root")
    if pinned["stateRoot"] != to_hex(state_root):
        raise SnapshotError("meta.state_root differs from the pinned header's stateRoot")

    # trie nodes: each node is keyed by its own keccak
    nodes: dict[bytes, bytes] = {}
    bad = conn.execute(
        "SELECT (SELECT COUNT(*) FROM trie_nodes WHERE typeof(rlp) != 'blob' OR typeof(hash) != 'text')"
        " + (SELECT COUNT(*) FROM headers WHERE typeof(rlp) != 'blob' OR typeof(hash) != 'text')"
        " + (SELECT COUNT(*) FROM accounts WHERE typeof(code) != 'blob' OR typeof(address) != 'text'"
        "    OR typeof(nonce) != 'text' OR typeof(balance) != 'text' OR typeof(\"exists\") != 'integer')"
        " + (SELECT COUNT(*) FROM storage WHERE typeof(slot) != 'text' OR typeof(value) != 'text')").fetchone()[0]
    if bad:
        raise SnapshotError(f"{bad} row(s) with wrong column types")
    for hh, r in conn.execute("SELECT hash, rlp FROM trie_nodes"):
        hb = _hex_field(hh, 32, "trie node hash")
        r = bytes(r)
        if keccak(r) != hb:
            raise SnapshotError(f"trie node {hh} does not hash to its key")
        nodes[hb] = r
    used: set[bytes] = set()
    dec = _decoded_getter(nodes, used)
    walk = lambda root, key: mpt.walk(root, key, None, get_decoded=dec)  # noqa: E731

    accounts: dict[str, Account] = {}
    n_exist = n_code = code_bytes = 0
    for row in conn.execute('SELECT address, "exists", nonce, balance, code_hash, storage_root, code FROM accounts'):
        addr, ex, nonce_s, bal_s, ch_s, sr_s, code = row
        _hex_field(addr, 20, "account address")
        code = bytes(code)
        leaf = walk(state_root, mpt.address_key(addr))
        nonce, bal = _qty(nonce_s, "nonce"), _qty(bal_s, "balance")
        ch, sr = _hex_field(ch_s, 32, "code_hash"), _hex_field(sr_s, 32, "storage_root")
        if leaf is None:
            if (ex, nonce, bal, ch, sr, code) != (0, 0, 0, EMPTY_CODE_HASH, EMPTY_TRIE_ROOT, b""):
                raise SnapshotError(f"account {addr}: proven absent but stored as existing/non-empty")
            accounts[addr] = Account(addr, False, 0, 0, EMPTY_TRIE_ROOT, EMPTY_CODE_HASH)
            continue
        p_nonce, p_bal, p_sr, p_ch = mpt.decode_account(leaf)
        if (ex, nonce, bal, sr, ch) != (1, p_nonce, p_bal, p_sr, p_ch):
            raise SnapshotError(f"account {addr}: stored fields differ from the proven account")
        if keccak(code) != ch:
            raise SnapshotError(f"account {addr}: code does not match its code hash")
        accounts[addr] = Account(addr, True, nonce, bal, sr, ch)
        n_exist += 1
        if code:
            n_code += 1
            code_bytes += len(code)

    n_slots = n_nonzero = 0
    for addr, slot, val in conn.execute("SELECT address, slot, value FROM storage"):
        a = accounts.get(addr)
        if a is None or not a.exists:
            raise SnapshotError(f"storage row for {addr} without an existing account row")
        _hex_field(slot, 32, "slot")
        v = int.from_bytes(_hex_field(val, 32, "storage value"), "big")
        proven = mpt.decode_storage_value(walk(a.storage_root, mpt.slot_key(slot)))
        if proven != v:
            raise SnapshotError(f"storage {addr}[{slot}]: stored value differs from the proven value")
        n_slots += 1
        n_nonzero += 1 if v else 0

    orphans = set(nodes) - used
    if orphans:
        raise SnapshotError(f"{len(orphans)} trie node(s) not used by any account or slot")
    return {
        "chain_id": chain_id, "block_number": number, "block_hash": to_hex(block_hash),
        "state_root": to_hex(state_root),
        "ancestors": {"count": len(headers) - 1, "lowest": headers[0][0]},
        "counts": {"accounts": len(accounts), "existing_accounts": n_exist, "accounts_with_code": n_code,
                   "code_bytes": code_bytes, "storage_slots": n_slots, "nonzero_slots": n_nonzero,
                   "trie_nodes": len(nodes), "headers": len(headers)},
    }


@dataclass
class Snapshot:
    """A loaded, verified snapshot held in an in-memory SQLite DB (the exact bytes that were hashed)."""
    path: str
    manifest: dict
    conn: sqlite3.Connection
    report: dict

    @property
    def digest(self) -> str:
        return self.manifest["digest"]

    def close(self) -> None:
        self.conn.close()


def load_snapshot(path: str, *, expect_block_hash: str | None = None, expect_chain_id: int | None = None,
                  expect_digest: str | None = None) -> Snapshot:
    """Load and fully verify a snapshot directory. Raises SnapshotError on any problem.

    ``expect_block_hash`` should come from the task manifest (chain.fork_block_hash). If omitted, the
    snapshot's own block hash is used, which only proves internal consistency."""
    try:
        with open(os.path.join(path, MANIFEST_FILE), "rb") as f:
            manifest = json.loads(f.read())
        with open(os.path.join(path, STATE_FILE), "rb") as f:
            state_bytes = f.read()
        with open(os.path.join(path, HEADER_FILE), "rb") as f:
            header_bytes = f.read()
    except (OSError, ValueError) as e:
        raise SnapshotError(f"cannot read snapshot: {e}") from None
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or not isinstance(manifest.get("files"), dict):
        raise SnapshotError("manifest: unknown format")
    if _sha256(state_bytes) != manifest.get("state_sha256") or \
            manifest.get("files", {}).get(STATE_FILE) != manifest.get("state_sha256"):
        raise SnapshotError("manifest: state.sqlite sha256 mismatch")
    if manifest.get("files", {}).get(HEADER_FILE) != _sha256(header_bytes):
        raise SnapshotError("manifest: header.json sha256 mismatch")
    if expect_digest is not None and manifest.get("digest") != expect_digest:
        raise SnapshotError("manifest: digest differs from the expected digest")
    block_hash = expect_block_hash or manifest.get("block_hash")
    if not isinstance(block_hash, str):
        raise SnapshotError("no block hash to verify against")
    conn = _open_memory(state_bytes)
    try:
        report = _verify_db(conn, block_hash, expect_chain_id)
        digest = compute_digest(conn)
        if digest != manifest.get("digest"):
            raise SnapshotError("manifest: content digest mismatch")
        for k in ("chain_id", "block_number", "block_hash", "state_root"):
            if manifest.get(k) != report[k]:
                raise SnapshotError(f"manifest: {k} differs from the verified content")
        if manifest.get("counts") != report["counts"]:
            raise SnapshotError("manifest: counts differ from the verified content")
        # header.json: its header fields must hash to the pinned block hash too
        try:
            block_obj = json.loads(header_bytes)
            enc = mpt.verify_header(block_obj, report["block_hash"])
        except (ValueError, ProofError) as e:
            raise SnapshotError(f"header.json does not verify: {e}") from None
        pinned_rlp = conn.execute("SELECT rlp FROM headers WHERE number = ?", (report["block_number"],)).fetchone()[0]
        if bytes(pinned_rlp) != enc:
            raise SnapshotError("header.json differs from the stored pinned header")
        hdr = mpt.decode_header(enc)
        if manifest.get("header") != hdr or manifest.get("timestamp") != int(hdr["timestamp"], 16):
            raise SnapshotError("manifest: header fields differ from the verified header")
    except SnapshotError:
        conn.close()
        raise
    except Exception as e:
        conn.close()
        raise SnapshotError(f"malformed snapshot: {type(e).__name__}: {e}") from None
    return Snapshot(path=path, manifest=manifest, conn=conn, report=report)


def load_content(snap: Snapshot) -> Content:
    """Turn a loaded (verified) snapshot back into Content, e.g. to extend it."""
    c = snap.conn
    m = snap.manifest
    with open(os.path.join(snap.path, HEADER_FILE), "rb") as f:
        block_obj = json.loads(f.read())
    content = Content(chain_id=m["chain_id"], block_number=m["block_number"],
                      block_hash=from_hex(m["block_hash"], 32), state_root=from_hex(m["state_root"], 32),
                      block_object=block_obj)
    for n, _, r in c.execute("SELECT number, hash, rlp FROM headers"):
        content.headers[n] = bytes(r)
    for row in c.execute('SELECT address, "exists", nonce, balance, code_hash, storage_root, code FROM accounts'):
        addr, ex, n, b, ch, sr, code = row
        content.accounts[addr] = (Account(addr, bool(ex), int(n, 16), int(b, 16), from_hex(sr, 32),
                                          from_hex(ch, 32)), bytes(code))
    for a, s, v in c.execute("SELECT address, slot, value FROM storage"):
        content.storage[(a, s)] = int(v, 16)
    for h, r in c.execute("SELECT hash, rlp FROM trie_nodes"):
        content.nodes[from_hex(h, 32)] = bytes(r)
    return content
