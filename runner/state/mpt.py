"""Ethereum Merkle-Patricia proof and block-header verification (no network, no trust in the RPC).

Everything the state layer serves is checked here first:

* ``verify_header(block, expected_hash)``: keccak(rlp(header fields)) must equal the pinned block hash.
  Handles London, Shanghai, Cancun and Prague fields (baseFeePerGas, withdrawalsRoot, blobGasUsed,
  excessBlobGas, parentBeaconBlockRoot, requestsHash). An unknown header field fails closed.
* ``verify_proof(root, key, proof)``: strict, ordered walk of an eth_getProof node list. Returns the
  leaf value, or ``None`` when the proof shows the key is absent (exclusion proof). Every node must be
  used exactly once and in order: a truncated proof, an extra node, a reordered node or a node that
  does not hash to its parent's reference raises ``ProofError``.
* ``verify_account_result(state_root, address, slots, result)``: checks a whole eth_getProof result:
  the account proof against the state root, the claimed account fields against the proven leaf,
  and one storage proof per requested slot (inclusion or exclusion) against the proven storage root.
* ``walk(root, key, get_node)``: the same walk over a node store (used to re-verify a snapshot offline
  and to re-create proofs for eth_getProof answers).

Only pycryptodome (keccak) and rlp are used.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable

import rlp
from Crypto.Hash import keccak as _keccak

__all__ = [
    "ProofError", "keccak", "EMPTY_TRIE_ROOT", "EMPTY_CODE_HASH", "Account", "verify_proof", "walk",
    "decode_account", "encode_account", "verify_account_result", "header_fields", "encode_header",
    "header_hash", "verify_header", "decode_header", "HEADER_FIELDS", "norm_address", "norm_slot",
    "norm_hash", "parse_quantity", "to_quantity", "to_hex", "from_hex", "slot_key", "address_key",
]


class ProofError(Exception):
    """Raised for any proof, header or encoding that does not verify. Never caught to 'fix up' data."""


def keccak(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


EMPTY_TRIE_ROOT = keccak(b"\x80")   # 0x56e81f17...b421, root of an empty trie
EMPTY_CODE_HASH = keccak(b"")       # 0xc5d24601...a470
ZERO32 = b"\x00" * 32


# ----------------------------------------------------------------------------------------------
# hex helpers (strict: the state layer never accepts loosely formatted data from an RPC)
# ----------------------------------------------------------------------------------------------

def to_hex(b: bytes) -> str:
    return "0x" + b.hex()


def from_hex(s: str, length: int | None = None, what: str = "hex") -> bytes:
    if not isinstance(s, str) or not s.startswith(("0x", "0X")):
        raise ProofError(f"{what}: expected 0x-prefixed hex, got {s!r:.80}")
    body = s[2:]
    if len(body) % 2:
        raise ProofError(f"{what}: odd-length hex")
    try:
        b = bytes.fromhex(body)
    except ValueError:
        raise ProofError(f"{what}: invalid hex") from None
    if length is not None and len(b) != length:
        raise ProofError(f"{what}: expected {length} bytes, got {len(b)}")
    return b


def parse_quantity(s, what: str = "quantity") -> int:
    """Parse a JSON-RPC quantity ('0x1a'). Accepts leading zeros (some servers pad) but nothing else."""
    if isinstance(s, int) and not isinstance(s, bool):
        if s < 0:
            raise ProofError(f"{what}: negative")
        return s
    if not isinstance(s, str) or not s.startswith(("0x", "0X")) or len(s) < 3:
        raise ProofError(f"{what}: expected 0x quantity, got {s!r:.80}")
    digits = s[2:]
    # hex digits only: Python's int() would also accept a sign, '_' and surrounding spaces ('0x-1')
    if len(digits) > 80 or not all(c in "0123456789abcdefABCDEF" for c in digits):
        raise ProofError(f"{what}: invalid quantity {s!r:.80}")
    return int(digits, 16)


def to_quantity(n: int) -> str:
    return hex(n)


def norm_address(a) -> str:
    """Lower-case 0x + 40 hex. Raises ProofError for anything else."""
    return to_hex(from_hex(a, 20, "address")) if isinstance(a, str) else _bad("address", a)


def norm_hash(h) -> str:
    return to_hex(from_hex(h, 32, "hash")) if isinstance(h, str) else _bad("hash", h)


def norm_slot(s) -> str:
    """A storage slot as a 32-byte 0x hex string. Accepts quantities ('0x1') and full 32-byte words."""
    v = parse_quantity(s, "slot")
    if v >= 1 << 256:
        raise ProofError("slot: larger than 256 bits")
    return "0x" + v.to_bytes(32, "big").hex()


def _bad(what, v):
    raise ProofError(f"{what}: invalid value {v!r:.80}")


def address_key(address: str) -> bytes:
    """Trie key of an account: keccak(address bytes)."""
    return keccak(from_hex(address, 20, "address"))


def slot_key(slot: str) -> bytes:
    """Trie key of a storage slot: keccak(slot as a 32-byte word)."""
    return keccak(int(norm_slot(slot), 16).to_bytes(32, "big"))


# ----------------------------------------------------------------------------------------------
# Merkle-Patricia walk
# ----------------------------------------------------------------------------------------------

def _nibbles(key: bytes) -> list[int]:
    out = []
    for b in key:
        out.append(b >> 4)
        out.append(b & 0x0F)
    return out


def _hp_decode(path: bytes) -> tuple[list[int], bool]:
    """Hex-prefix decoding. Returns (nibbles, is_leaf). Strict about the flag nibble and padding."""
    if not path:
        raise ProofError("trie: empty hex-prefix path")
    nib = _nibbles(path)
    flag = nib[0]
    if flag > 3:
        raise ProofError("trie: bad hex-prefix flag")
    is_leaf = flag >= 2
    if flag & 1:
        return nib[1:], is_leaf
    if nib[1] != 0:
        raise ProofError("trie: bad hex-prefix padding")
    return nib[2:], is_leaf


def _decode_node(raw: bytes):
    try:
        node = rlp.decode(raw)
    except Exception as e:  # rlp raises several exception types for malformed input
        raise ProofError(f"trie: node is not valid RLP ({type(e).__name__})") from None
    return node


def _child_ref(ref, depth_desc: str):
    """A child reference is b'' (empty), a 32-byte hash, or an embedded node (decoded list, < 32 bytes)."""
    if isinstance(ref, list):
        if len(rlp.encode(ref)) >= 32:
            raise ProofError(f"trie: embedded node of 32+ bytes at {depth_desc}")
        return ("inline", ref)
    if ref == b"":
        return ("empty", None)
    if len(ref) == 32:
        return ("hash", ref)
    raise ProofError(f"trie: bad child reference length {len(ref)} at {depth_desc}")


def walk(root: bytes, key: bytes, get_node: Callable[[bytes], bytes],
         on_node: Callable[[bytes, bytes], None] | None = None,
         on_inline: Callable[[list], None] | None = None,
         get_decoded: Callable[[bytes], object] | None = None) -> bytes | None:
    """Walk the trie with the given root along keccak'd ``key``.

    ``get_node(hash) -> raw RLP``: must return the node whose keccak is ``hash`` (the callee checks).
    Returns the leaf's value bytes, or None if the trie proves the key is absent.
    ``on_node(hash, raw)`` is called for each hashed node visited; ``on_inline(node)`` for embedded nodes.
    ``get_decoded(hash)``: optional, returns the already-decoded node (a cache over a verified node
    store); when given, ``get_node`` and ``on_node`` are not used.
    """
    if len(root) != 32:
        raise ProofError("trie: root must be 32 bytes")
    if root == EMPTY_TRIE_ROOT:
        return None
    path = _nibbles(key)
    pos = 0
    if get_decoded is not None:
        node = get_decoded(root)
    else:
        raw = get_node(root)
        if on_node:
            on_node(root, raw)
        node = _decode_node(raw)
    depth = 0
    while True:
        depth += 1
        if depth > 70:
            raise ProofError("trie: path too deep")
        if node == b"":
            # the empty trie; only valid as the root (handled above) -> malformed otherwise
            raise ProofError("trie: empty node inside a trie")
        if not isinstance(node, list):
            raise ProofError("trie: node is a string, not a list")
        if len(node) == 17:
            if any(isinstance(x, list) for x in node[16:]) or node[16] != b"":
                # fixed-length keys never end at a branch; a value here is malformed for state tries
                raise ProofError("trie: branch node carries a value")
            if pos >= len(path):
                raise ProofError("trie: key exhausted at a branch")
            kind, ref = _child_ref(node[path[pos]], f"nibble {pos}")
            pos += 1
            if kind == "empty":
                return None
        elif len(node) == 2:
            if not isinstance(node[0], bytes):
                raise ProofError("trie: leaf/extension path is not a string")
            seg, is_leaf = _hp_decode(node[0])
            if is_leaf:
                if not isinstance(node[1], bytes):
                    raise ProofError("trie: leaf value is not a string")
                if pos + len(seg) != len(path):
                    # a leaf whose path length does not finish the key: malformed for fixed-length keys
                    raise ProofError("trie: leaf path length does not match key length")
                if path[pos:] == seg:
                    if node[1] == b"":
                        raise ProofError("trie: empty leaf value")
                    return node[1]
                return None  # a different key lives here: exclusion
            # extension
            if not seg:
                raise ProofError("trie: empty extension")
            if path[pos:pos + len(seg)] != seg:
                return None  # diverges: exclusion
            pos += len(seg)
            kind, ref = _child_ref(node[1], f"extension at {pos}")
            if kind == "empty":
                raise ProofError("trie: extension with empty child")
        else:
            raise ProofError(f"trie: node with {len(node)} items")
        # follow the reference
        if kind == "inline":
            if on_inline:
                on_inline(ref)
            node = ref
        elif get_decoded is not None:
            node = get_decoded(ref)
        else:
            raw = get_node(ref)
            if on_node:
                on_node(ref, raw)
            node = _decode_node(raw)


def verify_proof(root: bytes, key: bytes, proof: Iterable[bytes]) -> bytes | None:
    """Verify an eth_getProof node list (strict, ordered).

    Returns the value at ``key`` (raw leaf payload) or None for a valid exclusion proof.
    """
    nodes = list(proof)
    if root == EMPTY_TRIE_ROOT:
        # empty trie: clients send [] or [rlp("")]
        if nodes in ([], [b"\x80"]):
            return None
        raise ProofError("trie: non-empty proof for the empty trie")
    idx = 0

    def get_node(h: bytes) -> bytes:
        nonlocal idx
        if idx >= len(nodes):
            raise ProofError("proof: truncated (a referenced node is missing)")
        raw = nodes[idx]
        if keccak(raw) != h:
            raise ProofError(f"proof: node {idx} does not hash to its reference")
        idx += 1
        return raw

    def on_inline(node) -> None:
        # Some clients also list embedded nodes as separate proof elements; consume an exact copy.
        nonlocal idx
        if idx < len(nodes) and nodes[idx] == rlp.encode(node):
            idx += 1

    value = walk(root, key, get_node, on_inline=on_inline)
    if idx != len(nodes):
        raise ProofError(f"proof: {len(nodes) - idx} extra node(s) after the walk ended")
    return value


# ----------------------------------------------------------------------------------------------
# accounts and storage
# ----------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Account:
    address: str          # 0x lower-case
    exists: bool
    nonce: int
    balance: int
    storage_root: bytes   # 32 bytes (EMPTY_TRIE_ROOT if none / absent)
    code_hash: bytes      # 32 bytes (EMPTY_CODE_HASH if none / absent)


def _canon_int(b: bytes, what: str) -> int:
    if not isinstance(b, bytes):
        raise ProofError(f"{what}: not a string")
    if b[:1] == b"\x00":
        raise ProofError(f"{what}: non-canonical integer (leading zero)")
    return int.from_bytes(b, "big")


def decode_account(value: bytes) -> tuple[int, int, bytes, bytes]:
    """Leaf payload of the state trie -> (nonce, balance, storage_root, code_hash)."""
    try:
        items = rlp.decode(value)
    except Exception:
        raise ProofError("account: leaf value is not valid RLP") from None
    if not isinstance(items, list) or len(items) != 4:
        raise ProofError("account: leaf must be a 4-item list")
    nonce = _canon_int(items[0], "account nonce")
    balance = _canon_int(items[1], "account balance")
    sr, ch = items[2], items[3]
    if not isinstance(sr, bytes) or len(sr) != 32 or not isinstance(ch, bytes) or len(ch) != 32:
        raise ProofError("account: storage root / code hash must be 32 bytes")
    return nonce, balance, sr, ch


def encode_account(nonce: int, balance: int, storage_root: bytes, code_hash: bytes) -> bytes:
    return rlp.encode([nonce, balance, storage_root, code_hash])


def decode_storage_value(value: bytes | None) -> int:
    if value is None:
        return 0
    try:
        inner = rlp.decode(value)
    except Exception:
        raise ProofError("storage: leaf value is not valid RLP") from None
    if not isinstance(inner, bytes) or len(inner) > 32:
        raise ProofError("storage: leaf value must be a string of at most 32 bytes")
    v = _canon_int(inner, "storage value")
    if v == 0:
        raise ProofError("storage: zero stored in the trie")
    return v


def _proof_nodes(lst, what: str) -> list[bytes]:
    if not isinstance(lst, list):
        raise ProofError(f"{what}: proof must be a list")
    return [from_hex(x, None, what) for x in lst]


def verify_account_result(state_root: bytes, address: str, slots: Iterable[str], result: dict
                          ) -> tuple[Account, dict[str, int], list[bytes]]:
    """Verify one eth_getProof result.

    ``slots``: the slots that were requested; the result must carry exactly one proof for each.
    Returns (account, {slot32hex: value}, every proof node used) or raises ProofError.
    """
    if not isinstance(result, dict):
        raise ProofError("getProof: result is not an object")
    address = norm_address(address)
    if norm_address(result.get("address", "")) != address:
        raise ProofError("getProof: result is for a different address")
    acct_nodes = _proof_nodes(result.get("accountProof"), "accountProof")
    leaf = verify_proof(state_root, address_key(address), acct_nodes)
    c_nonce = parse_quantity(result.get("nonce"), "nonce")
    c_balance = parse_quantity(result.get("balance"), "balance")
    c_code = from_hex(result.get("codeHash", ""), 32, "codeHash")
    c_sroot = from_hex(result.get("storageHash", ""), 32, "storageHash")
    if leaf is None:
        # proven absent: the RPC must not claim anything else (clients use either empty or zero hashes)
        if c_nonce or c_balance:
            raise ProofError("getProof: absent account claimed with nonce/balance")
        if c_code not in (EMPTY_CODE_HASH, ZERO32) or c_sroot not in (EMPTY_TRIE_ROOT, ZERO32):
            raise ProofError("getProof: absent account claimed with code or storage")
        acct = Account(address, False, 0, 0, EMPTY_TRIE_ROOT, EMPTY_CODE_HASH)
    else:
        nonce, balance, sroot, chash = decode_account(leaf)
        if (nonce, balance, sroot, chash) != (c_nonce, c_balance, c_sroot, c_code):
            raise ProofError("getProof: claimed account fields differ from the proven account")
        acct = Account(address, True, nonce, balance, sroot, chash)

    want = [norm_slot(s) for s in slots]
    sp = result.get("storageProof")
    if not isinstance(sp, list):
        raise ProofError("getProof: storageProof must be a list")
    if len(sp) != len(want):
        raise ProofError(f"getProof: {len(sp)} storage proofs for {len(want)} requested slots")
    values: dict[str, int] = {}
    nodes = list(acct_nodes)
    for item, slot in zip(sp, want):
        if not isinstance(item, dict):
            raise ProofError("getProof: storage proof item is not an object")
        if norm_slot(item.get("key", "")) != slot:
            raise ProofError("getProof: storage proofs are not in the requested order")
        claimed = parse_quantity(item.get("value"), "storage value")
        snodes = _proof_nodes(item.get("proof"), "storageProof")
        v = decode_storage_value(verify_proof(acct.storage_root, slot_key(slot), snodes))
        if v != claimed:
            raise ProofError(f"getProof: claimed value of slot {slot} differs from the proven value")
        values[slot] = v
        nodes.extend(snodes)
    return acct, values, nodes


# ----------------------------------------------------------------------------------------------
# block headers
# ----------------------------------------------------------------------------------------------

# (json key, kind). Order is the consensus RLP order. Fields after "nonce" are optional, but once one
# is present every earlier one must be present too.
HEADER_FIELDS: list[tuple[str, str]] = [
    ("parentHash", "h32"), ("sha3Uncles", "h32"), ("miner", "a20"), ("stateRoot", "h32"),
    ("transactionsRoot", "h32"), ("receiptsRoot", "h32"), ("logsBloom", "b256"), ("difficulty", "int"),
    ("number", "int"), ("gasLimit", "int"), ("gasUsed", "int"), ("timestamp", "int"),
    ("extraData", "bytes"), ("mixHash", "h32"), ("nonce", "b8"),
    ("baseFeePerGas", "int"),            # London
    ("withdrawalsRoot", "h32"),          # Shanghai
    ("blobGasUsed", "int"),              # Cancun
    ("excessBlobGas", "int"),            # Cancun
    ("parentBeaconBlockRoot", "h32"),    # Cancun
    ("requestsHash", "h32"),             # Prague
]
_MANDATORY = 15
_KIND = dict(HEADER_FIELDS)
# keys a block object may carry that are not header fields
_NON_HEADER_KEYS = {"hash", "size", "totalDifficulty", "transactions", "uncles", "withdrawals",
                    "author", "sealFields"}
_LEN = {"h32": 32, "a20": 20, "b256": 256, "b8": 8}


def header_fields(block: dict) -> list[tuple[str, object]]:
    """The header fields present in ``block`` in consensus order, as (key, python value)."""
    if not isinstance(block, dict):
        raise ProofError("header: block is not an object")
    unknown = set(block) - set(_KIND) - _NON_HEADER_KEYS
    if unknown:
        raise ProofError(f"header: unknown field(s) {sorted(unknown)}; add them to HEADER_FIELDS")
    out = []
    missing_seen = None
    for i, (key, kind) in enumerate(HEADER_FIELDS):
        if key not in block or block[key] is None:
            if i < _MANDATORY:
                raise ProofError(f"header: missing field {key}")
            missing_seen = missing_seen or key
            continue
        if missing_seen:
            raise ProofError(f"header: {key} present but earlier field {missing_seen} missing")
        v = block[key]
        if kind == "int":
            out.append((key, parse_quantity(v, key)))
        else:
            out.append((key, from_hex(v, _LEN.get(kind), key)))
    return out


def encode_header(block: dict) -> bytes:
    return rlp.encode([v for _, v in header_fields(block)])


def header_hash(block: dict) -> bytes:
    return keccak(encode_header(block))


def verify_header(block: dict, expected_hash: str | bytes) -> bytes:
    """keccak(rlp(header)) must equal ``expected_hash``; the block's own 'hash' field must agree.

    Returns the RLP encoding of the header (what the snapshot stores)."""
    exp = from_hex(expected_hash, 32, "expected block hash") if isinstance(expected_hash, str) else expected_hash
    enc = encode_header(block)
    got = keccak(enc)
    if got != exp:
        raise ProofError(f"header: keccak(rlp(header)) = {to_hex(got)} != pinned {to_hex(exp)}")
    if "hash" in block and from_hex(block["hash"], 32, "hash") != exp:
        raise ProofError("header: block object's 'hash' differs from the pinned hash")
    return enc


def decode_header(enc: bytes) -> dict:
    """RLP header -> JSON-RPC style dict (header fields plus 'hash'). Inverse of encode_header."""
    try:
        items = rlp.decode(enc)
    except Exception:
        raise ProofError("header: not valid RLP") from None
    if not isinstance(items, list) or not (_MANDATORY <= len(items) <= len(HEADER_FIELDS)):
        raise ProofError("header: wrong number of fields")
    out: dict = {}
    for (key, kind), v in zip(HEADER_FIELDS, items):
        if not isinstance(v, bytes):
            raise ProofError(f"header: field {key} is a list")
        if kind == "int":
            out[key] = to_quantity(_canon_int(v, key))
        else:
            n = _LEN.get(kind)
            if n is not None and len(v) != n:
                raise ProofError(f"header: field {key} has {len(v)} bytes")
            out[key] = to_hex(v)
    out["hash"] = to_hex(keccak(enc))
    return out
