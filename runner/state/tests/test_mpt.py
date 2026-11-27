"""Unit tests for runner/state/mpt.py (offline).

Data:
* fixtures/mainnet_26414000_header.json: the cap task's pinned block, must hash to tasks/cap/manifest.json
  chain.fork_block_hash.
* fixtures/mainnet_head_proofs.json: a real mainnet header + eth_getProof results (USDC with two
  non-zero slots and one zero slot, plus a second account) fetched at head on 2026-11-16.
* fixtures/anvil_proofs.json: eth_getProof results from the e2e toy chain (anvil 1.9.0), including an
  absent account and zero slots (exclusion proofs). Regenerate with HYBLIS_STATE_WRITE_FIXTURES=1.
* A reference trie builder (independent of mpt.py) for embedded-node and malformed-node cases.
"""
from __future__ import annotations

import copy
import json
import os
import unittest

import rlp

from state import mpt
from state.mpt import EMPTY_TRIE_ROOT, ProofError, keccak

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
CAP_MANIFEST = os.path.join(HERE, "..", "..", "..", "tasks", "cap", "manifest.json")


def load(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


# ----------------------------------------------------------------------------------------------
# independent reference trie (for embedded nodes and crafted malformed nodes)
# ----------------------------------------------------------------------------------------------

def _nib(b: bytes) -> list[int]:
    return [x for c in b for x in (c >> 4, c & 15)]


def _hp(n: list[int], leaf: bool) -> bytes:
    f = 2 if leaf else 0
    if len(n) % 2:
        n = [f + 1] + n
    else:
        n = [f, 0] + n
    return bytes(n[i] << 4 | n[i + 1] for i in range(0, len(n), 2))


class RefTrie:
    def __init__(self, items: dict[bytes, bytes]):
        self.db: dict[bytes, bytes] = {}
        top = self._build(sorted((_nib(k), v) for k, v in items.items()))
        enc = rlp.encode(top)
        self.root = keccak(enc)
        self.db[self.root] = enc
        self.top = top

    def _ref(self, node):
        enc = rlp.encode(node)
        if len(enc) < 32:
            return node
        h = keccak(enc)
        self.db[h] = enc
        return h

    def _build(self, items):
        if len(items) == 1:
            return [_hp(items[0][0], True), items[0][1]]
        pre = 0
        while all(len(p) > pre for p, _ in items) and len({p[pre] for p, _ in items}) == 1:
            pre += 1
        if pre:
            return [_hp(items[0][0][:pre], False), self._ref(self._build([(p[pre:], v) for p, v in items]))]
        node = [b""] * 17
        for d in range(16):
            group = [(p[1:], v) for p, v in items if p[0] == d]
            if group:
                node[d] = self._ref(self._build(group))
        return node

    def proof(self, key: bytes, list_inline: bool = False) -> list[bytes]:
        """geth convention: the root plus every node referenced by hash on the path.
        list_inline=True also lists embedded nodes as their own elements (other clients' convention)."""
        out = [self.db[self.root]]
        node, path = self.top, _nib(key)
        while True:
            if len(node) == 17:
                if not path:
                    return out
                ref, path = node[path[0]], path[1:]
            else:
                hp = _nib(node[0])
                seg = hp[1:] if hp[0] & 1 else hp[2:]
                if hp[0] >= 2 or path[:len(seg)] != seg:   # leaf, or diverging extension: walk ends
                    return out
                ref, path = node[1], path[len(seg):]
            if ref == b"":
                return out
            if isinstance(ref, list):
                if list_inline:
                    out.append(rlp.encode(ref))
                node = ref
            else:
                out.append(self.db[ref])
                node = rlp.decode(self.db[ref])


class HeaderTests(unittest.TestCase):
    def test_cap_pinned_header_matches_task_manifest(self):
        # the current pin (fixture mainnet_<fork_block>_header.json) must hash to the manifest's pinned hash;
        # the previous pin 26414000 must still hash to its own recorded hash
        with open(CAP_MANIFEST) as f:
            chain = json.load(f)["chain"]
        for name, number, want in ((f"mainnet_{chain['fork_block']}_header.json", int(chain["fork_block"]),
                                    chain["fork_block_hash"]),
                                   ("mainnet_26414000_header.json", 26414000,
                                    "0x918bab6229be5654778f15f6c8d20f3189ebb56b808c450d6453b3cd4dfffec7")):
            fx = load(name)
            enc = mpt.verify_header(fx["block"], want)
            self.assertEqual(mpt.to_hex(keccak(enc)), want.lower())
            dec = mpt.decode_header(enc)
            self.assertEqual(int(dec["number"], 16), number)
            self.assertIn("requestsHash", dec)  # Prague header
            self.assertEqual(mpt.encode_header(dec | {"hash": dec["hash"]}), enc)

    def test_head_and_anvil_headers(self):
        for name in ("mainnet_head_proofs.json", "anvil_proofs.json"):
            fx = load(name)
            mpt.verify_header(fx["block"], fx["block_hash"])

    def test_every_field_is_bound(self):
        blk = load("mainnet_26414000_header.json")["block"]
        h = blk["hash"]
        for key, kind in mpt.HEADER_FIELDS:
            b = copy.deepcopy(blk)
            v = b[key]
            if kind == "int":
                b[key] = hex(int(v, 16) + 1)
            else:
                raw = bytearray(bytes.fromhex(v[2:])) or bytearray(b"\x00")
                raw[-1] ^= 1
                b[key] = "0x" + raw.hex()
            b.pop("hash")
            with self.assertRaises(ProofError, msg=key):
                mpt.verify_header(b, h)

    def test_missing_optional_field_unknown_field_and_hash_field(self):
        blk = load("mainnet_26414000_header.json")["block"]
        h = blk["hash"]
        b = dict(blk)
        b.pop("requestsHash")
        with self.assertRaises(ProofError):
            mpt.verify_header(b, h)          # hash changes without requestsHash
        b = dict(blk)
        b.pop("excessBlobGas")
        with self.assertRaises(ProofError):
            mpt.verify_header(b, h)          # gap in the optional fields
        b = dict(blk, blockAccessListHash="0x" + "11" * 32)
        with self.assertRaises(ProofError):
            mpt.verify_header(b, h)          # unknown future field: fail closed
        b = dict(blk, hash="0x" + "22" * 32)
        with self.assertRaises(ProofError):
            mpt.verify_header(b, h)          # object's own hash disagrees
        with self.assertRaises(ProofError):
            mpt.verify_header(blk, "0x" + "33" * 32)


class AccountProofTests(unittest.TestCase):
    def setUp(self):
        self.fx = load("mainnet_head_proofs.json")
        self.root = mpt.from_hex(self.fx["block"]["stateRoot"], 32)

    def _ok(self, fx_proof, root=None):
        return mpt.verify_account_result(root or self.root, fx_proof["address"], fx_proof["slots"],
                                         fx_proof["result"])

    def test_mainnet_inclusion_and_zero_slot_exclusion(self):
        acct, vals, nodes = self._ok(self.fx["proofs"][0])
        self.assertTrue(acct.exists)
        self.assertGreater(len(nodes), 10)
        self.assertEqual(sorted(v == 0 for v in vals.values()), [False, False, True])
        acct2, _, _ = self._ok(self.fx["proofs"][1])
        self.assertTrue(acct2.exists)

    def _tamper(self, fn, which=0):
        p = copy.deepcopy(self.fx["proofs"][which])
        fn(p["result"], p)
        with self.assertRaises(ProofError):
            self._ok(p)

    def test_wrong_storage_value(self):
        def f(r, p):
            sp = r["storageProof"][0]
            sp["value"] = hex(int(sp["value"], 16) + 1)
        self._tamper(f)

    def test_zero_slot_claimed_nonzero(self):
        def f(r, p):
            r["storageProof"][2]["value"] = "0x1"
        self._tamper(f)

    def test_wrong_balance_nonce_codehash_storagehash(self):
        self._tamper(lambda r, p: r.__setitem__("balance", hex(int(r["balance"], 16) + 1)))
        self._tamper(lambda r, p: r.__setitem__("nonce", hex(int(r["nonce"], 16) + 1)))
        self._tamper(lambda r, p: r.__setitem__("codeHash", "0x" + "00" * 32))
        self._tamper(lambda r, p: r.__setitem__("storageHash", mpt.to_hex(EMPTY_TRIE_ROOT)))

    def test_wrong_root(self):
        p = self.fx["proofs"][0]
        with self.assertRaises(ProofError):
            self._ok(p, root=mpt.from_hex(self.fx["block"]["parentHash"], 32))

    def test_truncated_account_proof(self):
        self._tamper(lambda r, p: r["accountProof"].pop())
        self._tamper(lambda r, p: r.__setitem__("accountProof", []))

    def test_truncated_storage_proof(self):
        self._tamper(lambda r, p: r["storageProof"][0]["proof"].pop())
        self._tamper(lambda r, p: r["storageProof"][2]["proof"].pop())  # exclusion proof too

    def test_extra_node(self):
        self._tamper(lambda r, p: r["accountProof"].append(r["accountProof"][-1]))
        self._tamper(lambda r, p: r["storageProof"][1]["proof"].append(r["storageProof"][0]["proof"][-1]))

    def test_reordered_and_flipped_nodes(self):
        def swap(r, p):
            a = r["accountProof"]
            a[1], a[2] = a[2], a[1]
        self._tamper(swap)

        def flip(r, p):
            n = bytearray(bytes.fromhex(r["accountProof"][-1][2:]))
            n[-1] ^= 1
            r["accountProof"][-1] = "0x" + n.hex()
        self._tamper(flip)

    def test_wrong_address_and_slot_set(self):
        def addr(r, p):
            p["address"] = "0x" + "11" * 20
            r["address"] = p["address"]
        self._tamper(addr)
        self._tamper(lambda r, p: r["storageProof"].pop())                       # missing a slot
        self._tamper(lambda r, p: r["storageProof"].reverse())                   # wrong order
        self._tamper(lambda r, p: r["storageProof"][0].__setitem__("key", "0x2"))  # proof for another key

    def test_anvil_inclusion_exclusion(self):
        fx = load("anvil_proofs.json")
        root = mpt.from_hex(fx["block"]["stateRoot"], 32)
        kinds = set()
        for p in fx["proofs"]:
            acct, vals, _ = mpt.verify_account_result(root, p["address"], p["slots"], p["result"])
            kinds.add(("exists" if acct.exists else "absent",
                       "empty-storage" if acct.storage_root == EMPTY_TRIE_ROOT else "storage"))
            for s, v in vals.items():
                kinds.add("zero-slot" if v == 0 else "nonzero-slot")
            # every proof must fail once tampered
            for mut in ("value", "truncate", "extra"):
                q = copy.deepcopy(p["result"])
                if mut == "value":
                    if q["storageProof"]:
                        q["storageProof"][0]["value"] = hex(int(q["storageProof"][0]["value"], 16) + 1)
                    else:
                        q["balance"] = hex(int(q["balance"], 16) + 1)
                elif mut == "truncate":
                    q["accountProof"] = q["accountProof"][:-1]
                else:
                    q["accountProof"] = q["accountProof"] + [q["accountProof"][0]]
                with self.assertRaises(ProofError, msg=f"{p['address']} {mut}"):
                    mpt.verify_account_result(root, p["address"], p["slots"], q)
        self.assertIn(("absent", "empty-storage"), kinds)
        self.assertIn(("exists", "storage"), kinds)
        self.assertIn("zero-slot", kinds)
        self.assertIn("nonzero-slot", kinds)

    def test_absent_account_cannot_claim_balance(self):
        fx = load("anvil_proofs.json")
        root = mpt.from_hex(fx["block"]["stateRoot"], 32)
        absent = [p for p in fx["proofs"] if p["result"]["nonce"] == "0x0" and p["result"]["balance"] == "0x0"
                  and p["result"]["codeHash"] == mpt.to_hex(mpt.EMPTY_CODE_HASH)][0]
        q = copy.deepcopy(absent["result"])
        q["balance"] = "0x1"
        with self.assertRaises(ProofError):
            mpt.verify_account_result(root, absent["address"], absent["slots"], q)


class TrieWalkTests(unittest.TestCase):
    def test_reference_trie_with_embedded_nodes(self):
        # keys sharing long prefixes force small (embedded, < 32 byte) leaves deep in the trie
        base = bytes(range(32))
        items = {}
        for i in range(40):
            k = bytearray(base)
            k[28] = i // 8
            k[31] = i
            items[bytes(k)] = rlp.encode(i + 1)
        items[b"\xff" * 32] = rlp.encode(b"x" * 40)
        t = RefTrie(items)
        inline_seen = 0
        for k, v in items.items():
            pr = t.proof(k)
            self.assertEqual(mpt.verify_proof(t.root, k, pr), v)
            # walk over the node db reaches the same value and reports embedded nodes
            seen = []
            got = mpt.walk(t.root, k, lambda h: t.db[h], on_inline=seen.append)
            self.assertEqual(got, v)
            inline_seen += len(seen)
            with self.assertRaises(ProofError):
                mpt.verify_proof(t.root, k, pr[:-1])
            with self.assertRaises(ProofError):
                mpt.verify_proof(t.root, k, pr + [pr[-1]])
        self.assertGreater(inline_seen, 0, "test trie produced no embedded nodes")
        # exclusion: a key that diverges inside the shared prefix and one under an empty branch slot
        for k in (bytes(31) + b"\x01", base[:28] + b"\x09" + base[29:]):
            self.assertIsNone(mpt.verify_proof(t.root, k, t.proof(k)))
        # an embedded node also listed as its own proof element (some clients do this) is accepted,
        # but nothing else may follow
        listed = 0
        for k, v in items.items():
            pr2 = t.proof(k, list_inline=True)
            listed += len(pr2) - len(t.proof(k))
            self.assertEqual(mpt.verify_proof(t.root, k, pr2), v)
            with self.assertRaises(ProofError):
                mpt.verify_proof(t.root, k, pr2 + [pr2[0]])
        self.assertGreater(listed, 0)

    def test_empty_trie(self):
        k = keccak(b"x")
        self.assertIsNone(mpt.verify_proof(EMPTY_TRIE_ROOT, k, []))
        self.assertIsNone(mpt.verify_proof(EMPTY_TRIE_ROOT, k, [b"\x80"]))
        with self.assertRaises(ProofError):
            mpt.verify_proof(EMPTY_TRIE_ROOT, k, [rlp.encode([b"\x20", b"x"])])
        with self.assertRaises(ProofError):
            mpt.verify_proof(keccak(b"\x01"), k, [])

    def _single(self, node, key=bytes(32)):
        enc = rlp.encode(node)
        return mpt.verify_proof(keccak(enc), key, [enc])

    def test_malformed_nodes(self):
        k = bytes(32)
        with self.assertRaises(ProofError):   # branch carrying a value
            self._single([b""] * 16 + [b"v"], k)
        with self.assertRaises(ProofError):   # bad hex-prefix flag
            self._single([b"\x40" + bytes(31), b"v"], k)
        with self.assertRaises(ProofError):   # bad padding nibble on an even path
            self._single([b"\x21" + bytes(31), b"v"], k)
        with self.assertRaises(ProofError):   # leaf shorter than the key
            self._single([b"\x20" + bytes(30), b"v"], k)
        with self.assertRaises(ProofError):   # 3-item node
            self._single([b"a", b"b", b"c"], k)
        with self.assertRaises(ProofError):   # child reference of a wrong length
            self._single([b"\x05" * 20] + [b""] * 16, k)
        with self.assertRaises(ProofError):   # not RLP
            mpt.verify_proof(keccak(b"\xf9\xff"), k, [b"\xf9\xff"])
        self.assertEqual(self._single([b"\x20" + bytes(32), b"v"], k), b"v")      # proper leaf
        self.assertIsNone(self._single([b"\x20" + b"\x01" + bytes(31), b"v"], k))  # other key: absent

    def test_account_and_storage_decoding(self):
        with self.assertRaises(ProofError):
            mpt.decode_account(rlp.encode([b"\x00\x01", 1, b"\x00" * 32, b"\x00" * 32]))  # non-canonical
        with self.assertRaises(ProofError):
            mpt.decode_account(rlp.encode([1, 1, b"\x00" * 31, b"\x00" * 32]))
        with self.assertRaises(ProofError):
            mpt.decode_storage_value(rlp.encode(b"\x00\x05"))
        with self.assertRaises(ProofError):
            mpt.decode_storage_value(rlp.encode(b""))
        self.assertEqual(mpt.decode_storage_value(rlp.encode(b"\x05")), 5)
        self.assertEqual(mpt.norm_slot("0x1"), "0x" + "00" * 31 + "01")
        with self.assertRaises(ProofError):
            mpt.norm_slot("0x1" + "0" * 64)
        with self.assertRaises(ProofError):
            mpt.norm_address("0x1234")


if __name__ == "__main__":
    unittest.main()
