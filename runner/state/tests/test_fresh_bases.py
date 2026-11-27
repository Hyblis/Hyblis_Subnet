"""mapping_bases discovery on a synthetic snapshot (offline): bases after OpenZeppelin's 50-slot gaps are found,
and a discovered base gives the fresh accounts' slots there."""
import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from eth_utils import keccak  # noqa: E402
from state import fresh  # noqa: E402

TOKEN = "0x" + "cd" * 20
HOLDER = "0x" + "11" * 20
FRESH = "0x" + "77" * 20


def slot_of(key: str, base: int) -> int:
    return int.from_bytes(keccak(bytes(12) + bytes.fromhex(key[2:]) + base.to_bytes(32, "big")), "big")


class FakeSnap:
    def __init__(self, digest, rows):
        self.digest = digest
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute('CREATE TABLE accounts (address TEXT, "exists" INTEGER)')
        self.conn.execute("CREATE TABLE storage (address TEXT, slot TEXT, value TEXT)")
        self.conn.executemany('INSERT INTO accounts VALUES (?, 1)', [(TOKEN,), (HOLDER,)])
        self.conn.executemany("INSERT INTO storage VALUES (?, ?, ?)", rows)


class BasesTest(unittest.TestCase):
    def test_gap_layout_base_is_discovered(self):
        for base in (9, 51, 101, 151, 201, 251):
            snap = FakeSnap(f"sha256:test-{base}", [(TOKEN, hex(slot_of(HOLDER, base)), "0x" + "00" * 31 + "05")])
            bases = fresh.mapping_bases(snap)
            self.assertIn(base, bases, base)
            fs = fresh.FreshSet([FRESH], keys=[FRESH], bases=bases)
            self.assertTrue(fs.has_slot(hex(slot_of(FRESH, base))), base)

    def test_nested_id_positions(self):
        """m[user][id] (a lending position per reserve id) and m[id][user], with struct fields."""
        fs = fresh.FreshSet([FRESH], keys=[FRESH], bases=[])
        for base in (4, 15):
            for j in (0, 7, 31):
                user_first = int.from_bytes(keccak(j.to_bytes(32, "big") + keccak(bytes(12) + bytes.fromhex(FRESH[2:])
                                                                                 + base.to_bytes(32, "big"))), "big")
                id_first = int.from_bytes(keccak(bytes(12) + bytes.fromhex(FRESH[2:]) +
                                                 keccak(j.to_bytes(32, "big") + base.to_bytes(32, "big"))), "big")
                for f in (0, 2):
                    self.assertTrue(fs.has_slot(hex(user_first + f)), (base, j, f))
                    self.assertTrue(fs.has_slot(hex(id_first + f)), (base, j, f))
        far = int.from_bytes(keccak((32).to_bytes(32, "big") + keccak(bytes(12) + bytes.fromhex(FRESH[2:]) +
                                                                      (4).to_bytes(32, "big"))), "big")
        self.assertFalse(fs.has_slot(hex(far)), "ids from 32 on are not precomputed")

    def test_unknown_layout_is_not_invented(self):
        snap = FakeSnap("sha256:test-none", [(TOKEN, hex(slot_of(HOLDER, 300)), "0x01")])
        self.assertNotIn(300, fresh.mapping_bases(snap))


if __name__ == "__main__":
    unittest.main()
