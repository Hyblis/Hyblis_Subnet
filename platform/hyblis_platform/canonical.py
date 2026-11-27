"""Canonical JSON and hashing. Shared by miner, gateway and validators so that a
signature made by a miner verifies byte-for-byte on the server, and so that the
public ledger hash is reproducible by anyone.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic UTF-8 JSON: sorted keys, no insignificant whitespace.

    The same object always produces the same bytes on any machine and Python
    build, which is what the signatures and ledger hashes depend on.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(obj: Any) -> str:
    """sha256 of the canonical encoding of obj."""
    return sha256_hex(canonical_bytes(obj))
