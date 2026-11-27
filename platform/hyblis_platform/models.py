"""Submission / receipt / verdict schemas and validation.

A submission *package* is the object the miner signs. The signed envelope sent to
the gateway is {"package": <package>, "sig": "0x.."}. The signature covers the
canonical encoding of the package exactly as stored, so it stays verifiable
forever.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import canonical_bytes, digest, sha256_hex
from .config import SEVERITIES
from .keys import is_hotkey

ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")
MAX_POC_BYTES = 256 * 1024          # 256 KiB of Solidity is ample for one PoC file
MAX_DESC = 4000
MAX_TITLE = 160


class ValidationError(ValueError):
    pass


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ValidationError(msg)


TOP_KEYS = frozenset({"v", "task_id", "hotkey", "nonce", "ts", "header", "poc", "poc_sha256"})
HEADER_KEYS = frozenset({"title", "contract", "function", "severity", "description"})


def validate_package(pkg: dict, known_tasks: set[str]) -> None:
    """Raise ValidationError if the package is malformed. Does not touch the DB or
    the network; purely structural so the miner CLI can run the same check.

    The key sets are exact: unknown keys are refused, so the canonical encoding is
    the same in every client (Python CLI, browser) and nothing unreviewed is stored.
    """
    _require(isinstance(pkg, dict), "package must be an object")
    _require(set(pkg) == TOP_KEYS, f"package keys must be exactly {sorted(TOP_KEYS)}")
    _require(type(pkg.get("v")) is int and pkg["v"] == 1, "unsupported package version")
    _require(isinstance(pkg.get("task_id"), str) and pkg["task_id"] in known_tasks,
             f"unknown task_id (known: {sorted(known_tasks)})")
    _require(is_hotkey(pkg.get("hotkey")), "hotkey must be a Bittensor address (SS58 format 42)")
    _require(isinstance(pkg.get("nonce"), str) and HEX_RE.match(pkg["nonce"]) and 16 <= len(pkg["nonce"]) <= 128,
             "nonce must be 8 to 64 random bytes of hex")
    # bounded so every client can hold it exactly (a JavaScript number) and the server's
    # time comparison can never overflow
    _require(type(pkg.get("ts")) is int and 1_700_000_000 < pkg["ts"] < 2**53, "ts must be a unix timestamp")

    h = pkg.get("header")
    _require(isinstance(h, dict), "missing header")
    _require(set(h) == HEADER_KEYS, f"header keys must be exactly {sorted(HEADER_KEYS)}")
    _require(isinstance(h.get("title"), str) and 0 < len(h["title"]) <= MAX_TITLE, "title length")
    _require(isinstance(h.get("contract"), str) and ADDR_RE.match(h["contract"]), "header.contract must be an address")
    _require(isinstance(h.get("function"), str) and 0 < len(h["function"]) <= 120, "header.function")
    _require(h.get("severity") in SEVERITIES, f"severity must be one of {SEVERITIES}")
    _require(isinstance(h.get("description"), str) and 0 < len(h["description"]) <= MAX_DESC, "description length")

    poc = pkg.get("poc")
    _require(isinstance(poc, str) and poc.strip(), "missing poc source")
    try:
        poc_bytes = poc.encode("utf-8")
        canonical_bytes(pkg)            # every string must be valid Unicode (no lone surrogates)
    except (UnicodeError, TypeError, ValueError):
        raise ValidationError("package contains text that is not valid Unicode")
    _require(len(poc_bytes) <= MAX_POC_BYTES, f"poc too large (> {MAX_POC_BYTES} bytes)")
    _require(pkg.get("poc_sha256") == sha256_hex(poc_bytes), "poc_sha256 does not match poc")


def submission_id(pkg: dict) -> str:
    """Content address of the package: its canonical sha256. Two identical
    packages share an id; any change (including the nonce) yields a new one."""
    return digest(pkg)


@dataclass(frozen=True)
class Receipt:
    submission_id: str
    poc_sha256: str
    received_at: float      # finalized/server unix time
    task_id: str
    hotkey: str
    server_sig: str = ""    # signed by the server key when configured

    def signing_payload(self) -> dict:
        return {
            "submission_id": self.submission_id,
            "poc_sha256": self.poc_sha256,
            "received_at": self.received_at,
            "task_id": self.task_id,
            "hotkey": self.hotkey,
        }


def canonical_package_bytes(pkg: dict) -> bytes:
    return canonical_bytes(pkg)
