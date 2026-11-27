"""Duplicate detection. Decision: the first *valid* submission wins the credit
(docs/decisions.md, 2026-11-16).

A fingerprint identifies "the same bug", not "the same vulnerability class":
  program + in-scope contract + first in-scope function whose state the proof
  changes + impact type.
The contract, function and impact type come only from the runner's measured
verdict (the in-scope contract and function whose state backs the measured
impact); the miner's signed header never steers dedup. Dedup is therefore decided only once a
submission reaches `validated`, comparing against earlier validated/filed/
accepted submissions by received_at (ties broken by submission_id).
"""
from __future__ import annotations

from .canonical import digest


def fingerprint(program: str, contract: str, function: str, impact_type: str) -> str:
    """Stable id for one bug. Lower-cased and trimmed so trivial spelling
    differences collapse; addresses are already canonical lower-case hex."""
    return digest({
        "program": program.strip().lower(),
        "contract": contract.strip().lower(),
        "function": function.strip().lower(),
        "impact": impact_type.strip().lower(),
    })
