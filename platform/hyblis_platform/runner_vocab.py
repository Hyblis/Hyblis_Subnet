"""The runner's fixed vocabulary, read from the runner's own source files.

The runner (runner/trace_verdict.py, runner/run_submission.py) owns the error codes, their plain-words
explanations, the cheatcode allowlist and the pinned Foundry version. The platform shows them to
researchers, so it reads them from those files instead of keeping a copy: each value is a literal
assignment at module level, taken from the parsed source with ast.literal_eval. Nothing is imported
or executed (trace_verdict imports eth_abi and the runner may only ever run on its own machine).
platform/tests/e2e.py checks that what is read here equals the runner modules' own values.
"""
from __future__ import annotations

import ast
from pathlib import Path

from . import config

RUNNER_DIR = config.ROOT / "runner"


def _literals(path: Path, names: tuple[str, ...]) -> dict:
    tree = ast.parse(path.read_text(), filename=str(path))
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in names and name not in out:
                out[name] = ast.literal_eval(node.value)
    missing = [n for n in names if n not in out]
    if missing:
        raise RuntimeError(f"{path.name}: no literal assignment of {', '.join(missing)}")
    return out


_tv = _literals(RUNNER_DIR / "trace_verdict.py",
                ("ERRORS", "RETRY_ERRORS", "ALLOW", "RULED", "EXPECT_NAMES", "FOUNDRY_VERSION", "ENGINE_VERSION"))
_rs = _literals(RUNNER_DIR / "run_submission.py", ("FORGE_VERSION",))

ERRORS: dict[str, str] = dict(_tv["ERRORS"])          # code -> plain-words explanation
RETRY_ERRORS: tuple = tuple(_tv["RETRY_ERRORS"])      # runner faults: retried, never a judgement
ALLOW: frozenset = frozenset(_tv["ALLOW"])            # cheatcodes allowed without an argument rule
RULED: dict[str, str] = dict(_tv["RULED"])            # cheatcodes allowed under an argument rule
EXPECT_NAMES: frozenset = frozenset(_tv["EXPECT_NAMES"])
FOUNDRY_BUILD: str = _tv["FOUNDRY_VERSION"]           # e.g. "1.9.0-6056c58"
FORGE_VERSION: str = _rs["FORGE_VERSION"]             # e.g. "1.9.0"; the runner refuses any other
ENGINE_VERSION: str = _tv["ENGINE_VERSION"]


def explain(code: str | None) -> str:
    """The fixed explanation of an error code ("policy:<signature>" uses the "policy" text)."""
    return ERRORS.get(str(code or "").split(":", 1)[0], "")


# The cheatcodes a PoC may use, as researchers read them (runner/README.md, rule 7). Every name of
# ALLOW and RULED appears here, and nothing else besides the assert/expect families
# (platform/tests/e2e.py keeps the two in step).
ALLOWED_CHEATCODES = [
    ["prank, startPrank", "1 or 2 arguments, only as your own accounts"],
    ["stopPrank", ""],
    ["warp, roll", "forward only, within the program's limits"],
    ["createSelectFork", "once, in setUp(), at the pinned block, through HYBLIS_ETH_RPC"],
    ["envString", "only HYBLIS_ETH_RPC"],
    ["sign, signCompact", "only with your own keys from makeAddrAndKey"],
    ["addr, label, getLabel, load", ""],
    ["recordLogs, getRecordedLogs", ""],
    ["getBlockTimestamp, getBlockNumber, getNonce, getChainId", ""],
    ["assume, lastCallGas, toString", ""],
    ["computeCreateAddress, computeCreate2Address", ""],
    ["assert*", "allowed, but ignored by the runner"],
    ["expectRevert*, expectPartialRevert*, expectEmit*, expectEmitAnonymous*, expectCall*, expectCallMinGas*",
     "must not be left pending at the end of the test"],
]
