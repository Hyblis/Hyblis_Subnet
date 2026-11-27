#!/usr/bin/env python3
"""Hyblis verdict engine: decide a PoC's impact from forge's raw trace (design "trace", 2026-11-16).

Input: the `forge test --json -vvvv` output of the runner-owned HyblisHarness test (pass 1 and pass 2),
the output of the plain standalone run of the PoC file, and the compiled impact spec (gen_spec.py).
Nothing the PoC prints, asserts, labels or returns is read. Every fact comes from forge's raw trace
arena (decoded: null):

  * the root node is the harness frame; its direct children are made only by harness code, and they
    must be exactly the harness program (template);
  * every cheatcode invocation is a node whose address is the cheatcode address, issued by its parent
    frame (parent.address = code address), and is checked against a default-deny policy;
  * the attacker set A is built from the trace: the PoC, contracts A creates, and accounts whose key
    the runner's faucet handed out;
  * capital, trusted-role actions and price moves are the faucet's own records (logs and calldata of
    frames whose code address is HYBLIS_FAUCET, reached by CALL, never by delegatecall);
  * measurements are the raw `output` bytes of the harness's root-level probe.measure() calls on the
    exploited fork (POST) and on a clean fork of the same block at the same final time (BASE);
  * the changed function is the in-scope entry frame whose writes back the measured impact.

The result keeps the verdict shape platform/hyblis_platform/pipeline.py consumes.
CLI (fixtures, debugging): trace_verdict.py <spec.compiled.json> <pass2.json> [--pass1 p1.json]
                           [--standalone s.json] --rpc <url> --salt <hex> [--steps N]
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
from fractions import Fraction
from pathlib import Path

from eth_abi import decode
from eth_utils import keccak

ENGINE_VERSION = "trace-1.1"
FOUNDRY_VERSION = "1.9.0-6056c58"
HERE = Path(__file__).resolve().parent

CHEAT = "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d"
CONSOLE = "0x000000000000000000636f6e736f6c652e6c6f67"
HARNESS = "0x7fa9385be102ac3eac297483dd6233d62b3e1496"        # forge's default test-contract address
DEFAULT_SENDER = "0x1804c8ab1f12e6bbf3894d4083f33e07309d1f38"
CREATE2_DEPLOYER = "0x4e59b44847b379578588920ca78fbf26c0b4956c"
LIBRARY_DEPLOYER = "0x1f95d37f27ea0dea9c252fc09d5a6eaa97647353"   # forge's fixed sender for linked libraries
FAUCET = "0x" + keccak(text="hyblis.faucet")[-20:].hex()
SALT_SLOT = "0x" + keccak(text="hyblis.salt").hex()
ZERO = "0x" + "0" * 40
EMPTY_CODEHASH = "0x" + keccak(b"").hex()
SUITE = "test/hyblis/HyblisHarness.t.sol:HyblisHarness"
TEST = "test_hyblis()"
STANDALONE_SUITE = "test/hyblis/HyblisPoC.t.sol:HyblisPoC"
STANDALONE_TEST = "test_exploit()"
SENTINEL = 2 ** 256 - 1
SEVERITIES = ["low", "medium", "high", "critical"]

# forge 1.9.0 JSON layout (format drift fails closed)
RESULT_KEYS = {"status", "reason", "fork_block_number", "counterexample", "logs", "decoded_logs", "kind", "traces",
               "labeled_addresses", "duration", "breakpoints", "gas_snapshots"}
ARENA_KEYS = {"arena"}
NODE_KEYS = {"parent", "children", "idx", "trace", "logs", "ordering"}
TRACE_KEYS = {"depth", "success", "caller", "address", "maybe_precompile", "selfdestruct_address",
              "selfdestruct_refund_target", "selfdestruct_transferred_value", "kind", "value", "data", "output",
              "bytecode", "gas_used", "gas_limit", "gas_refund_counter", "status", "steps", "step_deltas", "decoded"}
LOG_KEYS = {"address", "raw_log", "decoded", "position", "index"}
RAW_LOG_KEYS = {"topics", "data"}
CALL_KINDS = ("CALL", "STATICCALL", "DELEGATECALL", "CALLCODE")
CREATE_KINDS = ("CREATE", "CREATE2")
OOG_STATUSES = frozenset({"OutOfGas", "MemoryOOG", "MemoryLimitOOG", "PrecompileOOG", "InvalidOperandOOG",
                          "ReentrancySentryOOG"})

# ------------------------------------------------------------------ error vocabulary (fixed)
# Codes are what pipeline.py stores and the gateway may show; detail strings are runner-written only
# (cheatcode names from our table, hex addresses, counts), never PoC-controlled text.
ERRORS = {
    "state_miss": "The runner's copy of the pinned chain state does not hold something your PoC reads. The job "
                  "waits until the operator extends the snapshot, then runs again. Nothing is wrong with your PoC.",
    "runner_error": "The runner failed for a reason unrelated to your PoC. The job is retried.",
    "screen": "The static screen rejected the file before it ran. Fix the listed lines.",
    "poc_shape": "The file is not in the required shape: one contract HyblisPoC (no constructor arguments) with "
                 "setUp() and exactly one test, test_exploit(); optional public step1()..stepN() numbered without "
                 "gaps; no imports of runner files.",
    "compile": "The file does not compile against the task project.",
    "no_json": "forge produced no readable result. This happens when a test hides trace data "
               "(vm.pauseTracing) or crashes forge.",
    "limits": "A size or time limit was exceeded (output size, run time, gas, attacker accounts or steps). Each PoC "
              "call (constructor, setUp(), test_exploit() or a step) may use at most the task's poc_gas.",
    "template": "The runner's own test did not run exactly its fixed program, or forge's output is not in the "
                "expected format. The PoC was not judged.",
    "harness_failed": "The runner's test failed after your PoC returned. Usual cause: an expectation "
                      "(vm.expectCall, vm.expectEmit, vm.expectRevert) left pending at the end of your test.",
    "policy": "Your PoC used a cheatcode that is not allowed, or called a cheatcode or a Hyblis helper with "
              "arguments that are not in canonical ABI encoding. Even an attempt counts, also inside helper "
              "contracts, constructors and reverted calls.",
    "impersonation": "Your PoC acted (prank or signature) as an account it does not control. Act only as "
                     "accounts from makeAddr/makeAddrAndKey, contracts you deploy, or the PoC itself.",
    "fork": "Fork exactly once, in setUp(): vm.createSelectFork(vm.envString(\"HYBLIS_ETH_RPC\"), FORK_BLOCK) "
            "at the task's pinned block.",
    "env": "Your PoC read an environment variable other than HYBLIS_ETH_RPC.",
    "time": "vm.warp/vm.roll moved time backwards or beyond the task's limits.",
    "reentry": "Your PoC reached the runner's own contracts (harness, probe, faucet) in a way that is not "
               "allowed, or used a cheatcode outside its own call frames.",
    "capital": "Capital rules broken: fund only tokens the task lists as capital, only accounts you control, "
               "and stay within the task's cap. Use _fund(); do not use deal/hoax/vm.deal outside it.",
    "helper": "A trusted helper was used outside what the task allows (_asRole: listed roles, targets, "
              "functions and arguments only; _setPrice: listed feeds, within the bound).",
    "poc_reverted": "Your setUp(), test_exploit() or a step reverted when run by the runner (your PoC runs as "
                    "a contract called by the runner: do not rely on msg.sender, address(this), the test "
                    "contract's default ETH balance, gas, or the RPC URL).",
    "measurement_failed": "The runner could not measure the protocol reliably (a balance read failed, watched "
                          "code changed, or one of your accounts already held state at the pinned block).",
    "nondeterministic": "Two identical runs of your PoC behaved differently.",
    "standalone_fails": "The file does not pass in plain forge test (as the bounty platform runs it).",
    "standalone_differs": "In plain forge test the file does something else than under the runner: different calls "
                          "into in-scope contracts (or with another outcome), different state-changing cheatcodes "
                          "or helper calls (prank, warp, roll, fork, _fund, deal, _asRole, _setPrice), or a "
                          "cheatcode the runner does not allow.",
    "no_impact": "Your PoC ran, but the runner measured no in-scope impact on the protocol (no loss, freeze, "
                 "insolvency, unbacked mint or broken invariant above the task's threshold). Asserts and logs "
                 "are ignored.",
    "out_of_scope": "The measured impact is out of scope for this task (impact type not in scope, not caused "
                    "by an in-scope contract, or only through a benign entry point such as a normal liquidation).",
    "known_issue": "The measured impact matches a known issue of this program.",
}
RETRY_ERRORS = ("state_miss", "runner_error")


class Reject(Exception):
    def __init__(self, code: str, detail: str = ""):
        base = code.split(":", 1)[0]
        assert base in ERRORS, code
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def explain(code: str) -> str:
    return ERRORS.get((code or "").split(":", 1)[0], "")


# ------------------------------------------------------------------ cheatcode policy (default deny)
ALLOW = {  # issued by attacker-controlled code, no argument rule
    "label(address,string)", "getLabel(address)", "stopPrank()", "recordLogs()", "getRecordedLogs()",
    "load(address,bytes32)", "getBlockTimestamp()", "getBlockNumber()", "getNonce(address)", "getChainId()",
    "assume(bool)", "computeCreateAddress(address,uint256)", "computeCreate2Address(bytes32,bytes32,address)",
    "computeCreate2Address(bytes32,bytes32)", "toString(uint256)", "toString(int256)", "toString(address)",
    "toString(bool)", "toString(bytes32)", "toString(bytes)", "addr(uint256)", "lastCallGas()",
}
RULED = {
    "prank(address)": "prank", "startPrank(address)": "prank",
    "prank(address,address)": "prank", "startPrank(address,address)": "prank",
    "warp(uint256)": "warp", "roll(uint256)": "roll",
    "createSelectFork(string,uint256)": "fork", "envString(string)": "env",
    "sign(uint256,bytes32)": "sign", "signCompact(uint256,bytes32)": "sign",
}
EXPECT_NAMES = {"expectRevert", "expectPartialRevert", "expectEmit", "expectEmitAnonymous", "expectCall",
                "expectCallMinGas"}
FAUCET_FUNCS = {
    "fund(address,address,uint256)": {"record()", "accesses(address)", "load(address,bytes32)",
                                      "store(address,bytes32,bytes32)", "deal(address,uint256)",
                                      "startMappingRecording()", "stopMappingRecording()",
                                      "getMappingKeyAndParentOf(address,bytes32)", "stopRecord()",
                                      "toString(uint256)", "toString(address)", "toString(bytes32)",
                                      "toString(bytes)", "toString(bool)", "toString(int256)"},
    "attackerKey(string)": {"addr(uint256)"},
    "asRole(address,address,bytes)": {"prank(address)"},
    "setPrice(address,int256)": {"mockCall(address,bytes,bytes)"},
}
# PoC cheatcodes that change what later calls do; plain forge test must make the same ones, in the same order
STATEFUL = ("prank(address)", "startPrank(address)", "prank(address,address)", "startPrank(address,address)",
            "stopPrank()", "warp(uint256)", "roll(uint256)", "createSelectFork(string,uint256)")
# HyblisBase's helper frames (functions of the PoC itself; the runner's own copy of HyblisBase.sol): under the
# runner each one calls the faucet, in plain forge test it issues forge-std cheatcodes. Value: the faucet function
# whose cheatcode rules apply to that frame in plain forge test.
HELPER_FRAMES = {
    "hyblisFund(address,address,uint256)": "fund(address,address,uint256)",
    "hyblisDeal(address,address,uint256)": "fund(address,address,uint256)",
    "hyblisAsRole(address,address,bytes)": "asRole(address,address,bytes)",
    "hyblisSetPrice(address,int256)": "setPrice(address,int256)",
}
DEPLOY_SIG = "hyblisDeploy(bytes32)"        # root call [10]: the harness deploys the PoC in a call capped at POC_GAS
EV_FUNDED = keccak(text="Funded(address,address,uint256,uint256)").hex()
EV_ATTACKER = keccak(text="Attacker(bytes32,address,address)").hex()
M_SIG = "measure(address[],address[],address[],bytes[],address[])"
M_OUT = ["uint256[]", "bool[]", "bytes[]", "bytes32[]", "bytes32[]"]
T_ACC = ("((uint256,uint256),uint8,address,address,bool,uint256,uint256,bytes,uint256,bytes,bool,"
         "(address,bytes32,bool,bytes32,bytes32,bool)[],uint64,uint64,uint64)[]")


def sel(sig: str) -> str:
    return keccak(text=sig)[:4].hex()


def split_types(sig: str) -> list[str]:
    inner = sig[sig.index("(") + 1:-1]
    out, depth, cur = [], 0, ""
    for ch in inner:
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    if cur:
        out.append(cur)
    return out


def load_selector_table(path: Path | None = None) -> dict[str, str]:
    data = json.loads((path or HERE / "vm_selectors.json").read_text())
    table = {s.lower(): sig for sig, s in data["selectors"].items()}
    for sig in list(ALLOW) + list(RULED) + [s for v in FAUCET_FUNCS.values() for s in v]:
        if sel(sig) not in table:
            raise RuntimeError(f"selector table lacks {sig}")
    return table


def is_assert_or_expect(sig: str) -> bool:
    name = sig.split("(")[0]
    return name.startswith("assert") or name in EXPECT_NAMES


# ------------------------------------------------------------------ forge JSON
def _no_constants(name):
    raise ValueError(f"JSON constant {name} not allowed")


def load_forge_json(path: str | os.PathLike, max_bytes: int) -> dict:
    """Strict, size-capped load. A truncated or oversized file is never parsed."""
    p = Path(path)
    if not p.exists():
        raise Reject("no_json", "forge wrote no output")
    size = p.stat().st_size
    if size == 0:
        raise Reject("no_json", "forge wrote no output")
    if size > max_bytes:
        raise Reject("limits", f"forge output {size} bytes is above the cap {max_bytes}")
    with open(p, "rb") as f:
        raw = f.read(max_bytes + 1)
    try:
        doc = json.loads(raw, parse_constant=_no_constants)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Reject("no_json", "forge output is not valid JSON") from None
    if not isinstance(doc, dict):
        raise Reject("no_json", "forge output is not a JSON object")
    return doc


_HEX = re.compile(r"0x[0-9a-fA-F]*")
_ADDR = re.compile(r"0x[0-9a-fA-F]{40}")
_WORD = re.compile(r"0x[0-9a-fA-F]{64}")


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _is_hex(v, even: bool = True) -> bool:
    return isinstance(v, str) and _HEX.fullmatch(v) is not None and (not even or len(v) % 2 == 0)


def _is_addr(v) -> bool:
    return isinstance(v, str) and _ADDR.fullmatch(v) is not None


def _log_ok(lg) -> bool:
    if not isinstance(lg, dict) or set(lg) != LOG_KEYS or not isinstance(lg["raw_log"], dict) or \
            set(lg["raw_log"]) != RAW_LOG_KEYS:
        return False
    raw = lg["raw_log"]
    return _is_addr(lg["address"]) and (lg["decoded"] is None or isinstance(lg["decoded"], dict)) and \
        _is_int(lg["position"]) and \
        _is_int(lg["index"]) and isinstance(raw["topics"], list) and len(raw["topics"]) <= 4 and \
        all(isinstance(x, str) and _WORD.fullmatch(x) for x in raw["topics"]) and _is_hex(raw["data"])


def _ordering_ok(o) -> bool:
    return isinstance(o, dict) and len(o) == 1 and next(iter(o)) in ("Call", "Log") and _is_int(next(iter(o.values())))


def _check_node_format(n, kind):
    """Every key and the type of every value the engine reads (forge 1.9.0 layout). A value of another type is
    forge output the engine was not built for: it fails closed as `template`, never as a crash (a crash would
    be a retried runner_error)."""
    if not isinstance(n, dict) or set(n) != NODE_KEYS:
        raise Reject("template", f"{kind} arena node keys changed")
    t = n["trace"]
    if not isinstance(t, dict) or set(t) != TRACE_KEYS:
        raise Reject("template", f"{kind} arena trace keys changed")
    ok = ((n["parent"] is None or _is_int(n["parent"])) and _is_int(n["idx"]) and
          isinstance(n["children"], list) and all(_is_int(c) for c in n["children"]) and
          isinstance(n["logs"], list) and all(_log_ok(lg) for lg in n["logs"]) and
          isinstance(n["ordering"], list) and all(_ordering_ok(o) for o in n["ordering"]) and
          _is_int(t["depth"]) and isinstance(t["success"], bool) and _is_addr(t["caller"]) and
          _is_addr(t["address"]) and t["maybe_precompile"] in (None, True, False) and
          t["kind"] in CALL_KINDS + CREATE_KINDS and (_is_hex(t["value"], even=False) or _is_int(t["value"])) and
          _is_hex(t["data"]) and _is_hex(t["output"]) and (t["bytecode"] is None or _is_hex(t["bytecode"])) and
          _is_int(t["gas_used"]) and _is_int(t["gas_limit"]) and _is_int(t["gas_refund_counter"]) and
          isinstance(t["status"], str) and isinstance(t["steps"], list) and isinstance(t["step_deltas"], list) and
          (t["decoded"] is None or isinstance(t["decoded"], dict)) and         # forge's own notes; never read
          (t["selfdestruct_address"] is None or _is_addr(t["selfdestruct_address"])) and
          (t["selfdestruct_refund_target"] is None or _is_addr(t["selfdestruct_refund_target"])) and
          (t["selfdestruct_transferred_value"] is None or _is_hex(t["selfdestruct_transferred_value"], even=False) or
           _is_int(t["selfdestruct_transferred_value"])))
    if not ok:
        raise Reject("template", f"{kind} arena node {n.get('idx')} holds a value of an unexpected type")


def _check_links(nodes, kind):
    """Node i's parent comes before it and lists it exactly once among its children; only node 0 is a root."""
    seen = [0] * len(nodes)
    for i, n in enumerate(nodes):
        p = n["parent"]
        if (i == 0) != (p is None) or (p is not None and not p < i):
            raise Reject("template", f"{kind} arena node {i} has a bad parent")
        for c in n["children"]:
            if not i < c < len(nodes) or nodes[c]["parent"] != i:
                raise Reject("template", f"{kind} arena node {i} has a bad child")
            seen[c] += 1
    if any(seen[i] != 1 for i in range(1, len(nodes))):
        raise Reject("template", f"{kind} arena children and parents do not match")


def _check_library_arena(nodes) -> None:
    root = nodes[0]
    t = T(root)
    if len(nodes) != 2 or root["parent"] is not None or t["kind"] != "CALL" or caller(root) != LIBRARY_DEPLOYER \
            or addr(root) != CREATE2_DEPLOYER or not t["success"] or root["children"] != [1] or root["logs"]:
        raise Reject("template", "a leading deployment is not a plain library deployment")
    c = nodes[1]
    tc = T(c)
    if c["parent"] != 0 or tc["kind"] != "CREATE2" or caller(c) != CREATE2_DEPLOYER or not tc["success"] \
            or c["children"] or c["logs"] or _int_value(t["value"]) or _int_value(tc["value"]):
        raise Reject("template", "a leading deployment is not a plain library deployment")


def _int_value(v) -> int:
    return int(v, 16) if isinstance(v, str) else int(v or 0)


def extract_result(doc: dict, suite: str, test: str) -> tuple[dict, dict]:
    if list(doc.keys()) != [suite]:
        raise Reject("template", "unexpected test suites in forge output")
    s = doc[suite]
    if not isinstance(s, dict) or not isinstance(s.get("test_results"), dict):
        raise Reject("template", "forge output has no test results")
    tests = s["test_results"]
    if list(tests.keys()) != [test]:
        raise Reject("template", "unexpected tests in forge output")
    r = tests[test]
    if not isinstance(r, dict) or not (set(r) == RESULT_KEYS or set(r) == RESULT_KEYS - {"fork_block_number"}):
        raise Reject("template", "forge test-result keys changed")    # (no fork_block_number when nothing forked)
    if not isinstance(r["status"], str):
        raise Reject("template", "forge test status malformed")
    arenas = {}
    items = r["traces"]
    if not isinstance(items, list):
        raise Reject("template", "traces malformed")
    # A project with external (linked) libraries: forge 1.9.0 deploys each one before the test contract, in its
    # own leading "Deployment" arena (found on the Cap project, 2026-11-16). Accepted only in exactly that shape:
    # a CALL from forge's library deployer to the CREATE2 factory whose only child is one successful CREATE2,
    # nothing else (Solidity libraries have no constructor code). The last Deployment arena is the test contract.
    n_dep = sum(1 for it in items if isinstance(it, list) and len(it) == 2 and it[0] == "Deployment")
    libs_left = max(0, n_dep - 1)
    for item in items:
        if not (isinstance(item, list) and len(item) == 2):
            raise Reject("template", "trace entry malformed")
        kind, a = item
        lib = kind == "Deployment" and libs_left > 0
        if kind not in ("Deployment", "Setup", "Execution") or (kind in arenas and not lib):
            raise Reject("template", "unexpected trace arena")
        if not isinstance(a, dict) or set(a) != ARENA_KEYS:       # e.g. 'ignored' from vm.pauseTracing
            raise Reject("template", f"{kind} arena carries unexpected keys")
        nodes = a["arena"]
        if not isinstance(nodes, list) or not nodes:
            raise Reject("template", f"{kind} arena empty")
        for i, n in enumerate(nodes):
            _check_node_format(n, kind)
            if n["idx"] != i:
                raise Reject("template", f"{kind} arena out of order")
        _check_links(nodes, kind)
        if lib:
            if kind in arenas or "Setup" in arenas or "Execution" in arenas:
                raise Reject("template", "library deployment after the test contract")
            _check_library_arena(nodes)
            arenas.setdefault("Libraries", []).append(nodes)
            libs_left -= 1
            continue
        arenas[kind] = nodes
    if "Execution" not in arenas:
        raise Reject("template", "no execution trace (verbosity below -vvv?)")
    return r, arenas


def T(n):
    return n["trace"]


def addr(n) -> str:
    return T(n)["address"].lower()


def caller(n) -> str:
    return T(n)["caller"].lower()


def data_hex(n) -> str:
    d = T(n)["data"]
    return d[2:] if d.startswith("0x") else d


def sel_of(n) -> str:
    return data_hex(n)[:8].lower()


def out_bytes(n) -> bytes:
    o = T(n)["output"]
    return bytes.fromhex(o[2:] if o.startswith("0x") else o)


def args_of(n, sig) -> tuple:
    """Arguments of a call the runner's own code made (harness, faucet): anything else than canonical ABI is not
    the runner's program."""
    try:
        return decode(split_types(sig), bytes.fromhex(data_hex(n)[8:]))
    except Exception:
        raise Reject("template", f"cannot decode arguments of {sig}") from None


_STATIC_WORD = ("address", "uint256", "int256", "bytes32")


def poc_args(n, sig, code: str | None = None) -> tuple:
    """Arguments of a cheatcode or faucet call the PoC made. forge decodes cheatcode arguments without validating
    them (an address is the low 20 bytes of its word, whatever the high bytes hold), so arguments made only of
    such words are read the same way when they are not canonical. Anything else that eth_abi cannot decode
    strictly is rejected (`policy:<sig>` by default): the runner never guesses what forge did with it."""
    raw = bytes.fromhex(data_hex(n)[8:])
    types = split_types(sig)
    try:
        return decode(types, raw)
    except Exception:
        pass
    if types and all(ty in _STATIC_WORD for ty in types) and len(raw) >= 32 * len(types):
        out = []
        for k, ty in enumerate(types):
            w = raw[32 * k: 32 * k + 32]
            if ty == "address":
                out.append("0x" + w[12:].hex())
            elif ty == "int256":
                out.append(int.from_bytes(w, "big", signed=True))
            elif ty == "uint256":
                out.append(int.from_bytes(w, "big"))
            else:
                out.append(w)
        return tuple(out)
    raise Reject(code or f"policy:{sig}", f"arguments of {sig} are not in canonical ABI encoding")


def subtree(nodes, i) -> list[int]:
    out, stack = [], [i]
    while stack:
        j = stack.pop()
        out.append(j)
        stack.extend(nodes[j]["children"])
    return sorted(out)


def effective(nodes, i) -> bool:
    """The node and all its ancestors succeeded (its state changes were kept)."""
    while i is not None:
        if not T(nodes[i])["success"]:
            return False
        i = nodes[i]["parent"]
    return True


def canon(nodes, idxs) -> str:
    keep = ("depth", "success", "caller", "address", "kind", "value", "data", "output", "gas_used", "gas_limit",
            "status", "selfdestruct_address", "selfdestruct_refund_target", "selfdestruct_transferred_value")
    h = hashlib.sha256()
    for i in idxs:
        n = nodes[i]
        row = [{k: T(n).get(k) for k in keep}, hashlib.sha256((T(n).get("bytecode") or "").encode()).hexdigest(),
               [lg.get("raw_log") for lg in n["logs"]], n["ordering"], len(n["children"])]
        h.update(json.dumps(row, sort_keys=True).encode())
    return h.hexdigest()


# ------------------------------------------------------------------ expressions (invariants)
_EXPR_NODES = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Compare, ast.BoolOp, ast.Name, ast.Load, ast.Constant,
               ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod, ast.USub, ast.Not, ast.And, ast.Or, ast.Gt,
               ast.GtE, ast.Lt, ast.LtE, ast.Eq, ast.NotEq)


def safe_eval(expr: str, env: dict):
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, _EXPR_NODES):
            raise ValueError(f"expression node {type(node).__name__} not allowed")
        if isinstance(node, ast.Name) and env.get(node.id) is None:
            raise ValueError(f"unknown value {node.id}")
    return eval(compile(tree, "<spec>", "eval"), {"__builtins__": {}}, env)


# ------------------------------------------------------------------ one harness pass
class Ctx:
    def __init__(self, spec: dict, rpc_url: str, salt: str, steps: int, attacker_set: list[str] | None,
                 table: dict, expected_code: dict | None = None):
        self.spec = spec
        self.rpc_url = rpc_url
        self.salt = salt.lower()
        self.steps = steps
        self.attacker_set = [a.lower() for a in (attacker_set or [])]
        self.table = table
        self.expected_code = expected_code or {}


def analyze_pass(doc: dict, ctx: Ctx) -> dict:
    spec = ctx.spec
    res, arenas = extract_result(doc, SUITE, TEST)
    ex = arenas["Execution"]
    root = ex[0]
    if root["parent"] is not None or T(root)["depth"] != 0 or addr(root) != HARNESS or \
            T(root)["kind"] != "CALL" or sel_of(root) != sel(TEST):
        raise Reject("template", "root frame is not the harness test")
    dep = arenas.get("Deployment", [])
    if len(dep) != 1 or T(dep[0])["kind"] != "CREATE" or addr(dep[0]) != HARNESS or dep[0]["children"]:
        raise Reject("template", "harness deployment is not a single plain CREATE")
    if "Setup" in arenas:
        raise Reject("template", "the harness has no setUp, yet a Setup arena exists")
    kids = root["children"]
    K = [ex[i] for i in kids]
    steps = ctx.steps
    m = max(1, steps)
    harness_ok = res["status"] == "Success"

    def expect(k, kind, target, sig=None):
        if k >= len(K):
            raise Reject("harness_failed" if not harness_ok else "template", f"harness stopped before step {k}")
        n = K[k]
        if T(n)["kind"] != kind or (target and addr(n) != target) or (sig and sel_of(n) != sel(sig)):
            raise Reject("template", f"harness program differs at root call {k}")
        return n

    def out_decode(n, types):
        try:
            return decode(types, out_bytes(n))
        except Exception:
            raise Reject("template", "cannot decode a harness cheatcode result") from None

    # ---- 1. the harness program before the PoC (root children 0..12)
    n0 = expect(0, "STATICCALL", CHEAT, "envString(string)")
    if args_of(n0, "envString(string)") != ("HYBLIS_ETH_RPC",) or out_decode(n0, ["string"])[0] != ctx.rpc_url:
        raise Reject("template", "harness read a different RPC")
    n1 = expect(1, "STATICCALL", CHEAT, "envBytes32(string)")
    if args_of(n1, "envBytes32(string)") != ("HYBLIS_SALT",) or "0x" + out_decode(n1, ["bytes32"])[0].hex() != ctx.salt:
        raise Reject("template", "harness read a different salt")
    n2 = expect(2, "STATICCALL", CHEAT, "envUint(string)")
    if args_of(n2, "envUint(string)") != ("HYBLIS_STEPS",) or out_decode(n2, ["uint256"])[0] != steps:
        raise Reject("template", "harness read a different step count")
    probe = addr(expect(3, "CREATE", None))
    if not T(K[3])["success"]:
        raise Reject("template", "probe deployment failed")
    if args_of(expect(4, "CALL", CHEAT, "makePersistent(address)"), "makePersistent(address)")[0].lower() != probe:
        raise Reject("template", "probe not made persistent")
    etch = expect(5, "CALL", CHEAT, "etch(address,bytes)")
    e_to, e_code = args_of(etch, "etch(address,bytes)")
    if e_to.lower() != FAUCET:
        raise Reject("template", "faucet etched elsewhere")
    if ctx.expected_code.get("faucet") and hashlib.sha256(e_code).hexdigest() != ctx.expected_code["faucet"]:
        raise Reject("template", "faucet code differs from the runner's build")
    if ctx.expected_code.get("probe") and hashlib.sha256(out_bytes(K[3])).hexdigest() != ctx.expected_code["probe"]:
        raise Reject("template", "probe code differs from the runner's build")
    st = args_of(expect(6, "CALL", CHEAT, "store(address,bytes32,bytes32)"), "store(address,bytes32,bytes32)")
    if st[0].lower() != FAUCET or "0x" + st[1].hex() != SALT_SLOT or "0x" + st[2].hex() != ctx.salt:
        raise Reject("template", "salt not stored in the faucet")
    if args_of(expect(7, "CALL", CHEAT, "makePersistent(address)"), "makePersistent(address)")[0].lower() != FAUCET:
        raise Reject("template", "faucet not made persistent")
    if args_of(expect(8, "CALL", CHEAT, "allowCheatcodes(address)"), "allowCheatcodes(address)")[0].lower() != FAUCET:
        raise Reject("template", "cheatcodes granted to another account")
    expect(9, "CALL", CHEAT, "startStateDiffRecording()")
    # [10] the harness calls its own hyblisDeploy(salt) with a gas cap; its only child is the PoC's CREATE2
    deploy = expect(10, "CALL", HARNESS, DEPLOY_SIG)
    if caller(deploy) != HARNESS or _value(deploy) or \
            "0x" + args_of(deploy, DEPLOY_SIG)[0].hex() != ctx.salt or len(deploy["children"]) != 1:
        raise Reject("template", "the PoC deployment call differs from the harness program")
    poc_create = ex[deploy["children"][0]]
    if T(poc_create)["kind"] != "CREATE2" or caller(poc_create) != HARNESS:
        raise Reject("template", "the PoC is not deployed by the harness's CREATE2")
    if T(poc_create)["success"] and not T(deploy)["success"]:
        raise Reject("template", "the PoC deployment call failed after the PoC was created")
    poc = addr(poc_create)
    poc_roots = [kids[10]]
    poc_frames = [(poc_create["idx"], kids[10], "constructor")]   # (PoC frame, the root call that caps its gas, name)
    if T(poc_create)["success"]:
        if args_of(expect(11, "CALL", CHEAT, "makePersistent(address)"), "makePersistent(address)")[0].lower() != poc:
            raise Reject("template", "PoC not made persistent")
        expect(12, "CALL", poc, "setUp()")
        poc_roots.append(kids[12])
        poc_frames.append((kids[12], kids[12], "setUp()"))
        step_sigs = [spec["poc_test"]] if steps == 0 else [f"step{k}()" for k in range(1, steps + 1)]
        for j, ssig in enumerate(step_sigs):
            if 13 + j < len(K):
                expect(13 + j, "CALL", poc, ssig)
                poc_roots.append(kids[13 + j])
                poc_frames.append((kids[13 + j], kids[13 + j], ssig))
    poc_nodes: set[int] = set()
    for r_i in poc_roots:
        poc_nodes.update(subtree(ex, r_i))
    setup_nodes = set(subtree(ex, kids[12])) if len(K) > 12 else set()

    # ---- 2. every node: ownership, cheatcode policy, attacker set, faucet use
    protected = set(spec["protected"]) | {HARNESS, probe, FAUCET, CHEAT, CONSOLE, CREATE2_DEPLOYER, DEFAULT_SENDER,
                                          ZERO}
    A = {poc}
    A_order = [poc]
    created: list[str] = []                     # contracts created by A, in execution order
    eoas: dict[str, str] = {}                   # runner EOA -> address plain forge test gives the same name
    issued_keys: set[int] = set()
    forks_seen = 0
    ts_now, bn_now = spec["fork"]["timestamp"], spec["fork"]["block"]
    max_warp, max_roll = spec["limits"]["max_warp_s"], spec["limits"]["max_roll"]
    capital_tokens = {t["address"]: t for t in spec["tokens"] if t["capital"]}
    capital: dict[str, int] = {}
    role_calls: dict[str, int] = {}
    feeds = {f["feed"]: f for f in spec["price_feeds"]}
    price_moves: dict[str, int] = {}
    helpers_used = {"fund": 0, "asRole": 0, "setPrice": 0, "attackerKey": 0}
    faucet_fn = {s: sig for sig in FAUCET_FUNCS for s in [sel(sig)]}
    helper_fn = {sel(sig): sig for sig in HELPER_FRAMES}
    helper_frames: set[int] = set()
    events: list = []                           # state-changing cheatcodes and helper calls, in order (7.11)

    def add_attacker(a):
        if a in protected:
            raise Reject("impersonation", f"attacker account {a} is a protected address")
        if a not in A:
            A.add(a)
            A_order.append(a)

    for n in ex[1:]:
        t = T(n)
        a = addr(n)
        i = n["idx"]
        p = ex[n["parent"]]
        in_poc = i in poc_nodes
        if a == HARNESS and i != kids[10]:
            raise Reject("reentry", "the harness was called again")
        if a == poc and in_poc and t["kind"] == "CALL" and sel_of(n) in helper_fn:
            hsig = helper_fn[sel_of(n)]          # HyblisBase's own helper frame (fixed code): it calls the faucet
            helper_frames.add(i)
            events.append(_event(hsig, poc_args(n, hsig), t["success"]))
        if a == probe and p is not root:
            raise Reject("reentry", "the probe was called from outside the harness")
        if t["kind"] in CREATE_KINDS and in_poc and t["success"] and caller(n) in A:
            # only contracts the attacker set deploys itself: their addresses derive from the job's secret
            # salt. (A contract made through a public CREATE2 factory has a predictable address that could
            # hold state placed on chain in advance, so it is not attacker-controlled.)
            add_attacker(a)
            created.append(a)
        if a == FAUCET:
            if not in_poc:
                raise Reject("reentry", "the faucet was reached outside the PoC")
            if t["kind"] not in ("CALL", "STATICCALL"):
                raise Reject("reentry", f"{t['kind']} into the faucet")
            fn = faucet_fn.get(sel_of(n))
            if fn is None:
                continue                        # unknown function: the faucet reverts, nothing happens
            fargs = _faucet_call(n, ex, fn, ctx, A, protected, capital_tokens, capital, role_calls, feeds,
                                 price_moves, helpers_used, eoas, issued_keys, add_attacker)
            if not fn.startswith("attackerKey(") and n["parent"] not in helper_frames:
                events.append(_event("faucet:" + fn, fargs, t["success"]))   # no counterpart in plain forge test
            continue
        if a != CHEAT or p is root:
            continue
        # ---- a cheatcode node below the root: who issued it?
        issuer = addr(p)
        s8 = sel_of(n)
        sig = ctx.table.get(s8, f"unknown(0x{s8})")
        if issuer == FAUCET:
            fsig = faucet_fn.get(sel_of(p))
            if fsig is None or sig not in FAUCET_FUNCS[fsig] or T(p)["kind"] != "CALL":
                raise Reject("reentry", f"faucet issued unexpected {sig}")
            _faucet_cheat(n, p, fsig, sig)
            continue
        if issuer in (HARNESS, probe):
            raise Reject("reentry", f"runner code issued {sig} outside the root frame")
        if not in_poc:
            raise Reject("reentry", f"cheatcode {sig} outside the PoC's frames")
        if issuer not in A:
            raise Reject(f"policy:{sig}", f"issued by {issuer}, code the PoC does not control")
        if is_assert_or_expect(sig):
            continue
        if sig in ALLOW:
            if sig in STATEFUL:
                events.append(_event(sig, (), t["success"]))
            continue
        rule = RULED.get(sig)
        if rule is None:
            raise Reject(f"policy:{sig}", "cheatcode not allowed")
        cargs = poc_args(n, sig)
        if sig in STATEFUL:
            events.append(_event(sig, cargs, t["success"]))
        if rule == "prank":
            for target in cargs:
                target = target.lower()
                if target in protected:
                    raise Reject("impersonation", f"{sig} as protected address {target}")
                if target not in A:
                    raise Reject("impersonation", f"{sig} as {target}, which the PoC does not control")
        elif rule == "warp":
            (ts,) = cargs
            if ts < ts_now or ts - spec["fork"]["timestamp"] > max_warp:
                raise Reject("time", f"warp to {ts} (backwards, or more than {max_warp} s after the fork block)")
            ts_now = ts
        elif rule == "roll":
            (bn,) = cargs
            if bn < bn_now or bn - spec["fork"]["block"] > max_roll:
                raise Reject("time", f"roll to {bn} (backwards, or more than {max_roll} blocks after the fork block)")
            bn_now = bn
        elif rule == "fork":
            url, b = cargs
            forks_seen += 1
            if forks_seen > 1:
                raise Reject("fork", "more than one fork")
            if url != ctx.rpc_url or b != spec["fork"]["block"]:
                raise Reject("fork", f"fork at block {b} through another URL or block than the pinned one")
            if i not in setup_nodes:
                raise Reject("fork", "fork created outside setUp()")
            ts_now, bn_now = spec["fork"]["timestamp"], spec["fork"]["block"]
        elif rule == "env":
            (name,) = cargs
            if name != "HYBLIS_ETH_RPC":
                raise Reject("env", "read of an environment variable other than HYBLIS_ETH_RPC")
        elif rule == "sign":
            key, _ = cargs
            if key not in issued_keys:
                raise Reject("impersonation", f"{sig} with a key not from makeAddrAndKey")

    if len(A) > spec["limits"]["max_attackers"]:
        raise Reject("limits", f"{len(A)} attacker accounts (limit {spec['limits']['max_attackers']})")

    # ---- 3. did the PoC run, within its gas?
    poc_gas = spec["limits"]["poc_gas"]
    for f_i, r_i, what in poc_frames:
        if T(ex[r_i])["gas_limit"] < poc_gas:
            raise Reject("limits", f"{what} got {T(ex[r_i])['gas_limit']} gas, less than poc_gas: the harness's total "
                                   "gas budget ran out")
        if T(ex[f_i])["gas_used"] > poc_gas or _ran_out_of_gas(ex, f_i):
            raise Reject("limits", f"{what} needs more than poc_gas ({poc_gas})")
    for r_i in poc_roots:
        if not T(ex[r_i])["success"]:
            raise Reject("poc_reverted", "constructor, setUp or a test/step call reverted")
    if forks_seen != 1:
        raise Reject("fork", f"{forks_seen} forks; exactly one pinned fork in setUp() is required")
    if len(poc_roots) != 2 + m:
        raise Reject("harness_failed", "the harness did not run every PoC step")
    if not harness_ok:
        raise Reject("harness_failed", "harness test did not succeed after the PoC")

    # ---- 4. the harness program after the PoC
    e = 13 + m
    diff_node = expect(e, "CALL", CHEAT, "stopAndReturnStateDiff()")
    expect(e + 1, "CALL", CHEAT, "stopPrank()")
    expect(e + 2, "CALL", CHEAT, "clearMockedCalls()")
    env_n = expect(e + 3, "STATICCALL", CHEAT, "envOr(string,string,address[])")
    if args_of(env_n, "envOr(string,string,address[])")[0] != "HYBLIS_ATTACKER_SET" or \
            [x.lower() for x in out_decode(env_n, ["address[]"])[0]] != ctx.attacker_set:
        raise Reject("template", "harness read a different attacker set")
    expect(e + 4, "CALL", CHEAT, "startStateDiffRecording()")
    post_node = expect(e + 5, "STATICCALL", probe, M_SIG)
    readset_node = expect(e + 6, "CALL", CHEAT, "stopAndReturnStateDiff()")
    k = e + 7
    post_probes, probe_readsets, base_probes = [], [], []
    for pr in spec["probes"]:
        expect(k, "CALL", CHEAT, "snapshotState()")
        expect(k + 1, "CALL", CHEAT, "startStateDiffRecording()")
        _probe_prank(expect(k + 2, "CALL", CHEAT, "prank(address)"), pr)
        post_probes.append(_probe_call(expect(k + 3, "CALL", pr["target"]), pr))
        probe_readsets.append(expect(k + 4, "CALL", CHEAT, "stopAndReturnStateDiff()"))
        expect(k + 5, "CALL", CHEAT, "revertToStateAndDelete(uint256)")
        k += 6
    if args_of(expect(k, "CALL", CHEAT, "revokePersistent(address)"), "revokePersistent(address)")[0].lower() != poc:
        raise Reject("template", "baseline keeps another account persistent")
    fork_c = expect(k + 1, "CALL", CHEAT, "createSelectFork(string,uint256)")
    if tuple(args_of(fork_c, "createSelectFork(string,uint256)")) != (ctx.rpc_url, spec["fork"]["block"]):
        raise Reject("template", "baseline fork not at the pinned block")
    (ts_final,) = args_of(expect(k + 2, "CALL", CHEAT, "warp(uint256)"), "warp(uint256)")
    (bn_final,) = args_of(expect(k + 3, "CALL", CHEAT, "roll(uint256)"), "roll(uint256)")
    base_node = expect(k + 4, "STATICCALL", probe, M_SIG)
    k += 5
    for pr in spec["probes"]:
        expect(k, "CALL", CHEAT, "snapshotState()")
        _probe_prank(expect(k + 1, "CALL", CHEAT, "prank(address)"), pr)
        base_probes.append(_probe_call(expect(k + 2, "CALL", pr["target"]), pr))
        expect(k + 3, "CALL", CHEAT, "revertToStateAndDelete(uint256)")
        k += 4
    if len(K) != k:
        raise Reject("template", f"harness root made {len(K)} calls, the program has {k}")
    if not T(post_node)["success"] or not T(base_node)["success"]:
        raise Reject("measurement_failed", "probe.measure reverted")

    # ---- 5. measurements
    meas = _measurements(post_node, base_node, poc, ctx)
    missing = [x for x in A if x not in meas["holders"]]
    result = {
        "poc": poc, "probe": probe, "attacker_set": sorted(A), "attacker_order": A_order,
        "unmeasured_attackers": sorted(missing), "eoas": eoas, "created": created,
        "helpers_used": helpers_used, "capital_raw": capital, "price_moves": price_moves,
        "role_calls": role_calls, "ts_final": ts_final, "bn_final": bn_final,
        "entries": _entries(ex, poc_nodes, spec), "events": events,
        "fingerprints": {
            "poc": canon(ex, sorted(set(kids[:e + 1]) | poc_nodes)),
            "measure": meas["fingerprint"],
        },
    }
    if missing:
        result["impact"] = None                  # pass 1: not every attacker address measured yet
        return result

    # ---- 6. integrity of what was measured
    for (tk, h), v in list(meas["post"].items()) + list(meas["base"].items()):
        if v == SENTINEL:
            raise Reject("measurement_failed", f"balanceOf({h}) on {tk} did not return a value")
    for w in spec["code_watch"]:
        if meas["watch_post"][w] != meas["watch_base"][w]:
            raise Reject("measurement_failed", f"code at {w} differs between the exploited fork and the baseline")
    for x in A:
        # The PoC itself is created with CREATE2 from the job's secret salt; forge keeps its code on the
        # baseline fork (the harness revokes its persistence, so not its balances), so only its code is exempt.
        if any(meas["base"][(tk["address"], x)] != 0 for tk in spec["tokens"]) or \
                (x != poc and meas["code_base"][x] not in ("0x" + "0" * 64, EMPTY_CODEHASH)) or \
                any(v not in (0, None) for (cid, who), v in meas["aclaims_base"].items() if who == x):
            raise Reject("measurement_failed", f"attacker account {x} already holds state at the pinned block")

    impact = _classify(meas, A, capital, price_moves, post_probes, base_probes, spec)
    result.update(impact)
    if impact["impact_type"]:
        anchor = _anchor(impact, meas, A, diff_node, readset_node, probe_readsets, spec)
        result.update(anchor)
    return result


def _probe_prank(n, pr):
    if args_of(n, "prank(address)")[0].lower() != pr["actor"]:
        raise Reject("template", "probe pranks another actor")


def _value(n) -> int:
    v = T(n)["value"]
    return int(v, 16) if isinstance(v, str) else int(v or 0)


def _probe_call(n, pr):
    if "0x" + data_hex(n).lower() != pr["calldata"].lower() or _value(n) != 0:
        raise Reject("template", "probe call differs from the spec")
    return n


def _helper_cheat_problem(cargs, fargs, fsig, sig) -> tuple[str, str] | None:
    """A cheatcode inside a faucet frame (or a HyblisBase helper frame in plain forge test) may touch only what
    that call is about. Returns (error code, what) or None."""
    if fsig.startswith("fund("):
        token, to = fargs[0].lower(), fargs[1].lower()
        if sig in ("accesses(address)", "load(address,bytes32)", "store(address,bytes32,bytes32)",
                   "getMappingKeyAndParentOf(address,bytes32)") and cargs[0].lower() != token:
            return "capital", "touched storage of another contract"
        if sig == "deal(address,uint256)" and (token != ZERO or cargs[0].lower() != to):
            return "capital", "changed the ETH balance of another account"
    elif fsig.startswith("asRole("):
        if cargs[0].lower() != fargs[0].lower():
            return "helper", "pranked another account"
    elif fsig.startswith("setPrice("):
        if cargs[0].lower() != fargs[0].lower():
            return "helper", "mocked another contract"
    return None


def _faucet_cheat(n, p, fsig, sig):
    """Cheatcodes inside a faucet frame must touch only what that faucet call is about."""
    fargs = poc_args(p, fsig)                     # the faucet call's arguments came from the PoC
    cargs = args_of(n, sig) if "(" in sig and not sig.endswith("()") else ()
    prob = _helper_cheat_problem(cargs, fargs, fsig, sig)
    if prob:
        raise Reject(prob[0], "faucet " + prob[1])


def _faucet_call(n, ex, fsig, ctx, A, protected, capital_tokens, capital, role_calls, feeds, price_moves,
                 helpers_used, eoas, issued_keys, add_attacker):
    """Checks one faucet call against the spec and records what it did; returns its (PoC-supplied) arguments."""
    spec = ctx.spec
    t = T(n)
    fargs = poc_args(n, fsig)
    eff = effective(ex, n["idx"])
    if fsig.startswith("fund("):
        helpers_used["fund"] += 1
        token, to, amount = fargs[0].lower(), fargs[1].lower(), fargs[2]
        if token not in capital_tokens:
            raise Reject("capital", f"token {token} is not a capital token of this task")
        if to in protected or to not in A:
            raise Reject("capital", f"funded {to}, which the PoC does not control")
        if not eff:
            return fargs
        for lg in n["logs"]:
            raw = lg.get("raw_log") or {}
            topics = raw.get("topics") or []
            if (lg.get("address") or "").lower() != FAUCET or not topics or topics[0][2:].lower() != EV_FUNDED:
                continue
            if len(topics) != 3:
                raise Reject("template", "faucet Funded record malformed")
            tok, who = "0x" + topics[1][-40:].lower(), "0x" + topics[2][-40:].lower()
            old, new = _decode_or_template(["uint256", "uint256"], bytes.fromhex(raw["data"][2:]), "faucet Funded record")
            if (tok, who) != (token, to) or new < old:
                raise Reject("capital", "faucet record does not match the call")
            capital[tok] = capital.get(tok, 0) + (new - old)
            if capital[tok] > int(capital_tokens[tok]["capital_cap"]):
                raise Reject("capital", f"capital in {capital_tokens[tok]['symbol']} above the task's cap")
    elif fsig.startswith("attackerKey("):
        helpers_used["attackerKey"] += 1
        if not t["success"]:
            return fargs
        (key,) = _decode_or_template(["uint256"], out_bytes(n), "faucet attackerKey result")
        issued_keys.add(key)
        for lg in n["logs"]:
            raw = lg.get("raw_log") or {}
            topics = raw.get("topics") or []
            if (lg.get("address") or "").lower() != FAUCET or not topics or topics[0][2:].lower() != EV_ATTACKER:
                continue
            runner_a, standalone_a = (x.lower() for x in _decode_or_template(
                ["address", "address"], bytes.fromhex(raw["data"][2:]), "faucet Attacker record"))
            add_attacker(runner_a)
            eoas.setdefault(runner_a, standalone_a)
    elif fsig.startswith("asRole("):
        helpers_used["asRole"] += 1
        role, target, data = fargs[0].lower(), fargs[1].lower(), fargs[2]
        match = None
        for act in spec["trusted_actions"]:
            if act["role"] == role and act["target"] == target and data[:4].hex() == act["selector"]:
                if _action_args_ok(act, data):
                    match = act
                    break
        if match is None:
            raise Reject("helper", "_asRole call not allowed by the task")
        if eff:
            role_calls[match["id"]] = role_calls.get(match["id"], 0) + 1
            if role_calls[match["id"]] > match["max_calls"]:
                raise Reject("helper", f"_asRole {match['id']} called more than {match['max_calls']} times")
    elif fsig.startswith("setPrice("):
        helpers_used["setPrice"] += 1
        feed, answer = fargs[0].lower(), fargs[1]
        f = feeds.get(feed)
        if f is None:
            raise Reject("helper", "_setPrice on a feed the task does not list")
        ref = int(f["answer"])
        if answer <= 0 or abs(answer - ref) * 10_000 > ref * f["max_move_bps"]:
            raise Reject("helper", f"_setPrice moves {f['id']} by more than {f['max_move_bps']} bps")
        price_moves[feed] = answer               # mocks are not rolled back on revert: the last one counts
    return fargs


def _decode_or_template(types, raw: bytes, what: str) -> tuple:
    """Decode output or a log the runner's own code wrote; anything else is forge output in a form the engine was
    not built for (template, never a crash)."""
    try:
        return decode(types, raw)
    except Exception:
        raise Reject("template", f"{what} unreadable") from None


def _ev_value(x):
    if isinstance(x, bytes):
        return "0x" + x.hex()
    if isinstance(x, str):
        return x.lower()
    if isinstance(x, (list, tuple)):
        return [_ev_value(y) for y in x]
    return x


def _event(name: str, args, success) -> list:
    """One state-changing cheatcode or helper call, as compared between the measured and the standalone run."""
    return [name, *[_ev_value(x) for x in args], bool(success)]


def _ran_out_of_gas(ex, i) -> bool:
    """PoC frame i failed for lack of gas: it ran out itself, or a call below it ran out after taking all the gas
    the frame could pass on (the frame then has at most 1/64 of its gas left, and reverts)."""
    t = T(ex[i])
    if t["success"]:
        return False
    if t["status"] in OOG_STATUSES:
        return True
    return t["gas_used"] * 64 >= t["gas_limit"] * 63 and \
        any(T(ex[j])["status"] in OOG_STATUSES and not T(ex[j])["success"] for j in subtree(ex, i)[1:])


def _action_args_ok(act, data: bytes) -> bool:
    try:
        vals = decode(act["arg_types"], data[4:]) if act["arg_types"] else ()
    except Exception:
        return False
    for ty, v, rule in zip(act["arg_types"], vals, act["args"]):
        if not rule:
            continue
        if ty == "address":
            v = v.lower()
            if "eq" in rule and v != rule["eq"]:
                return False
            continue
        if "eq" in rule and v != int(rule["eq"]):
            return False
        if "min" in rule and v < int(rule["min"]):
            return False
        if "max" in rule and v > int(rule["max"]):
            return False
    return True


def _measurements(post_node, base_node, poc, ctx: Ctx) -> dict:
    spec = ctx.spec
    if data_hex(post_node) != data_hex(base_node):
        raise Reject("template", "POST and BASE measured different sets")
    tokens, holders, targets, data, watch = args_of(post_node, M_SIG)
    tokens = [x.lower() for x in tokens]
    holders = [x.lower() for x in holders]
    targets = [x.lower() for x in targets]
    watch = [x.lower() for x in watch]
    extra = ctx.attacker_set
    exp_holders = [h["address"] for h in spec["holders"]] + [poc] + extra
    exp_views = [(v["target"], bytes.fromhex(v["calldata"][2:])) for v in spec["views"]]
    for c in spec["attacker_claims"]:
        for who in [poc] + extra:
            exp_views.append((c["target"], bytes.fromhex(c["selector"] + "0" * 24 + who[2:])))
    if tokens != [t["address"] for t in spec["tokens"]] or holders != exp_holders or \
            list(zip(targets, data)) != exp_views or watch != spec["code_watch"]:
        raise Reject("template", "harness measured a set other than the spec's")
    out = {"holders": holders}
    fp = hashlib.sha256()
    nspec_h = len(spec["holders"])
    for tag, node in (("post", post_node), ("base", base_node)):
        try:
            bal, ok, outv, hcode, wcode = decode(M_OUT, out_bytes(node))
        except Exception:
            raise Reject("measurement_failed", "measurement output unreadable") from None
        if len(bal) != len(tokens) * len(holders) or len(ok) != len(targets) or len(hcode) != len(holders) or \
                len(wcode) != len(watch):
            raise Reject("measurement_failed", "measurement output has the wrong shape")
        B = {(tokens[i], holders[j]): bal[i * len(holders) + j] for i in range(len(tokens)) for j in range(len(holders))}
        views, aclaims = {}, {}
        for idx, v in enumerate(spec["views"]):
            views[v["id"]] = _view_value(v["type"], ok[idx], outv[idx])
        q = len(spec["views"])
        for c in spec["attacker_claims"]:
            for who in [poc] + extra:
                aclaims[(c["id"], who)] = _view_value(c["type"], ok[q], outv[q])
                q += 1
        out[tag] = B
        out[f"views_{tag}"] = views
        out[f"aclaims_{tag}"] = aclaims
        out[f"code_{tag}"] = {h: "0x" + c.hex() for h, c in zip(holders, hcode)}
        out[f"watch_{tag}"] = {w: "0x" + c.hex() for w, c in zip(watch, wcode)}
        fp.update(json.dumps([[B[(t, h)] for t in tokens for h in holders[:nspec_h]],
                              sorted((k_, str(v_)) for k_, v_ in views.items())]).encode())
    out["fingerprint"] = fp.hexdigest()
    return out


def _view_value(ty, ok, raw: bytes):
    if not ok or len(raw) < 32:
        return None
    try:
        v = decode([ty], raw[:32])[0]
    except Exception:
        return None
    if isinstance(v, bytes):
        return int.from_bytes(v, "big")
    if isinstance(v, str):
        return int(v, 16)
    return v


# ------------------------------------------------------------------ classification
def _prices(spec, price_moves) -> dict[str, Fraction]:
    P = {t["address"]: Fraction(t["usd"]) / (10 ** t["decimals"]) for t in spec["tokens"]}
    for f in spec["price_feeds"]:
        if f["feed"] in price_moves:
            tok = next(t for t in spec["tokens"] if t["symbol"] == f["token"])
            P[tok["address"]] = Fraction(price_moves[f["feed"]], 10 ** f["decimals"]) / (10 ** tok["decimals"])
    return P


def _classify(meas, A, capital, price_moves, post_probes, base_probes, spec) -> dict:
    P = _prices(spec, price_moves)
    sym = {t["symbol"]: t["address"] for t in spec["tokens"]}
    toks = [t["address"] for t in spec["tokens"]]
    th = Fraction(spec["thresholds"]["min_usd"])

    def hvalue(tag, h):
        val = sum(P[t] * meas[tag][(t, h["address"])] for t in toks)
        for vv in h["value_views"]:
            x = meas[f"views_{tag}"].get(vv["view"])
            if x is not None:
                val += P[sym[vv["token"]]] * int(x)
        return val

    custody = [h for h in spec["holders"] if h["role"] == "custody"]
    lc = sum((max(Fraction(0), hvalue("base", h) - hvalue("post", h)) for h in custody), Fraction(0))
    tvl = sum((hvalue("base", h) for h in custody), Fraction(0))
    lv = Fraction(0)
    for v in spec["views"]:
        if v["role"] == "victim_claim":
            b, q = meas["views_base"].get(v["id"]), meas["views_post"].get(v["id"])
            if b is not None and q is not None and q < b:
                lv += P[sym[v["token"]]] * (b - q)
    loss = max(lc, lv)
    gain = Fraction(0)
    for a in A:
        gain += sum(P[t] * (meas["post"][(t, a)] - meas["base"][(t, a)]) for t in toks)
    for c in spec["attacker_claims"]:
        for a in A:
            b, q = meas["aclaims_base"].get((c["id"], a)), meas["aclaims_post"].get((c["id"], a))
            if b is not None and q is not None:
                gain += c["sign"] * P[sym[c["token"]]] * (q - b)
    cap_value = sum((P[t] * amt for t, amt in capital.items()), Fraction(0))
    gain -= cap_value

    # invariants: usable only if they hold on the clean fork
    env = {}
    for tag in ("base", "post"):
        e = dict(meas[f"views_{tag}"])
        for t in spec["tokens"]:
            for h in spec["holders"]:
                e[f"bal_{t['symbol']}_{h['id']}"] = meas[tag][(t["address"], h["address"])]
        env[tag] = e
    broken, inv_unhealthy = [], []
    for inv in spec["invariants"]:
        try:
            hb = bool(safe_eval(inv["holds"], env["base"]))
            hp = bool(safe_eval(inv["holds"], env["post"]))
        except Exception:
            inv_unhealthy.append(inv["id"])
            continue                              # a failed read is unknown, never "broken"
        if not hb:
            inv_unhealthy.append(inv["id"])
            continue
        if not hp:
            short = Fraction(0)
            if inv.get("shortfall"):
                try:
                    short = max(Fraction(0), Fraction(int(safe_eval(inv["shortfall"], env["post"]))))
                except Exception:
                    short = Fraction(0)
            units_p = P[sym[inv["units"]]] if inv.get("units") else Fraction(0)
            if inv.get("units"):
                # what the protocol owes the attacker accounts themselves in the shortfall's token (e.g. their
                # own capital put into it, an attacker claim) is not a shortfall towards victims
                own = sum(max(0, (meas["aclaims_post"].get((c["id"], a)) or 0) -
                              (meas["aclaims_base"].get((c["id"], a)) or 0))
                          for c in spec["attacker_claims"] if c["sign"] > 0 and c["token"] == inv["units"] for a in A)
                short = max(Fraction(0), short - own)
            broken.append({"id": inv["id"], "class": inv["class"], "impact": inv["impact"],
                           "shortfall_usd": short * units_p})
    flips, probes_unhealthy = [], []
    for pr, nb, npst in zip(spec["probes"], base_probes, post_probes):
        if not T(nb)["success"]:
            probes_unhealthy.append(pr["id"])
            continue
        if not T(npst)["success"]:
            at_risk = Fraction(0)
            if pr.get("at_risk"):
                # funds still owed but no longer withdrawable: the at-risk view on BOTH forks (a claim that was
                # taken, not frozen, is a loss, never a freeze)
                xb, xp = meas["views_base"].get(pr["at_risk"]), meas["views_post"].get(pr["at_risk"])
                x = None if xb is None or xp is None else min(xb, xp)
                if x is not None:
                    at_risk = P[sym[pr["at_risk_token"]]] * int(x)
            flips.append({"id": pr["id"], "class": pr["class"], "impact": pr["impact"], "at_risk_usd": at_risk})
    views_failed = sorted(k for k, v in meas["views_base"].items() if v is None)

    # unbacked mint of a protocol-issued token
    mint = None
    for t in spec["tokens"]:
        if not t["issued_by_protocol"]:
            continue
        sb, sp = meas["views_base"].get(t["supply_view"]), meas["views_post"].get(t["supply_view"])
        if sb is None or sp is None or sp <= sb:
            continue
        ds = sp - sb
        to_a = sum(meas["post"][(t["address"], a)] - meas["base"][(t["address"], a)] for a in A)
        backing = sum(((hvalue("post", h) - hvalue("base", h)) for h in custody), Fraction(0))
        backing -= sum(P[t["address"]] * (meas["post"][(t["address"], h["address"])] -
                                          meas["base"][(t["address"], h["address"])]) for h in custody)
        dv = P[t["address"]] * ds
        if dv >= th and to_a * 10 >= ds * 9 and backing * 10 < dv * 9:
            mint = {"token": t["symbol"], "amount_usd": dv - max(Fraction(0), backing)}
            break

    corroborated = loss >= th or bool(flips) or lv > 0
    impact, amount = "", Fraction(0)
    solv = [b for b in broken if b["impact"] == "insolvency"]
    acct = [b for b in broken if b["impact"] == "accounting_error"]
    freeze = [f for f in flips if f["impact"] == "funds_freeze" and f["at_risk_usd"] >= th]
    live = [f for f in flips if f["impact"] == "dos"]
    if gain >= th and loss >= th:
        impact, amount = "funds_loss", min(gain, loss)
    elif mint:
        impact, amount = "unauthorized_mint", mint["amount_usd"]
    elif solv and corroborated:
        impact, amount = "insolvency", max(b["shortfall_usd"] for b in solv)
    elif freeze:
        impact, amount = "funds_freeze", freeze[0]["at_risk_usd"]
    elif loss >= th:
        impact, amount = "griefing", loss
    elif acct or solv:
        impact, amount = "accounting_error", Fraction(0)
    elif live:
        impact, amount = "dos", Fraction(0)

    sev = ""
    if impact:
        rule = spec["severity"].get(impact, {"default": "low"})
        sev = rule["default"]
        share = amount / tvl if tvl > 0 else Fraction(0)
        if ("high_if_tvl_share" in rule and share >= Fraction(rule["high_if_tvl_share"])) or \
                ("high_if_usd" in rule and amount >= Fraction(rule["high_if_usd"])):
            sev = max(sev, "high", key=SEVERITIES.index)
        if ("critical_if_tvl_share" in rule and share >= Fraction(rule["critical_if_tvl_share"])) or \
                ("critical_if_usd" in rule and amount >= Fraction(rule["critical_if_usd"])):
            sev = "critical"
        if impact == "accounting_error" and not corroborated:
            sev = "low"                            # a break seen only in views stays low
        if SEVERITIES.index(sev) > SEVERITIES.index(spec["severity"]["max"]):
            sev = spec["severity"]["max"]
    f = lambda x: float(round(x, 6))
    return {
        "impact_type": impact, "measured_severity": sev,
        "evidence": {"amount_usd": f(amount), "victim_loss_usd": f(loss), "custody_loss_usd": f(lc),
                     "claims_loss_usd": f(lv), "attacker_gain_usd": f(gain), "capital_usd": f(cap_value),
                     "tvl_usd": f(tvl),
                     "broken_invariants": [{"id": b["id"], "impact": b["impact"], "shortfall_usd": f(b["shortfall_usd"])}
                                           for b in broken],
                     "probe_flips": [{"id": x["id"], "impact": x["impact"], "at_risk_usd": f(x["at_risk_usd"])}
                                     for x in flips],
                     "unbacked_mint": ({"token": mint["token"], "amount_usd": f(mint["amount_usd"])} if mint else None),
                     "price_moves": {k: str(v) for k, v in price_moves.items()}},
        "spec_health": {"views_failed": views_failed, "invariants_not_holding": inv_unhealthy,
                        "probes_failing": probes_unhealthy,
                        "views_base": {k: (v if isinstance(v, (int, bool)) or v is None else str(v))
                                       for k, v in meas["views_base"].items()}},
        "_flips": flips,
    }


# ------------------------------------------------------------------ changed function (impact-anchored)
def _diff(node):
    try:
        return decode([T_ACC], out_bytes(node))[0]
    except Exception:
        raise Reject("measurement_failed", "state diff unreadable") from None


def _read_groups(acc):
    """Slots read by each top-level quantity of a recording: every access after a depth-(top+1) call
    record belongs to that call until the next one. (forge's Resume records copy the account and depth
    of an outer record, so their own depth is not used.)"""
    groups, cur = [], None
    calls = [x for x in acc if x[1] in (0, 1, 2, 3, 4)]
    if not calls:
        return groups
    top = min(x[12] for x in calls)
    for x in acc:
        if x[1] in (0, 1, 2, 3, 4) and x[12] == top + 1:
            cur = {"target": x[2].lower(), "data": bytes(x[9]), "slots": set()}
            groups.append(cur)
        if cur is not None:
            cur["slots"].update((s[0].lower(), "0x" + s[1].hex()) for s in x[11])
    return groups


def _entry_frames(acc, in_scope: set):
    """In-scope entry frames (outermost in-scope call entered from outside), in execution order, with
    the first previous and last new value of every non-reverted slot write made while the frame was open,
    ETH that in-scope code sent, and ETH sent into the frame's account by the call that opened it. A frame
    opens at an in-scope call record and closes at the next call record at its depth or above. Resume records
    are attributed to the open frame (their own account and depth fields are copies of an outer record in
    forge 1.9.0 and are not used)."""
    frames, cur = [], None
    for x in acc:
        kind, account, accessor, depth = x[1], x[2].lower(), x[3].lower(), x[12]
        if kind in (0, 1, 2, 3, 4):
            if cur is not None and depth <= cur["depth"]:
                cur = None
            if cur is None and account in in_scope:
                cur = {"account": account, "sel": bytes(x[9])[:4].hex(), "depth": depth, "first": {}, "last": {},
                       "eth_out": {}, "eth_in": x[8] if kind == 0 and not x[10] else 0}
                frames.append(cur)
        if cur is None or x[10]:
            continue
        for st in x[11]:
            if st[2] and not st[5]:
                key = (st[0].lower(), "0x" + st[1].hex())
                cur["first"].setdefault(key, int.from_bytes(st[3], "big"))
                cur["last"][key] = int.from_bytes(st[4], "big")
        if kind in (0, 2) and x[8] and accessor in in_scope:
            cur["eth_out"][accessor] = cur["eth_out"].get(accessor, 0) + x[8]
    return frames


def _anchor(impact, meas, A, diff_node, readset_node, probe_readsets, spec) -> dict:
    in_scope = {c["address"]: c for c in spec["in_scope"]}
    frames = _entry_frames(_diff(diff_node), set(in_scope))
    groups = _read_groups(_diff(readset_node))
    P = _prices(spec, {k: int(v) for k, v in impact["evidence"]["price_moves"].items()})
    sym = {t["symbol"]: t["address"] for t in spec["tokens"]}
    custody = {h["address"] for h in spec["holders"] if h["role"] == "custody"}
    vclaim_cd = {(v["target"], bytes.fromhex(v["calldata"][2:])): v for v in spec["views"] if v["role"] == "victim_claim"}
    state_cd = {(v["target"], bytes.fromhex(v["calldata"][2:])) for v in spec["views"] if v["role"] == "state"}
    claim_by_sel = {(c["target"], c["selector"]): c for c in spec["attacker_claims"]}
    slot_price: dict = {}
    S_cust, S_vclaim, S_aclaim, S_state, S_abal = set(), set(), set(), set(), set()
    for g in groups:
        d4 = g["data"][:4].hex()
        who = "0x" + g["data"][-20:].hex() if len(g["data"]) >= 36 else ""
        if d4 == "70a08231" and g["target"] in sym.values():
            if who in custody:
                S_cust |= g["slots"]
            elif who in A:
                S_abal |= g["slots"]
            for s_ in g["slots"]:
                slot_price.setdefault(s_, P.get(g["target"], Fraction(0)))
        elif (g["target"], g["data"]) in vclaim_cd:
            v = vclaim_cd[(g["target"], g["data"])]
            S_vclaim |= g["slots"]
            for s_ in g["slots"]:
                slot_price.setdefault(s_, P[sym[v["token"]]])
        elif (g["target"], d4) in claim_by_sel and who in A:
            c = claim_by_sel[(g["target"], d4)]
            S_aclaim |= g["slots"]
            for s_ in g["slots"]:
                slot_price.setdefault(s_, P[sym[c["token"]]] * c["sign"])
        elif (g["target"], g["data"]) in state_cd:
            S_state |= g["slots"]
    eth_p = P.get(ZERO, Fraction(0))
    th = Fraction(spec["thresholds"]["min_usd"])
    tol = th / 2

    def delta_value(fr, S, sign):
        tot = Fraction(0)
        for key, last in fr["last"].items():
            if key in S:
                d = (last - fr["first"][key]) * sign
                if d > 0:
                    tot += d * abs(slot_price.get(key, Fraction(0)))
        return tot

    def moved(fr, S, sign):
        return any(k in S and (fr["last"][k] - fr["first"][k]) * sign > 0 for k in fr["last"])

    it = impact["impact_type"]
    best = None
    if it in ("funds_loss", "griefing", "insolvency"):
        for fr in frames:
            # value out of / into custody (token balance slots, and ETH sent by or into a custody account), and the
            # signed change of what the attacker accounts are owed (assets +, liabilities such as debt -)
            cust_out = delta_value(fr, S_cust, -1) + sum(v for a_, v in fr["eth_out"].items() if a_ in custody) * eth_p
            cust_in = delta_value(fr, S_cust, +1) + (fr["eth_in"] * eth_p if fr["account"] in custody else 0)
            claims = sum(((fr["last"][k] - fr["first"][k]) * slot_price.get(k, Fraction(0)) for k in fr["last"]
                          if k in S_aclaim), Fraction(0))
            if moved(fr, S_vclaim, -1) or cust_out > max(Fraction(0), -claims) + tol or claims > cust_in + tol:
                best = fr
                break
    elif it in ("funds_freeze", "dos"):
        flipped = next(x for x in impact["_flips"] if x["impact"] == it)
        pi = [p_["id"] for p_ in spec["probes"]].index(flipped["id"])
        pacc = _diff(probe_readsets[pi])
        reads = [(s[0].lower(), "0x" + s[1].hex()) for x in pacc for s in x[11] if not s[2]]
        crit = {reads[-1]} if reads else set()
        allp = set(reads)
        for S in (crit, allp):
            best = next((fr for fr in frames if any(k in S and fr["last"][k] != fr["first"][k] for k in fr["last"])), None)
            if best:
                break
    elif it == "unauthorized_mint":
        best = next((fr for fr in frames if moved(fr, S_abal | S_state, +1)), None)
    else:
        best = next((fr for fr in frames if any(k in S_state for k in fr["last"])), None)
    if best is None and it in ("accounting_error", "dos"):
        # fall back (7.9, these types only): first in-scope frame that wrote a measured slot, then any write.
        # A value impact, freeze or mint without an anchor was not caused by in-scope code: out_of_scope.
        measured = S_cust | S_vclaim | S_aclaim | S_state | S_abal
        best = next((fr for fr in frames if any(k in measured for k in fr["last"])), None) or \
            next((fr for fr in frames if fr["last"] or fr["eth_out"]), None)
    if best is None:
        raise Reject("out_of_scope", "no in-scope contract changed state")
    c = in_scope[best["account"]]
    name = c["functions"].get(best["sel"])
    if name is None:
        name = next((x["functions"][best["sel"]] for x in spec["in_scope"] if best["sel"] in x["functions"]),
                    "0x" + best["sel"])
    return {"changed_function": name, "changed_contract": best["account"], "changed_selector": best["sel"]}


# ------------------------------------------------------------------ conformance (standalone run)
def _entries(ex, nodes, spec) -> list:
    """(target, value, data, success) of every state-changing entry into in-scope code from outside it."""
    scope = {c["address"] for c in spec["in_scope"]}
    out = []
    for i in sorted(nodes):
        n = ex[i]
        if T(n)["kind"] == "STATICCALL" or n["parent"] is None:
            continue
        if addr(n) in scope and addr(ex[n["parent"]]) not in scope:
            out.append((addr(n), _value(n), data_hex(n).lower(), bool(T(n)["success"])))
    return out


def _norm_value(x, mapping: dict):
    if isinstance(x, str):
        if _ADDR.fullmatch(x):
            return mapping.get(x.lower(), x.lower())
        if x.startswith("0x") or _HEX.fullmatch("0x" + x):
            for real, token in mapping.items():
                x = x.replace(real[2:], token)
        return x
    if isinstance(x, (list, tuple)):
        return [_norm_value(y, mapping) for y in x]
    return x


def _normalise(entries, mapping: dict) -> list:
    """Entries or events with the run's own accounts (PoC, attacker accounts, created contracts) replaced by tokens."""
    return [tuple(_norm_value(x, mapping) for x in e) for e in entries]


def _standalone_cheat(n, nodes, table, ctrl, helper_frames, events):
    """One cheatcode call in plain forge test: the same default-deny policy as under the runner. Inside a HyblisBase
    helper frame only what the faucet may do for that helper; elsewhere only allowed cheatcodes, issued by the PoC
    or contracts it created. State-changing ones are recorded in order (compared with the runner's)."""
    differs = "standalone_differs"
    p = nodes[n["parent"]]
    s8 = sel_of(n)
    sig = table.get(s8, f"unknown(0x{s8})")
    if n["parent"] in helper_frames:
        fsig, hsig = helper_frames[n["parent"]]
        if sig not in FAUCET_FUNCS[fsig]:
            raise Reject(differs, f"plain forge test: {hsig} issued {sig}")
        cargs = poc_args(n, sig, differs) if "(" in sig and not sig.endswith("()") else ()
        prob = _helper_cheat_problem(cargs, poc_args(p, hsig, differs), fsig, sig)
        if prob:
            raise Reject(differs, f"plain forge test: {hsig} {prob[1]}")
        return
    issuer = addr(p)
    if issuer not in ctrl:
        raise Reject(differs, f"plain forge test: {sig} issued by {issuer}, code the PoC does not control")
    if is_assert_or_expect(sig):
        return
    if sig in ALLOW:
        if sig in STATEFUL:
            events.append(_event(sig, (), T(n)["success"]))
        return
    rule = RULED.get(sig)
    if rule is None:
        raise Reject(differs, f"plain forge test calls {sig}, which the runner does not allow")
    cargs = poc_args(n, sig, differs)
    if rule == "env" and cargs[0] != "HYBLIS_ETH_RPC":
        raise Reject(differs, "plain forge test reads an environment variable other than HYBLIS_ETH_RPC")
    if sig in STATEFUL:
        events.append(_event(sig, cargs, T(n)["success"]))


def standalone_check(doc: dict, pr: dict, spec: dict, table: dict | None = None) -> None:
    """Rule 8 (the filed file is what was validated): plain forge test of the PoC file must pass, make the same
    entries into in-scope code with the same outcome, the same state-changing cheatcodes and helper calls in the
    same order (HyblisBase's helper frames there stand for the faucet calls under the runner), and no cheatcode
    the runner's policy denies, in any arena (constructor, setUp(), test_exploit() with its steps)."""
    table = table or load_selector_table()
    try:
        res, arenas = extract_result(doc, STANDALONE_SUITE, STANDALONE_TEST)
    except Reject:
        raise Reject("standalone_fails", "plain forge test did not run test_exploit() of HyblisPoC") from None
    if res["status"] != "Success":
        raise Reject("standalone_fails", "test_exploit() fails in plain forge test")
    sa_eoas = set(pr["eoas"].values())
    ctrl = {HARNESS} | sa_eoas
    helper_fn = {sel(sig): sig for sig in HELPER_FRAMES}
    sa_created, entries, events = [], [], []
    for kind in ("Deployment", "Setup", "Execution"):
        nodes = arenas.get(kind)
        if not nodes:
            continue
        helper_frames: dict[int, tuple[str, str]] = {}
        for n in nodes:
            t = T(n)
            if t["kind"] in CREATE_KINDS and t["success"] and n["parent"] is not None and caller(n) in ctrl:
                ctrl.add(addr(n))
                sa_created.append(addr(n))
            if n["parent"] is None:
                continue
            if addr(n) == HARNESS and t["kind"] == "CALL" and sel_of(n) in helper_fn:
                hsig = helper_fn[sel_of(n)]       # HyblisBase's helper frame on the PoC itself (the runner's copy)
                helper_frames[n["idx"]] = (HELPER_FRAMES[hsig], hsig)
                events.append(_event(hsig, poc_args(n, hsig, "standalone_differs"), t["success"]))
            elif addr(n) == CHEAT:
                _standalone_cheat(n, nodes, table, ctrl, helper_frames, events)
        entries += _entries(nodes, range(len(nodes)), spec)
    if len(sa_created) != len(pr["created"]):
        raise Reject("standalone_differs", "plain forge test creates a different number of contracts")
    m_h = {pr["poc"]: "<poc>"}
    m_s = {HARNESS: "<poc>"}
    for i, (ra, sa) in enumerate(pr["eoas"].items()):
        m_h[ra] = f"<eoa{i}>"
        m_s[sa] = f"<eoa{i}>"
    for i, (hc, sc) in enumerate(zip(pr["created"], sa_created)):
        m_h[hc] = f"<new{i}>"
        m_s[sc] = f"<new{i}>"
    a = _normalise(pr["entries"], m_h)
    b = _normalise(entries, m_s)
    if a != b:
        raise Reject("standalone_differs", f"{len(b)} in-scope calls in plain forge test, {len(a)} under the runner, "
                                          "or different arguments or outcomes")
    a = _normalise(pr["events"], m_h)
    b = _normalise(events, m_s)
    if a != b:
        k = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
        what = (b[k][0] if k < len(b) else a[k][0]).split(":")[-1]
        raise Reject("standalone_differs", f"state-changing cheatcode or helper call {k + 1} differs ({what}): "
                                          f"{len(b)} in plain forge test, {len(a)} under the runner")


# ------------------------------------------------------------------ the verdict
def base_verdict(submission_id: str = "") -> dict:
    return {"submission_id": submission_id, "reproduced": False, "deterministic": False, "impact_type": "",
            "measured_severity": "low", "changed_function": "", "changed_contract": "", "evidence": {},
            "state_misses": [], "error": None, "detail": ""}


def reject_verdict(err: Reject, submission_id: str = "", deterministic: bool = False, extra: dict | None = None) -> dict:
    v = base_verdict(submission_id)
    v.update({"deterministic": deterministic, "error": err.code, "detail": err.detail})
    if extra:
        v.update(extra)
    return v


def program_rules(pr: dict, spec: dict) -> None:
    it = pr["impact_type"]
    if it not in spec["in_scope_impacts"]:
        raise Reject("out_of_scope", f"impact {it} is not in scope for this task")
    for k in spec["known_issues"]:
        if k["contract"] == pr["changed_contract"] and k["function"] == pr["changed_function"] and k["impact"] == it:
            raise Reject("known_issue", f"known issue {k['id']}")
    for b in spec["benign_entry_points"]:
        if b["contract"] == pr["changed_contract"] and b["selector"] == pr["changed_selector"]:
            raise Reject("out_of_scope", f"through the benign entry point {b['function']}")


def decide(pass1: dict | None, pass2: dict, standalone_doc: dict | None, spec: dict, runner_info: dict,
           submission_id: str = "") -> dict:
    """Combine analysed passes (dicts from analyze_pass) and the standalone run into the verdict."""
    det = pass1 is None or pass1["fingerprints"]["poc"] == pass2["fingerprints"]["poc"]
    info = {"attacker_set": pass2["attacker_set"], "fingerprints": pass2["fingerprints"], "runner": runner_info}
    try:
        if not det:
            raise Reject("nondeterministic", "the PoC's calls differ between pass 1 and pass 2")
        if pass1 is not None and pass1["fingerprints"]["measure"] != pass2["fingerprints"]["measure"]:
            raise Reject("nondeterministic", "spec measurements differ between pass 1 and pass 2")
        if pass2.get("unmeasured_attackers"):
            raise Reject("nondeterministic", "pass 2 found attacker accounts pass 1 did not")
        if not pass2.get("impact_type"):
            raise Reject("no_impact", "no measured impact")
        if standalone_doc is not None:
            standalone_check(standalone_doc, pass2, spec)
        program_rules(pass2, spec)
    except Reject as e:
        v = reject_verdict(e, submission_id, deterministic=det, extra=info)
        if e.code == "no_impact":
            v["evidence"] = pass2.get("evidence", {})
        return v
    v = base_verdict(submission_id)
    v.update({"reproduced": True, "deterministic": True, "impact_type": pass2["impact_type"],
              "measured_severity": pass2["measured_severity"], "changed_function": pass2["changed_function"],
              "changed_contract": pass2["changed_contract"], "evidence": dict(pass2["evidence"]), "error": None})
    v["evidence"]["final_timestamp"] = pass2["ts_final"]
    v["evidence"]["helpers"] = {k: n for k, n in pass2["helpers_used"].items() if n and k != "attackerKey"}
    v.update(info)
    return v


def runner_info(spec: dict, hashes: dict | None = None, salt: str = "", steps: int = 0) -> dict:
    return {"version": ENGINE_VERSION, "foundry": FOUNDRY_VERSION, "spec_sha256": spec.get("spec_sha256", ""),
            "files": hashes or {}, "salt": salt, "steps": steps}


def main():
    ap = argparse.ArgumentParser(description="Analyse saved forge JSON (fixtures, debugging).")
    ap.add_argument("spec")
    ap.add_argument("pass2")
    ap.add_argument("--pass1")
    ap.add_argument("--standalone")
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--salt", required=True)
    ap.add_argument("--steps", type=int, default=0)
    ap.add_argument("--attacker-set", default="")
    ap.add_argument("--max-mb", type=int, default=256)
    a = ap.parse_args()
    spec = json.loads(Path(a.spec).read_text())
    table = load_selector_table()
    cap = a.max_mb * 1024 * 1024
    try:
        p1 = None
        if a.pass1:
            p1 = analyze_pass(load_forge_json(a.pass1, cap), Ctx(spec, a.rpc, a.salt, a.steps, [], table))
        aset = [x for x in a.attacker_set.split(",") if x] if a.attacker_set else \
            ([x for x in p1["attacker_order"] if x != p1["poc"]] if p1 else [])
        p2 = analyze_pass(load_forge_json(a.pass2, cap), Ctx(spec, a.rpc, a.salt, a.steps, aset, table))
        sd = load_forge_json(a.standalone, cap) if a.standalone else None
        v = decide(p1, p2, sd, spec, runner_info(spec, salt=a.salt, steps=a.steps))
    except Reject as e:
        v = reject_verdict(e)
    print(json.dumps(v, indent=1, default=str))


if __name__ == "__main__":
    main()
