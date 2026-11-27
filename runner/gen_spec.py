#!/usr/bin/env python3
"""impact-spec.json v2 -> generated HyblisSpec.sol + compiled spec JSON (runner input).

The impact spec is written per task by Hyblis (never by a miner). This tool:
  1. validates it strictly (unknown keys are errors; keys starting with "_" are comments);
  2. resolves every reference ("@holder-id", "@TOKEN", "@InScopeName"), signature and argument into
     exact addresses, selectors and calldata;
  3. writes HyblisSpec.sol, the only generated Solidity the harness uses (constants and arrays), and
     the compiled JSON the verdict engine (trace_verdict.py) reads;
  4. optionally self-checks the spec on a clean fork (--self-check): the fork block's hash and
     timestamp match, every view resolves, every invariant holds, every probe succeeds, every price
     feed reports the recorded answer, and an empty PoC gets "no impact".

The schema is documented in runner/README.md ("impact-spec v2").
Usage:
  gen_spec.py <impact-spec.json> [--sol out/HyblisSpec.sol] [--json out/spec.compiled.json] [--allow-draft]
  gen_spec.py <impact-spec.json> --self-check --project <prepared task project> --fork-url <url|ipc path>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from fractions import Fraction
from pathlib import Path

from eth_abi import encode as abi_encode
from eth_utils import keccak, to_checksum_address

HERE = Path(__file__).resolve().parent
SEVERITIES = ["low", "medium", "high", "critical"]
IMPACTS = ["funds_loss", "unauthorized_mint", "insolvency", "funds_freeze", "griefing", "accounting_error", "dos"]
ZERO = "0x" + "0" * 40
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
LIMIT_DEFAULTS = {"max_warp_s": 3600, "max_roll": 300, "poc_gas": 300_000_000, "max_attackers": 64,
                  "max_steps": 16, "json_max_mb": 256, "forge_timeout_s": 900, "job_timeout_s": 2700}
LIMIT_CAPS = {"poc_gas": 1_000_000_000, "max_attackers": 64, "max_steps": 16, "json_max_mb": 512}
MAX_VIEWS, MAX_PROBES = 256, 16


class SpecError(Exception):
    pass


# ------------------------------------------------------------------ small helpers
def sel(sig: str) -> str:
    return keccak(text=sig)[:4].hex()


ACCOUNT = "@account"
STATIC_ARG = re.compile(r"address|bool|u?int\d*|bytes([1-9]|[12]\d|3[0-2])")


def _claim_template(c: dict, w: str, encode_args) -> tuple[str, str]:
    """An attacker claim is read once per attacker account. Its calldata is `prefix + account + suffix`
    (hex, no 0x): the selector and the 32-byte words before the account argument, then the words after
    it. A one-address signature needs no `args`; any other takes `args` with exactly one "@account"
    (an address argument) and only static types, so the account word sits at a fixed offset."""
    types = split_types(c["sig"])
    args = c.get("args")
    if args is None:
        if types != ["address"]:
            raise SpecError(f"{w}: an attacker-claim view takes one address argument, or `args` with one "
                            f'"{ACCOUNT}"')
        args = [ACCOUNT]
    if not isinstance(args, list) or len(args) != len(types):
        raise SpecError(f"{w}: args must list one value per argument of {c['sig']}")
    at = [i for i, a in enumerate(args) if a == ACCOUNT]
    if len(at) != 1 or types[at[0]] != "address":
        raise SpecError(f'{w}: exactly one address argument must be "{ACCOUNT}"')
    if not all(STATIC_ARG.fullmatch(t) for t in types):
        raise SpecError(f"{w}: attacker-claim arguments must be static types")
    zero = "0x" + "00" * 20
    data = encode_args(c["sig"], [zero if i == at[0] else a for i, a in enumerate(args)], w)[2:]
    k = 8 + 64 * at[0]
    return data[:k], data[k + 64:]


def split_types(sig: str) -> list[str]:
    if "(" not in sig or not sig.endswith(")"):
        raise SpecError(f"bad signature {sig!r}")
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


def _keys(obj: dict, where: str, required: set, optional: set = frozenset()):
    if not isinstance(obj, dict):
        raise SpecError(f"{where}: expected an object")
    keys = {k for k in obj if not k.startswith("_") and not k.endswith("_note")}
    missing = required - keys
    unknown = keys - required - set(optional)
    if missing:
        raise SpecError(f"{where}: missing {sorted(missing)}")
    if unknown:
        raise SpecError(f"{where}: unknown keys {sorted(unknown)}")


def _addr(v, where: str) -> str:
    if not isinstance(v, str) or not ADDR_RE.match(v):
        raise SpecError(f"{where}: not an address: {v!r}")
    return v.lower()


def _int(v, where: str) -> int:
    if isinstance(v, bool):
        raise SpecError(f"{where}: expected an integer")
    if isinstance(v, int):
        return v
    if isinstance(v, str) and re.fullmatch(r"-?\d+", v):
        return int(v)
    raise SpecError(f"{where}: expected an integer, got {v!r}")


def _dec(v, where: str) -> str:
    try:
        f = Fraction(str(v))
    except (ValueError, ZeroDivisionError):
        raise SpecError(f"{where}: expected a decimal number, got {v!r}") from None
    if f < 0:
        raise SpecError(f"{where}: must not be negative")
    return str(v)


# ------------------------------------------------------------------ compile
def compile_spec(spec: dict, allow_draft: bool = False) -> dict:
    """Validate and resolve an impact-spec v2 into the compiled form the engine and generator use."""
    _keys(spec, "spec", {"task_id", "spec_version", "fork", "tokens", "holders", "in_scope", "views",
                         "thresholds", "severity", "in_scope_impacts"},
          {"status", "limits", "harness", "protected_extra", "attacker_claims", "invariants", "probes",
           "trusted_actions", "price_feeds", "benign_entry_points", "known_issues", "pending_verification"})
    if spec["spec_version"] != 2:
        raise SpecError("spec_version must be 2")
    status = spec.get("status", "verified")
    if status not in ("verified", "draft", "scaffold"):
        raise SpecError(f"status {status!r} must be verified, draft or scaffold")
    if status != "verified" and not allow_draft:
        raise SpecError(f"spec status is {status!r}: only a verified spec can be used by the runner")
    if spec.get("pending_verification") and not allow_draft:
        raise SpecError("spec still has pending_verification items")

    fk = spec["fork"]
    _keys(fk, "fork", {"chain_id", "block", "block_hash", "timestamp"}, {"rpc_env"})
    if fk.get("rpc_env", "HYBLIS_ETH_RPC") != "HYBLIS_ETH_RPC":
        raise SpecError("fork.rpc_env must be HYBLIS_ETH_RPC")
    fork = {"chain_id": _int(fk["chain_id"], "fork.chain_id"), "block": _int(fk["block"], "fork.block"),
            "block_hash": str(fk["block_hash"]).lower(), "timestamp": _int(fk["timestamp"], "fork.timestamp"),
            "rpc_env": "HYBLIS_ETH_RPC"}
    if not re.fullmatch(r"0x[0-9a-f]{64}", fork["block_hash"]):
        raise SpecError("fork.block_hash must be a 32-byte hex hash")

    lim_in = spec.get("limits", {})
    _keys(lim_in, "limits", set(), set(LIMIT_DEFAULTS) | {"horizon_basis"})
    limits = dict(LIMIT_DEFAULTS)
    for k in LIMIT_DEFAULTS:
        if k in lim_in:
            limits[k] = _int(lim_in[k], f"limits.{k}")
            if limits[k] < 0:
                raise SpecError(f"limits.{k} must not be negative")
            if k in LIMIT_CAPS and limits[k] > LIMIT_CAPS[k]:
                raise SpecError(f"limits.{k} above the runner maximum {LIMIT_CAPS[k]}")
    if ("max_warp_s" in lim_in or "max_roll" in lim_in) and not lim_in.get("horizon_basis"):
        raise SpecError("limits.horizon_basis must say which protocol horizon the time limits come from")
    limits["horizon_basis"] = lim_in.get("horizon_basis", "")

    hz = spec.get("harness", {})
    _keys(hz, "harness", set(), {"poc_test"})
    poc_test = hz.get("poc_test", "test_exploit()")
    if poc_test != "test_exploit()":
        raise SpecError("harness.poc_test must be test_exploit()")

    # ---- names that "@ref" may point to
    refs: dict[str, str] = {}

    def add_ref(name, address, where):
        if name in refs and refs[name] != address:
            raise SpecError(f"{where}: name {name!r} already used for another address")
        refs[name] = address

    tokens, sym = [], {}
    for i, t in enumerate(spec["tokens"]):
        w = f"tokens[{i}]"
        _keys(t, w, {"symbol", "address", "decimals", "usd"},
              {"capital", "capital_cap", "issued_by_protocol", "supply_view"})
        a = _addr(t["address"], w)
        if t["symbol"] in sym:
            raise SpecError(f"{w}: duplicate symbol")
        if bool(t.get("capital")) != ("capital_cap" in t):
            raise SpecError(f"{w}: a capital token needs capital_cap (and only a capital token has one)")
        tok = {"symbol": t["symbol"], "address": a, "decimals": _int(t["decimals"], f"{w}.decimals"),
               "usd": _dec(t["usd"], f"{w}.usd"), "capital": bool(t.get("capital")),
               "capital_cap": str(_int(t["capital_cap"], f"{w}.capital_cap")) if t.get("capital") else "0",
               "issued_by_protocol": bool(t.get("issued_by_protocol")), "supply_view": t.get("supply_view")}
        if tok["issued_by_protocol"] and tok["capital"]:
            raise SpecError(f"{w}: a protocol-issued token cannot be attacker capital")
        if tok["issued_by_protocol"] and not tok["supply_view"]:
            raise SpecError(f"{w}: a protocol-issued token needs supply_view")
        tokens.append(tok)
        sym[tok["symbol"]] = tok
        add_ref(tok["symbol"], a, w)
    if not tokens:
        raise SpecError("tokens: at least one")

    holders, hid = [], {}
    for i, h in enumerate(spec["holders"]):
        w = f"holders[{i}]"
        _keys(h, w, {"id", "address", "role"}, {"value_views"})
        if h["role"] not in ("custody", "victim", "watch"):
            raise SpecError(f"{w}: role must be custody, victim or watch")
        a = _addr(h["address"], w)
        if h["id"] in hid or a in {x["address"] for x in holders}:
            raise SpecError(f"{w}: duplicate holder")
        hold = {"id": h["id"], "address": a, "role": h["role"], "value_views": []}
        for j, vv in enumerate(h.get("value_views", [])):
            _keys(vv, f"{w}.value_views[{j}]", {"view", "token"})
            hold["value_views"].append({"view": vv["view"], "token": vv["token"]})
        holders.append(hold)
        hid[h["id"]] = hold
        add_ref(h["id"], a, w)
    if not any(h["role"] == "custody" for h in holders):
        raise SpecError("holders: at least one custody holder")

    in_scope = []
    for i, c in enumerate(spec["in_scope"]):
        w = f"in_scope[{i}]"
        _keys(c, w, {"name", "address"}, {"functions", "abi_file", "implementation"})
        a = _addr(c["address"], w)
        fns = list(c.get("functions", []))
        if c.get("abi_file"):
            fns += _abi_functions(c["abi_file"])
        functions = {sel(f): f for f in fns}
        entry = {"name": c["name"], "address": a, "functions": functions}
        in_scope.append(entry)
        add_ref(c["name"], a, w)
        if c.get("implementation"):
            in_scope.append({"name": c["name"] + ".implementation", "address": _addr(c["implementation"], w),
                             "functions": {}})
    if len({c["address"] for c in in_scope}) != len(in_scope):
        raise SpecError("in_scope: duplicate address")

    def resolve_addr(v, where):
        if isinstance(v, str) and v.startswith("@"):
            if v[1:] not in refs:
                raise SpecError(f"{where}: unknown reference {v}")
            return refs[v[1:]]
        return _addr(v, where)

    def encode_args(sig, args, where):
        types = split_types(sig)
        args = list(args or [])
        if len(args) != len(types):
            raise SpecError(f"{where}: {sig} takes {len(types)} arguments, got {len(args)}")
        vals = []
        for k, (ty, v) in enumerate(zip(types, args)):
            wk = f"{where}.args[{k}]"
            if ty == "address":
                vals.append(to_checksum_address(resolve_addr(v, wk)))
            elif re.fullmatch(r"u?int\d*", ty):
                vals.append(_int(v, wk))
            elif ty == "bool":
                if not isinstance(v, bool):
                    raise SpecError(f"{wk}: expected true/false")
                vals.append(v)
            elif re.fullmatch(r"bytes\d+", ty):
                vals.append(bytes.fromhex(str(v)[2:]))
            elif ty == "string":
                vals.append(str(v))
            else:
                raise SpecError(f"{wk}: argument type {ty} not supported in specs")
        return "0x" + sel(sig) + abi_encode(types, vals).hex()

    views, vid = [], {}
    for i, v in enumerate(spec["views"]):
        w = f"views[{i}]"
        _keys(v, w, {"id", "target", "sig", "type", "role"}, {"args", "token"})
        if v["role"] not in ("state", "victim_claim"):
            raise SpecError(f"{w}: role must be state or victim_claim")
        if v["type"] not in ("uint256", "int256", "bool", "address", "uint128", "uint64", "uint8", "bytes32"):
            raise SpecError(f"{w}: unsupported view type {v['type']}")
        if v["role"] == "victim_claim" and v.get("token") not in sym:
            raise SpecError(f"{w}: a victim_claim view needs token (a token symbol)")
        if v["id"] in vid:
            raise SpecError(f"{w}: duplicate id")
        cv = {"id": v["id"], "target": resolve_addr(v["target"], w), "sig": v["sig"],
              "calldata": encode_args(v["sig"], v.get("args"), w), "type": v["type"], "role": v["role"],
              "token": v.get("token")}
        views.append(cv)
        vid[v["id"]] = cv
    if len({(v["target"], v["calldata"]) for v in views}) != len(views):
        raise SpecError("views: two views make the same call")
    for t in tokens:
        if t["supply_view"] and t["supply_view"] not in vid:
            raise SpecError(f"token {t['symbol']}: supply_view {t['supply_view']} is not a view")
    for h in holders:
        for vv in h["value_views"]:
            if vv["view"] not in vid or vv["token"] not in sym:
                raise SpecError(f"holder {h['id']}: value_views reference unknown view/token")

    claims = []
    for i, c in enumerate(spec.get("attacker_claims", [])):
        w = f"attacker_claims[{i}]"
        _keys(c, w, {"id", "target", "sig", "type", "token"}, {"sign", "args"})
        prefix, suffix = _claim_template(c, w, encode_args)
        if c["token"] not in sym:
            raise SpecError(f"{w}: unknown token")
        sign = _int(c.get("sign", 1), f"{w}.sign")
        if sign not in (1, -1):
            raise SpecError(f"{w}: sign must be 1 (asset) or -1 (liability)")
        claims.append({"id": c["id"], "target": resolve_addr(c["target"], w), "selector": sel(c["sig"]),
                       "prefix": prefix, "suffix": suffix,
                       "sig": c["sig"], "type": c["type"], "token": c["token"], "sign": sign})
    if len({(c["target"], c["prefix"], c["suffix"]) for c in claims}) != len(claims):
        raise SpecError("attacker_claims: two claims make the same call")

    names = set(vid) | {f"bal_{t['symbol']}_{h['id']}" for t in tokens for h in holders}
    invariants = []
    for i, inv in enumerate(spec.get("invariants", [])):
        w = f"invariants[{i}]"
        _keys(inv, w, {"id", "class", "holds"}, {"shortfall", "units"})
        if inv["class"] not in ("solvency", "accounting"):
            raise SpecError(f"{w}: class must be solvency or accounting")
        for expr_key in ("holds", "shortfall"):
            if expr_key in inv:
                _check_expr(inv[expr_key], names, f"{w}.{expr_key}")
        if inv["class"] == "solvency" and ("shortfall" not in inv or inv.get("units") not in sym):
            raise SpecError(f"{w}: a solvency invariant needs shortfall and units (a token symbol)")
        invariants.append({"id": inv["id"], "class": inv["class"],
                           "impact": "insolvency" if inv["class"] == "solvency" else "accounting_error",
                           "holds": inv["holds"], "shortfall": inv.get("shortfall"), "units": inv.get("units")})

    probes = []
    for i, p in enumerate(spec.get("probes", [])):
        w = f"probes[{i}]"
        _keys(p, w, {"id", "class", "actor", "target", "sig"}, {"args", "gas", "at_risk", "at_risk_token"})
        if p["class"] not in ("freeze", "liveness"):
            raise SpecError(f"{w}: class must be freeze or liveness")
        if p["class"] == "freeze" and p.get("at_risk") not in vid:
            raise SpecError(f"{w}: a freeze probe needs at_risk (a view id)")
        at_tok = p.get("at_risk_token") or (vid[p["at_risk"]]["token"] if p.get("at_risk") else None)
        if p["class"] == "freeze" and at_tok not in sym:
            raise SpecError(f"{w}: at_risk_token unknown (set it, or give the at_risk view a token)")
        probes.append({"id": p["id"], "class": p["class"],
                       "impact": "funds_freeze" if p["class"] == "freeze" else "dos",
                       "actor": resolve_addr(p["actor"], w), "target": resolve_addr(p["target"], w),
                       "sig": p["sig"], "calldata": encode_args(p["sig"], p.get("args"), w),
                       "gas": _int(p.get("gas", 5_000_000), f"{w}.gas"), "at_risk": p.get("at_risk"),
                       "at_risk_token": at_tok})
    if len(views) > MAX_VIEWS or len(probes) > MAX_PROBES:
        raise SpecError(f"at most {MAX_VIEWS} views and {MAX_PROBES} probes")

    actions = []
    for i, a in enumerate(spec.get("trusted_actions", [])):
        w = f"trusted_actions[{i}]"
        _keys(a, w, {"id", "role", "target", "sig"}, {"args", "max_calls"})
        types = split_types(a["sig"])
        rules = a.get("args")
        if rules is not None and len(rules) != len(types):
            raise SpecError(f"{w}: args must have one rule (or null) per argument")
        crules = []
        for k, r in enumerate(rules or [None] * len(types)):
            if r is None:
                crules.append(None)
                continue
            _keys(r, f"{w}.args[{k}]", set(), {"eq", "min", "max"})
            cr = {}
            for kk in ("eq", "min", "max"):
                if kk in r:
                    if types[k] == "address":
                        cr[kk] = resolve_addr(r[kk], f"{w}.args[{k}].{kk}")
                    else:
                        cr[kk] = str(_int(r[kk], f"{w}.args[{k}].{kk}"))
            crules.append(cr)
        actions.append({"id": a["id"], "role": resolve_addr(a["role"], w), "target": resolve_addr(a["target"], w),
                        "sig": a["sig"], "selector": sel(a["sig"]), "arg_types": types, "args": crules,
                        "max_calls": _int(a.get("max_calls", 1), f"{w}.max_calls")})

    feeds = []
    for i, f in enumerate(spec.get("price_feeds", [])):
        w = f"price_feeds[{i}]"
        _keys(f, w, {"id", "feed", "token", "decimals", "answer", "max_move_bps"})
        if f["token"] not in sym:
            raise SpecError(f"{w}: unknown token")
        feeds.append({"id": f["id"], "feed": _addr(f["feed"], w), "token": f["token"],
                      "decimals": _int(f["decimals"], f"{w}.decimals"), "answer": str(_int(f["answer"], f"{w}.answer")),
                      "max_move_bps": _int(f["max_move_bps"], f"{w}.max_move_bps")})
    if len({f["token"] for f in feeds}) != len(feeds):
        raise SpecError("price_feeds: one feed per token")
    for f in feeds:   # every feed's answer is measured too, so the self-check can verify it through the harness
        cv = {"id": f"__feed_{f['id']}", "target": f["feed"], "sig": "latestAnswer()", "calldata": "0x" + sel("latestAnswer()"),
              "type": "int256", "role": "state", "token": None}
        if (cv["target"], cv["calldata"]) not in {(v["target"], v["calldata"]) for v in views}:
            views.append(cv)
            vid[cv["id"]] = cv

    by_name = {c["name"]: c for c in in_scope}
    benign = []
    for i, b in enumerate(spec.get("benign_entry_points", [])):
        _keys(b, f"benign_entry_points[{i}]", {"contract", "function"})
        if b["contract"] not in by_name:
            raise SpecError(f"benign_entry_points[{i}]: unknown in-scope contract")
        benign.append({"contract": by_name[b["contract"]]["address"], "selector": sel(b["function"]),
                       "function": b["function"]})
    known = []
    for i, k in enumerate(spec.get("known_issues", [])):
        _keys(k, f"known_issues[{i}]", {"id", "contract", "function", "impact"})
        if k["contract"] not in by_name or k["impact"] not in IMPACTS:
            raise SpecError(f"known_issues[{i}]: unknown contract or impact")
        known.append({"id": k["id"], "contract": by_name[k["contract"]]["address"], "function": k["function"],
                      "impact": k["impact"]})

    th = spec["thresholds"]
    _keys(th, "thresholds", {"min_usd"})
    sev = spec["severity"]
    _keys(sev, "severity", {"max"}, set(IMPACTS))
    if sev["max"] not in SEVERITIES:
        raise SpecError("severity.max must be low, medium, high or critical")
    csev = {"max": sev["max"]}
    for imp in IMPACTS:
        r = sev.get(imp, {"default": "low"})
        _keys(r, f"severity.{imp}", {"default"},
              {"high_if_tvl_share", "high_if_usd", "critical_if_tvl_share", "critical_if_usd"})
        if r["default"] not in SEVERITIES:
            raise SpecError(f"severity.{imp}.default invalid")
        csev[imp] = {k: (v if k == "default" else _dec(v, f"severity.{imp}.{k}")) for k, v in r.items()
                     if not k.startswith("_")}
    impacts = list(spec["in_scope_impacts"])
    if not set(impacts) <= set(IMPACTS):
        raise SpecError("in_scope_impacts: unknown impact type")

    protected = set(refs.values()) | {c["address"] for c in in_scope} | {v["target"] for v in views}
    protected |= {a["role"] for a in actions} | {a["target"] for a in actions} | {f["feed"] for f in feeds}
    protected |= {p["actor"] for p in probes} | {p["target"] for p in probes}
    for i, a in enumerate(spec.get("protected_extra", [])):
        protected.add(_addr(a, f"protected_extra[{i}]"))
    protected.discard(ZERO)
    watch = {c["address"] for c in in_scope} | {t["address"] for t in tokens if t["address"] != ZERO}
    watch |= {f["feed"] for f in feeds} | {h["address"] for h in holders if h["role"] == "custody"}

    compiled = {
        "task_id": spec["task_id"], "spec_version": 2, "status": status, "fork": fork, "limits": limits,
        "poc_test": poc_test, "poc_test_selector": sel(poc_test), "tokens": tokens, "holders": holders,
        "in_scope": in_scope, "views": views, "attacker_claims": claims, "invariants": invariants,
        "probes": probes, "trusted_actions": actions, "price_feeds": feeds, "protected": sorted(protected),
        "code_watch": sorted(watch), "benign_entry_points": benign, "known_issues": known,
        "thresholds": {"min_usd": _dec(th["min_usd"], "thresholds.min_usd")}, "severity": csev,
        "in_scope_impacts": impacts,
    }
    compiled["spec_sha256"] = hashlib.sha256(json.dumps(compiled, sort_keys=True).encode()).hexdigest()
    return compiled


def _abi_functions(path: str) -> list[str]:
    p = Path(path)
    if not p.is_absolute():
        p = HERE.parent / p
    data = json.loads(p.read_text())
    abi = data["abi"] if isinstance(data, dict) else data
    out = []
    for item in abi:
        if item.get("type") == "function":
            out.append(f"{item['name']}({','.join(_abi_type(x) for x in item.get('inputs', []))})")
    return out


def _abi_type(x: dict) -> str:
    t = x["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(_abi_type(c) for c in x["components"]) + ")" + t[len("tuple"):]
    return t


_EXPR_NODES = None


def _check_expr(expr: str, names: set, where: str):
    import ast
    global _EXPR_NODES
    if _EXPR_NODES is None:
        _EXPR_NODES = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Compare, ast.BoolOp, ast.Name, ast.Load,
                       ast.Constant, ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod, ast.USub, ast.Not,
                       ast.And, ast.Or, ast.Gt, ast.GtE, ast.Lt, ast.LtE, ast.Eq, ast.NotEq)
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError:
        raise SpecError(f"{where}: not an expression") from None
    for node in ast.walk(tree):
        if not isinstance(node, _EXPR_NODES):
            raise SpecError(f"{where}: {type(node).__name__} not allowed (arithmetic, comparisons, and/or/not only)")
        if isinstance(node, ast.Name) and node.id not in names:
            raise SpecError(f"{where}: unknown name {node.id}")
        if isinstance(node, ast.Constant) and not isinstance(node.value, (int, bool)):
            raise SpecError(f"{where}: only integer constants")


# ------------------------------------------------------------------ Solidity
def _sol_addr(a: str) -> str:
    return "address(0)" if a == ZERO else to_checksum_address(a)


def _addr_array(fn: str, addrs: list[str]) -> str:
    body = [f"        out = new address[]({len(addrs)});"]
    body += [f"        out[{i}] = {_sol_addr(a)};" for i, a in enumerate(addrs)]
    return f"    function {fn}() internal pure returns (address[] memory out) {{\n" + "\n".join(body) + "\n    }\n"


PROBE_READ_GAS = 5_000_000          # HyblisProbe.READ_GAS: gas cap of each balance or view read
HARNESS_RESERVE = 1_000_000_000     # the harness's own root calls (probe, faucet, state-diff reads, the baseline fork)


def harness_gas_limit(c: dict) -> int:
    """The harness test's total gas budget (foundry.toml gas_limit of the runner): every PoC call may use its full
    poc_gas (constructor, setUp, and test_exploit() or up to max_steps steps), plus the worst case of the two
    measurements (every read at its gas cap, with the largest attacker set), the probes on both forks, and a
    reserve for the harness itself. A PoC call that gets less than poc_gas is rejected as `limits`."""
    lim = c["limits"]
    poc_calls = 2 + max(1, lim["max_steps"])
    holders = len(c["holders"]) + 1 + lim["max_attackers"]
    reads = len(c["tokens"]) * holders + len(c["views"]) + len(c["attacker_claims"]) * (1 + lim["max_attackers"])
    probes = sum(p["gas"] for p in c["probes"])
    return poc_calls * lim["poc_gas"] + 2 * (reads * PROBE_READ_GAS + probes) + HARNESS_RESERVE


def render_solidity(c: dict) -> str:
    v_t = [v["target"] for v in c["views"]]
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity >=0.8.13 <0.9.0;",
        "",
        f"// GENERATED by runner/gen_spec.py from the impact spec of task {c['task_id']!r}",
        f"// (spec_sha256 {c['spec_sha256']}). Do not edit: the runner regenerates it for every job.",
        "",
        "library HyblisSpec {",
        f"    uint256 internal constant FORK_BLOCK = {c['fork']['block']};",
        f"    uint256 internal constant POC_GAS = {c['limits']['poc_gas']};",
        f"    bytes4 internal constant POC_TEST = 0x{c['poc_test_selector']};",
        "",
        _addr_array("tokens", [t["address"] for t in c["tokens"]]),
        _addr_array("holders", [h["address"] for h in c["holders"]]),
        _addr_array("codeWatch", c["code_watch"]),
        "    function views() internal pure returns (address[] memory t, bytes[] memory d) {",
        f"        t = new address[]({len(v_t)});",
        f"        d = new bytes[]({len(v_t)});",
    ]
    for i, v in enumerate(c["views"]):
        lines.append(f"        t[{i}] = {_sol_addr(v['target'])}; d[{i}] = hex\"{v['calldata'][2:]}\";")
    lines += ["    }", "",
              "    function claimTemplates()",
              "        internal pure returns (address[] memory t, bytes[] memory pre, bytes[] memory post)",
              "    {",
              f"        t = new address[]({len(c['attacker_claims'])});",
              f"        pre = new bytes[]({len(c['attacker_claims'])});",
              f"        post = new bytes[]({len(c['attacker_claims'])});"]
    for i, cl in enumerate(c["attacker_claims"]):
        lines.append(f"        t[{i}] = {_sol_addr(cl['target'])}; pre[{i}] = hex\"{cl['prefix']}\"; "
                     f"post[{i}] = hex\"{cl['suffix']}\";")
    lines += ["    }", "",
              "    function probes() internal pure",
              "        returns (address[] memory a, address[] memory t, bytes[] memory d, uint256[] memory g)",
              "    {",
              f"        a = new address[]({len(c['probes'])});",
              f"        t = new address[]({len(c['probes'])});",
              f"        d = new bytes[]({len(c['probes'])});",
              f"        g = new uint256[]({len(c['probes'])});"]
    for i, p in enumerate(c["probes"]):
        lines.append(f"        a[{i}] = {_sol_addr(p['actor'])}; t[{i}] = {_sol_addr(p['target'])}; "
                     f"d[{i}] = hex\"{p['calldata'][2:]}\"; g[{i}] = {p['gas']};")
    lines += ["    }", "}", ""]
    return "\n".join(lines)


# ------------------------------------------------------------------ self-check
def self_check(spec_path: Path, project: Path, fork_url: str, manifest: dict | None = None,
               options=None, sandbox: str = "auto", fork=None) -> dict:
    """Run the spec on a clean fork with an empty PoC through the real harness and engine. `fork` is the
    state layer's proxy handle when the fork is a snapshot (it answers the job's fresh accounts)."""
    import run_submission
    spec = json.loads(Path(spec_path).read_text())
    compiled = compile_spec(spec)
    problems = []
    hdr = run_submission.fork_block_header(fork_url, compiled["fork"]["block"])
    if hdr is None:
        problems.append("could not read the fork block header (cast block)")
    else:
        if hdr["hash"] != compiled["fork"]["block_hash"]:
            problems.append(f"fork block hash {hdr['hash']} != spec {compiled['fork']['block_hash']}")
        if hdr["timestamp"] != compiled["fork"]["timestamp"]:
            problems.append(f"fork timestamp {hdr['timestamp']} != spec {compiled['fork']['timestamp']}")
    poc = null_poc(compiled)
    verdict = run_submission.reproduce_with_spec(compiled, poc, Path(project), fork_url, "self-check",
                                                 sandbox=sandbox, debug=True, manifest=manifest, options=options,
                                                 fork=fork)
    health = (verdict.get("debug") or {}).get("spec_health") or {}
    for k in ("views_failed", "invariants_not_holding", "probes_failing"):
        for item in health.get(k, []):
            problems.append(f"{k}: {item}")
    for f in compiled["price_feeds"]:
        got = (health.get("views_base") or {}).get(f"__feed_{f['id']}")
        if got is None or str(got) != f["answer"]:
            problems.append(f"feeds_off: {f['id']} answers {got} at the fork block, spec {f['answer']}")
    if verdict.get("error") != "no_impact":
        problems.append(f"empty PoC verdict is {verdict.get('error') or verdict.get('impact_type')!r}, expected no_impact"
                        + (f" ({len(verdict.get('state_misses') or [])} state misses)" if verdict.get("state_misses") else ""))
    return {"ok": not problems, "problems": problems, "spec_sha256": compiled["spec_sha256"],
            "verdict_error": verdict.get("error"), "detail": verdict.get("detail")}


def null_poc(compiled: dict) -> str:
    return f"""// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.13 <0.9.0;
import {{HyblisBase}} from "./HyblisBase.sol";
// Hyblis spec self-check: an empty PoC must get "no impact".
contract HyblisPoC is HyblisBase {{
    uint256 constant FORK_BLOCK = {compiled['fork']['block']};
    function setUp() public {{ vm.createSelectFork(vm.envString("HYBLIS_ETH_RPC"), FORK_BLOCK); }}
    function test_exploit() public {{}}
}}
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spec")
    ap.add_argument("--sol")
    ap.add_argument("--json")
    ap.add_argument("--allow-draft", action="store_true")
    ap.add_argument("--self-check", action="store_true")
    ap.add_argument("--project")
    ap.add_argument("--fork-url")
    ap.add_argument("--snapshot", help="serve this verified snapshot in-process (runner/state) instead of --fork-url;"
                                       " needs --task-manifest (its chain.fork_block_hash is the trust anchor)")
    ap.add_argument("--task-manifest")
    ap.add_argument("--sandbox", default="auto", choices=["auto", "netns", "none"])
    a = ap.parse_args()
    try:
        compiled = compile_spec(json.loads(Path(a.spec).read_text()), allow_draft=a.allow_draft)
    except (SpecError, ValueError, KeyError, TypeError) as e:
        print(f"SPEC ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    if a.sol:
        Path(a.sol).write_text(render_solidity(compiled))
    if a.json:
        Path(a.json).write_text(json.dumps(compiled, indent=1, sort_keys=True))
    if a.self_check:
        if not (a.project and (a.fork_url or a.snapshot)):
            sys.exit("--self-check needs --project and --fork-url or --snapshot")
        handle = None
        fork_url = a.fork_url
        if a.snapshot:
            import tempfile
            sys.path.insert(0, str(HERE))
            from state import fork_proxy
            if not a.task_manifest:
                sys.exit("--snapshot needs --task-manifest")
            ch = json.loads(Path(a.task_manifest).read_text())["chain"]
            fork_url = str(Path(tempfile.mkdtemp(prefix="hyblis-selfcheck-")) / "fork.ipc")
            handle = fork_proxy.serve(a.snapshot, fork_url, expect_block_hash=ch["fork_block_hash"],
                                      expect_chain_id=int(ch["chain_id"]))
        try:
            res = self_check(Path(a.spec), Path(a.project), fork_url, sandbox=a.sandbox, fork=handle)
            if handle is not None:
                res["state_misses"] = handle.misses()
                res["ok"] = res["ok"] and not res["state_misses"]
        finally:
            if handle is not None:
                handle.close()
                import shutil
                shutil.rmtree(Path(fork_url).parent, ignore_errors=True)
        print(json.dumps(res, indent=1))
        sys.exit(0 if res["ok"] else 1)
    if not (a.sol or a.json):
        print(json.dumps({"ok": True, "spec_sha256": compiled["spec_sha256"]}))


if __name__ == "__main__":
    main()
