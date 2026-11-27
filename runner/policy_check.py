#!/usr/bin/env python3
"""Hyblis PoC policy check (static, first pass).

Reads one Solidity PoC file plus the task manifest and returns a verdict:
  REJECT  forbidden capability, or the PoC manipulates in-scope protocol state directly
  FLAG    allowed, but a reviewer must accept the justification (attacker capital, time travel,
          impersonating an external account, ...)
  PASS    nothing suspicious found

This is a cheap pre-filter, not a security boundary. The isolated runner (no network except the
read-only fork RPC, ffi off, disposable VM) and the human review are still required.
The PoC is untrusted text, so every scan here runs in time linear in its length: no pattern is
retried over the rest of the file from every position (a 256 KiB PoC is checked in well under a
second). Reported lines are lines of the PoC as written, comments included.
Usage: policy_check.py <manifest.json> <poc.t.sol | ->   -> prints JSON, exit 0/1/2 = PASS/FLAG/REJECT
       ("-" reads the PoC from stdin)
"""
import bisect
import json
import re
import sys

FORBIDDEN = ["ffi", "store", "etch", "mockCall", "mockCallRevert", "mockFunction", "setNonce", "setNonceUnsafe",
             "writeFile", "writeLine", "readFile", "readLine", "removeFile", "readDir", "fsMetadata", "projectRoot",
             "setEnv", "broadcast", "startBroadcast", "rpc", "allowCheatcodes", "copyStorage", "setArbitraryStorage",
             "cool", "resetNonce", "chainId", "createFork", "selectFork", "rollFork", "makePersistent"]
FLAGGED = ["warp", "roll", "fee", "coinbase", "prevrandao", "difficulty", "txGasPrice", "deal", "label"]
ADDR = re.compile(r"0x[0-9a-fA-F]{40}")

# `NAME = 0x...` or `NAME = Iface(0x...)`. Searched from word starts only: an unanchored (\w+) is
# retried at every position of a long word, which is quadratic. _bound() keeps finditer's matches.
_BOUND = r"(\w+)\s*=\s*(?:[\w.]+\s*\(\s*)*(0x[0-9a-fA-F]{40})"
_BOUND_HERE, _BOUND_NEXT = re.compile(_BOUND), re.compile(r"\b" + _BOUND)
# Calls whose arguments run up to `) ;`, found per statement by _calls()
_FORK = re.compile(r"vm\s*\.\s*createSelectFork\s*\(")
_PRANK = re.compile(r"vm\s*\.\s*(prank|startPrank)\s*\(")
_VM_DEAL = re.compile(r"vm\s*\.\s*deal\s*\(")
_DEAL = re.compile(r"(?<![\w.])deal\s*\(")
_HOAX = re.compile(r"(?<![\w.])(hoax|startHoax|changePrank)\s*\(")
_ADDRESS_OF = re.compile(r"address\s*\(")


def _without(text, spans):
    """text minus the given sorted, non-overlapping (start, end) spans, and the start of each kept
    piece as (position in the result, position in text)."""
    pieces, starts, pos, n = [], [], 0, 0
    for a, b in spans:
        pieces.append(text[pos:a])
        starts.append((n, pos))
        n += a - pos
        pos = b
    pieces.append(text[pos:])
    starts.append((n, pos))
    return "".join(pieces), starts


def _block_comments(src):
    # Each /* ends at the first */ after it; an unclosed /* is left alone. Same matches as
    # re.sub(r"/\*.*?\*/", "", src, flags=re.S), which was quadratic on many unclosed "/*".
    i = 0
    while True:
        j = src.find("/*", i)
        k = src.find("*/", j + 2) if j >= 0 else -1
        if k < 0:
            return
        yield j, k + 2
        i = k + 2


def _strip(src):
    """(code, src_pos): src without /* */ and then // comments, and a function giving the
    position in src of code[p], so findings can name the line the researcher wrote."""
    text, kept1 = _without(src, _block_comments(src))
    code, kept2 = _without(text, ((m.start(), m.end()) for m in re.finditer(r"//[^\n]*", text)))
    at1, at2 = [a for a, _ in kept1], [a for a, _ in kept2]

    def src_pos(p):
        i = bisect.bisect_right(at2, p) - 1
        t = kept2[i][1] + p - at2[i]
        j = bisect.bisect_right(at1, t) - 1
        return kept1[j][1] + t - at1[j]
    return code, src_pos


def strip_comments(src):
    return _strip(src)[0]


def _bound(code):
    """The matches of re.finditer(_BOUND, code). A match starts at a word start, or exactly where
    the previous one ended (an address literal may run on into more word characters)."""
    out, pos = [], 0
    while True:
        m = _BOUND_HERE.match(code, pos) or _BOUND_NEXT.search(code, pos)
        if not m:
            return out
        out.append(m)
        pos = m.end()


def _statements(code):
    """(start, end, close) for each ';'-terminated statement whose last non-blank character is
    ')', at position close."""
    out, start = [], 0
    while True:
        end = code.find(";", start)
        if end < 0:
            return out
        body = code[start:end].rstrip()
        if body.endswith(")"):
            out.append((start, end, start + len(body) - 1))
        start = end + 1


def _calls(prefix, statements, code):
    """The matches of prefix + r"([^;]*?)\\)\\s*;" as (match, arguments). Such a match ends at the
    first ';' after the prefix, and its last ')' is the last non-blank character before that ';'.
    So a statement holds at most one: the first prefix in a statement that ends with ')'.
    (Retrying the regex from every prefix up to the next ';' was quadratic.)"""
    out = []
    for start, end, close in statements:
        m = prefix.search(code, start, end)
        if m:
            out.append((m, code[m.end():close]))
    return out


def _unwrap_address(expr):
    """re.sub(r"^address\\s*\\(\\s*(.*)\\s*\\)$", r"\\1", expr) for an expr without surrounding blanks,
    without that regex's backtracking (cubic on a long run of blanks inside the parentheses)."""
    m = _ADDRESS_OF.match(expr)
    if not m or not expr.endswith(")"):
        return expr
    inner = expr[m.end():-1].lstrip()
    nl = inner.find("\n")             # `.` stops at a newline; only blanks may follow it
    if nl < 0:
        return inner
    return expr if inner[nl:].strip() else inner[:nl]


def in_scope_addresses(manifest):
    found = set()

    def walk(v):
        if isinstance(v, str):
            found.update(a.lower() for a in ADDR.findall(v))
        elif isinstance(v, dict):
            for k, x in v.items():
                if k not in ("token",):   # collateral tokens (WETH, LSTs) are external, not in scope
                    walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk(manifest.get("deployed", {}))
    return found


def check(manifest, src):
    code, src_pos = _strip(src)
    scope = in_scope_addresses(manifest)
    findings = []
    statements = _statements(code)

    # identifiers bound to literal addresses, e.g. `IBoldToken constant BOLD = IBoldToken(0x...)`
    bound = {}
    for m in _bound(code):
        bound[m.group(1)] = m.group(2).lower()
    # identifiers created as fresh EOAs
    fresh = set(re.findall(r"\b(\w+)\s*=\s*makeAddr\s*\(", code))
    fresh |= set(re.findall(r"\(\s*address\s+(\w+)\s*,\s*uint256\s+\w+\s*\)\s*=\s*makeAddrAndKey", code))

    def resolve(expr):
        expr = _unwrap_address(expr.strip()).strip()
        if ADDR.fullmatch(expr):
            return "literal", expr.lower()
        if expr in fresh or expr in ("address(this)", "this"):
            return "fresh", expr
        if expr in bound:
            return "bound", bound[expr]
        return "unknown", expr

    # 1) forbidden cheatcodes
    for name in FORBIDDEN:
        for m in re.finditer(r"\bvm\s*\.\s*" + name + r"\s*\(", code):
            findings.append(("REJECT", f"forbidden cheatcode vm.{name}", m.start()))

    # 2) the fork must be the template's own: exactly one createSelectFork with the pinned block
    forks = [args for _, args in _calls(_FORK, statements, code)]
    pinned = str(manifest["chain"]["fork_block"])
    if len(forks) != 1:
        findings.append(("REJECT", f"expected exactly one vm.createSelectFork, found {len(forks)}", 0))
    elif "HYBLIS_ETH_RPC" not in forks[0] or not ("FORK_BLOCK" in forks[0] or pinned in forks[0]):
        findings.append(("REJECT", "fork must use HYBLIS_ETH_RPC at the pinned FORK_BLOCK", 0))
    m = re.search(r"FORK_BLOCK\s*=\s*(\d+)", code)
    if m and m.group(1) != pinned:
        findings.append(("REJECT", f"FORK_BLOCK {m.group(1)} differs from pinned {pinned}", m.start()))

    # 3) env access other than the RPC variable
    for m in re.finditer(r"vm\s*\.\s*env\w*\s*\(\s*\"([^\"]*)\"", code):
        if m.group(1) != "HYBLIS_ETH_RPC":
            findings.append(("REJECT", f"reads environment variable {m.group(1)}", m.start()))

    # 4) impersonation
    for m, args in _calls(_PRANK, statements, code):
        target = args.split(",")[0]
        kind, val = resolve(target)
        if kind == "fresh":
            continue
        if kind in ("literal", "bound") and val in scope:
            findings.append(("REJECT", f"impersonates in-scope protocol contract {val}", m.start()))
        else:
            findings.append(("FLAG", f"impersonates non-fresh account {target.strip()} (justify: e.g. a public whale)", m.start()))

    # 5) balance manipulation: vm.deal (ETH) and forge-std deal(token, to, amt)
    for m, args in _calls(_VM_DEAL, statements, code):
        kind, val = resolve(args.split(",")[0])
        if kind in ("literal", "bound") and val in scope:
            findings.append(("REJECT", f"vm.deal to in-scope contract {val}", m.start()))
        else:
            findings.append(("FLAG", "gives ETH with vm.deal (justify attacker capital)", m.start()))
    for m, args in _calls(_DEAL, statements, code):
        args = [a.strip() for a in args.split(",")]
        if len(args) >= 3:
            tkind, tval = resolve(args[0])
            hkind, hval = resolve(args[1])
            if (tkind in ("literal", "bound") and tval in scope) or (hkind in ("literal", "bound") and hval in scope):
                findings.append(("REJECT", "deal() on an in-scope token or holder rewrites protocol state", m.start()))
            else:
                findings.append(("FLAG", f"deal() of external token {args[0]} (justify attacker capital)", m.start()))
        else:
            findings.append(("FLAG", "deal() call (justify attacker capital)", m.start()))

    # 6) other environment changes a reviewer should see
    for name in ("warp", "roll", "fee", "coinbase", "prevrandao", "txGasPrice"):
        for m in re.finditer(r"\bvm\s*\.\s*" + name + r"\s*\(", code):
            findings.append(("FLAG", f"vm.{name} changes block/tx context (justify)", m.start()))

    # 7) forge-std helpers that hide cheatcodes
    for m in re.finditer(r"\bstdstore\b|\bStdStorage\b|\bstdStorage\b", code):
        findings.append(("REJECT", "forge-std StdStorage writes contract storage (hidden vm.store)", m.start()))
    for m in re.finditer(r"(?<![\w.])deployCodeTo\s*\(", code):
        findings.append(("REJECT", "deployCodeTo replaces code at an address (hidden vm.etch)", m.start()))
    for m, args in _calls(_HOAX, statements, code):
        kind, val = resolve(args.split(",")[0])
        if kind in ("literal", "bound") and val in scope:
            findings.append(("REJECT", f"{m.group(1)} impersonates in-scope protocol contract {val}", m.start()))
        elif kind != "fresh":
            findings.append(("FLAG", f"{m.group(1)} impersonates non-fresh account (justify)", m.start()))
        elif m.group(1) in ("hoax", "startHoax"):
            findings.append(("FLAG", f"{m.group(1)} gives ETH to the attacker (justify attacker capital)", m.start()))
    for m in re.finditer(r"(?<![\w.])(skip|rewind)\s*\(", code):
        findings.append(("FLAG", f"{m.group(1)}() changes block time (justify)", m.start()))

    # 8) inline assembly in the PoC is unusual and worth a look
    if re.search(r"\bassembly\s*\{", code):
        findings.append(("FLAG", "inline assembly in PoC", 0))

    verdict = "PASS"
    if any(f[0] == "FLAG" for f in findings):
        verdict = "FLAG"
    if any(f[0] == "REJECT" for f in findings):
        verdict = "REJECT"
    newlines = [m.start() for m in re.finditer("\n", src)]
    return verdict, [{"level": f[0], "reason": f[1], "line": bisect.bisect_left(newlines, src_pos(f[2])) + 1}
                     for f in findings]


def main():
    with open(sys.argv[1], encoding="utf-8") as f:
        manifest = json.load(f)
    if sys.argv[2] == "-":
        src = sys.stdin.buffer.read().decode("utf-8")
    else:
        with open(sys.argv[2], encoding="utf-8", newline="") as f:   # the text exactly as written
            src = f.read()
    verdict, findings = check(manifest, src)
    print(json.dumps({"verdict": verdict, "findings": findings}, indent=1))
    sys.exit({"PASS": 0, "FLAG": 1, "REJECT": 2}[verdict])


if __name__ == "__main__":
    main()
