#!/usr/bin/env python3
"""Compare deployed runtime bytecode with a Foundry artifact, ignoring the CBOR metadata tail and
immutable values. Prints MATCH / DIFFERENT with a similarity ratio.
Usage: compare_code.py <hex_code_file_or_0x...> <artifact.json>"""
import json, sys, difflib
def strip_meta(h):
    b = bytes.fromhex(h)
    if len(b) < 2: return b
    n = int.from_bytes(b[-2:], "big")
    return b[: -(n + 2)] if n + 2 <= len(b) else b
onchain = sys.argv[1]
if not onchain.startswith("0x"): onchain = open(onchain).read().strip()
import re
art = json.load(open(sys.argv[2]))["deployedBytecode"]
obj = re.sub(r"__\$[0-9a-fA-F]{34}\$__", "00" * 20, art["object"][2:])   # unlinked library placeholders
local = bytearray(strip_meta(obj))
chain = bytearray(strip_meta(onchain[2:]))
for libs in (art.get("linkReferences") or {}).values():          # mask linked library addresses
    for refs in libs.values():
        for r in refs:
            s, l = r["start"], r["length"]
            if s + l <= len(chain): chain[s:s+l] = b"\0" * l
for refs in (art.get("immutableReferences") or {}).values():
    for r in refs:
        s, l = r["start"], r["length"]
        if s + l <= len(local) and s + l <= len(chain):
            chain[s:s+l] = b"\0" * l; local[s:s+l] = b"\0" * l
if chain == local:
    print("MATCH"); sys.exit(0)
ratio = difflib.SequenceMatcher(None, chain.hex(), local.hex(), autojunk=False).quick_ratio()
print(f"DIFFERENT len_onchain={len(chain)} len_local={len(local)} similarity~{ratio:.3f}"); sys.exit(1)
