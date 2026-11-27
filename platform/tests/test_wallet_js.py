"""Cross-language test: the browser code (site/assets/js/wallet.js, run under Node)
must produce byte-for-byte the same canonical JSON, the same sha256 and the same
submission id as the Python server, for awkward text as well as plain text.
If these ever differ, a browser-signed report would be refused by the gateway.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from bittensor_wallet import Keypair
from hyblis_platform import canonical, keys, models

ROOT = pathlib.Path(__file__).resolve().parents[2]
WALLET_JS = ROOT / "platform" / "site" / "assets" / "js" / "wallet.js"
node = shutil.which("node")
if not node:
    print("SKIP: node is not installed, cannot run the browser code")
    sys.exit(0)

kp = Keypair.create_from_uri("//BrowserWallet")
TRICKY = [
    "plain ascii",
    'quotes " and \' and backslash \\ and slash /',
    "newline\nreturn\rtab\tbackspace\bformfeed\f",
    "controls \x00\x01\x02\x1e\x1f and del \x7f",
    "line sep   para sep   nbsp   bom ﻿",
    "accents éàüñ ß · greek αβγ · cyrillic дж · cjk 漢字 · arabic مرحبا",
    "emoji 😀🚀 and flags 🇰🇷 and zwj 👩‍💻 and combining é",
    "astral 𝔘𝔫𝔦𝔠𝔬𝔡𝔢 \U0001F600 \U0010FFFF",
    "</script><script>alert(1)</script> &amp; <b>",
    "windows\r\nline\r\nendings",
    "x" * 3999,
]
POCS = [
    "// SPDX\ncontract X { function test_x() public {} }\n",
    "contract Y {\r\n  // crlf file\r\n  string s = \"é😀\";\r\n}\r\n",
    "a" * 55, "b" * 56, "c" * 63, "d" * 64, "e" * 65, "f" * 119, "g" * 120,
    "/* 200 KiB */ " + ("0123456789abcdef" * 12800),
]


def pkg(title, desc, poc, i):
    return {
        "v": 1, "task_id": "cap", "hotkey": kp.ss58_address, "nonce": f"{i:032x}", "ts": 1794800000 + i,
        "header": {"title": title[:160] or "t", "contract": "0x15622c3dbbc5614e6dfa9446603c1779647f01fc",
                   "function": "borrow", "severity": "medium", "description": desc[:4000] or "d"},
        "poc": poc, "poc_sha256": canonical.sha256_hex(poc.encode("utf-8")),
    }


packages = [pkg(t, t, POCS[i % len(POCS)], i) for i, t in enumerate(TRICKY)]
packages += [pkg("poc case", "poc case", p, 100 + i) for i, p in enumerate(POCS)]
vectors = ["", "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "é😀\n", "a" * 1000]

script = r"""
const fs = require('fs');
const w = require(process.argv[2]);
const inp = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const out = {
  canon: inp.packages.map((p) => Buffer.from(w.canonical(p), 'utf8').toString('hex')),
  ids: inp.packages.map((p) => w.submissionId(p)),
  poc: inp.packages.map((p) => w.sha256Hex(w.utf8(p.poc))),
  vec: inp.vectors.map((s) => w.sha256Hex(w.utf8(s))),
  built: inp.fields.map((f) => { const p = w.buildPackage(f); return { pkg: p, id: w.submissionId(p), msg: w.message(w.submissionId(p)) }; }),
  bad: (() => { try { w.canonical({ a: '\ud800' }); return 'accepted'; } catch (e) { return 'refused'; } })(),
  frac: (() => { try { w.canonical({ a: 1.5 }); return 'accepted'; } catch (e) { return 'refused'; } })(),
};
process.stdout.write(JSON.stringify(out));
"""
fields = [{"task_id": "cap", "hotkey": kp.ss58_address, "title": "  Rounding favours the caller  ",
           "contract": "0xCCCC62962D17B8914C62D74FFB843D73B2A3CCCC", "fn": " redeem ", "severity": "low",
           "description": " Shares round down.\nSecond line é😀 ", "poc": POCS[1], "nonce": "ab" * 16, "ts": int(time.time())}]

with tempfile.TemporaryDirectory() as d:
    d = pathlib.Path(d)
    (d / "in.json").write_text(json.dumps({"packages": packages, "vectors": vectors, "fields": fields}))
    (d / "run.js").write_text(script)
    res = subprocess.run([node, str(d / "run.js"), str(WALLET_JS), str(d / "in.json")], capture_output=True, text=True, timeout=120)
    if res.returncode != 0:
        print(res.stderr[-2000:])
        sys.exit("node run failed")
    out = json.loads(res.stdout)

for i, p in enumerate(packages):
    want = canonical.canonical_bytes(p).hex()
    assert out["canon"][i] == want, f"canonical JSON differs for package {i}: {p['header']['title'][:40]!r}"
    assert out["ids"][i] == models.submission_id(p), f"submission id differs for package {i}"
    assert out["poc"][i] == p["poc_sha256"], f"poc hash differs for package {i}"
print(f"ok canonical JSON, submission id and poc hash identical for {len(packages)} packages")

for s, got in zip(vectors, out["vec"]):
    assert got == canonical.sha256_hex(s.encode("utf-8")), f"sha256 differs for {s[:20]!r}"
print(f"ok sha256 matches hashlib for {len(vectors)} vectors")

assert out["bad"] == "refused" and out["frac"] == "refused"
print("ok browser refuses a lone surrogate and a non-integer number")

# a package built by the browser code is accepted by the server-side validation, and a
# wallet signature over the browser's message verifies on the server
b = out["built"][0]
models.validate_package(b["pkg"], {"cap"})
assert b["pkg"]["header"] == {"title": "Rounding favours the caller", "contract": "0xcccc62962d17b8914c62d74ffb843d73b2a3cccc",
                              "function": "redeem", "severity": "low", "description": "Shares round down.\nSecond line é😀"}
assert b["id"] == models.submission_id(b["pkg"])
assert b["msg"].encode() == keys.wallet_message(b["id"])
sig = "0x" + kp.sign(b"<Bytes>" + b["msg"].encode() + b"</Bytes>").hex()      # what a wallet extension returns
assert keys.verify_submission(kp.ss58_address, b["pkg"], sig, keys.SCHEME_WALLET, models.submission_id(b["pkg"]))
assert not keys.verify_submission(kp.ss58_address, b["pkg"], sig, keys.SCHEME_RAW, models.submission_id(b["pkg"]))
print("ok a browser-built package validates and its wallet signature verifies on the server")
print("ALL WALLET-JS TESTS PASS")
