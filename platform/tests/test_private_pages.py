"""publicsite.private_page: every run/private-pages/*.token names one page, served only at /p/<name>
with noindex and no-store; any other /p/ address (wrong name, prefix, odd characters, a name file
that points outside the folder) answers exactly like an unknown page. In-process; no ports."""
import asyncio, atexit, os, shutil, sys, tempfile, pathlib

d = tempfile.mkdtemp()
atexit.register(shutil.rmtree, d, True)
os.environ.update(HYBLIS_DATA_DIR=d + "/data", HYBLIS_PUBLIC_DIR=d + "/public", HYBLIS_DISPATCH_TOKEN="t")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402
from hyblis_platform import config, publicsite  # noqa: E402

config.RUN_DIR = pathlib.Path(d) / "run"
pages = config.RUN_DIR / "private-pages"
pages.mkdir(parents=True)
(pages / "plan.token").write_text("investor-plan")
(pages / "investor-plan.html").write_text("<p>plan</p>")
(pages / "testnet.token").write_text("testnet-proof\n")
(pages / "testnet-proof.html").write_text("<p>proof</p>")
(pages / "evil.token").write_text("../../etc/passwd")          # never matches: not a valid name
fails = 0


def check(name, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + name)
    fails += 0 if ok else 1


async def main():
    async with TestClient(TestServer(publicsite.make_app())) as c:
        for name, body in (("investor-plan", "plan"), ("testnet-proof", "proof")):
            r = await c.get(f"/p/{name}")
            t = await r.text()
            check(f"/p/{name} served", r.status == 200 and body in t)
            check(f"/p/{name} noindex + no-store", "noindex" in r.headers.get("X-Robots-Tag", "")
                  and r.headers.get("Cache-Control") == "no-store")
        for bad in ("testnet", "testnet-proof-x", "investor", "TESTNET-PROOF", "x", "plan", "evil",
                    "..%2F..%2Fetc%2Fpasswd", "testnet-proof.html"):
            r = await c.get(f"/p/{bad}")
            check(f"/p/{bad} -> 404", r.status == 404)
        r = await c.get("/nope")
        check("an unknown page is the same 404", r.status == 404)

asyncio.run(main())
print("private pages: all passed" if not fails else f"private pages: {fails} FAILED")
sys.exit(1 if fails else 0)
