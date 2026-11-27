"""edge.https_only: plain-http visits to the public hosts are redirected to https (301 for
GET/HEAD, 308 otherwise), answers for public hosts carry HSTS, and other hosts (local use) are
neither redirected nor given HSTS. Runs both apps in-process; no ports, no network."""
import asyncio, os, sys, tempfile, pathlib

import atexit, shutil  # noqa: E401
d = tempfile.mkdtemp()
atexit.register(shutil.rmtree, d, True)
os.environ.update(HYBLIS_DATA_DIR=d + "/data", HYBLIS_PUBLIC_DIR=d + "/public", HYBLIS_DISPATCH_TOKEN="t",
                  HYBLIS_CORS_ORIGINS="https://hyblis.com,https://www.hyblis.com")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402
from hyblis_platform import gateway, publicsite  # noqa: E402

HTTP, HTTPS = {"CF-Visitor": '{"scheme":"http"}'}, {"CF-Visitor": '{"scheme":"https"}'}
fails = 0


def check(name, ok):
    global fails
    print(("ok   " if ok else "FAIL ") + name)
    fails += 0 if ok else 1


async def main():
    for label, app in (("site", publicsite.make_app()), ("gateway", gateway.make_app())):
        async with TestClient(TestServer(app)) as c:
            path = "/config.json" if label == "site" else "/api/submission/0123456789abcdef"
            r = await c.get(path + "?a=1", headers={"Host": "hyblis.com", **HTTP}, allow_redirects=False)
            check(f"{label}: http GET -> 301 https", r.status == 301 and r.headers["Location"] == f"https://hyblis.com{path}?a=1")
            r = await c.get(path, headers={"Host": "www.hyblis.com:80", **HTTP}, allow_redirects=False)
            check(f"{label}: www keeps its host", r.status == 301 and r.headers["Location"] == f"https://www.hyblis.com{path}")
            r = await c.post("/api/submit", data=b"{}", headers={"Host": "hyblis.com", **HTTP}, allow_redirects=False)
            check(f"{label}: http POST -> 308", r.status == 308)
            r = await c.get(path, headers={"Host": "hyblis.com", **HTTPS}, allow_redirects=False)
            check(f"{label}: https answer has HSTS", r.status != 301 and "max-age=31536000" in r.headers.get("Strict-Transport-Security", ""))
            check(f"{label}: nosniff + no-referrer", r.headers.get("X-Content-Type-Options") == "nosniff" and r.headers.get("Referrer-Policy") == "no-referrer")
            r = await c.get(path, headers={"Host": "evil.example", **HTTP}, allow_redirects=False)
            check(f"{label}: other host never redirected", r.status != 301 and "Strict-Transport-Security" not in r.headers)
            r = await c.get(path, headers={"Host": "127.0.0.1:9851"}, allow_redirects=False)
            check(f"{label}: local use unchanged", r.status != 301 and "Strict-Transport-Security" not in r.headers)

asyncio.run(main())
print("edge: all passed" if not fails else f"edge: {fails} FAILED")
sys.exit(1 if fails else 0)
