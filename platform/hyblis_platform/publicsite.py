"""Public site server (port 9851). Pure read-only: serves the static front-end
and the public JSON files that the gateway exports (publish.export_all). It
never opens the private DB and never exports anything itself, so the community
site has no access to submission content; a file that has not been exported
yet is answered with 503.

The front-end is a single page (platform/site/index.html) with hash routes. It
reads /data/*.json from here and calls the gateway (config.public_api_base())
only to submit a signed report, to look up a submission's public status, and
to fetch the submitter's own receipt by its secret token. Each released, ready
program's `hyblis check` bundle is served from /data/check/<id>.tar.gz.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from urllib.parse import urlsplit

from aiohttp import web, web_fileresponse

from . import config, edge, publish

# aiohttp keeps its own content-type table for static files
if hasattr(web_fileresponse, "CONTENT_TYPES"):
    web_fileresponse.CONTENT_TYPES.add_type("font/woff2", ".woff2")

ROUTES = web.RouteTableDef()
_DATA_FILES = ("leaderboard", "ledger", "tasks", "summary", "scoring-policy")


def _api_base(request: web.Request) -> str:
    """Where this visitor's browser reaches the gateway (config.public_api_base), by the
    Host the request was sent to. A request relayed by a proxy or the Cloudflare Tunnel (it carries
    X-Real-IP, CF-Connecting-IP, X-Forwarded-For, Forwarded or the configured client-address header)
    comes from a browser elsewhere, whatever Host it has."""
    host = None
    relayed = ("X-Real-IP", "CF-Connecting-IP", "X-Forwarded-For", "Forwarded", config.client_ip_header())
    if not any(h in request.headers for h in relayed):
        try:
            host = urlsplit("//" + request.headers.get("Host", "")).hostname
        except ValueError:
            pass
    return config.public_api_base(host)


def _csp(request: web.Request) -> str:
    api = _api_base(request)
    connect = "'self'"
    if api:
        u = urlsplit(api)
        if u.scheme and u.netloc:
            connect += f" {u.scheme}://{u.netloc}"
    return ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; "
            f"connect-src {connect}; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")


@web.middleware
async def security_headers(request: web.Request, handler):
    try:
        resp = await handler(request)
    except web.HTTPException as ex:
        resp = ex
    resp.headers.setdefault("Content-Security-Policy", _csp(request))
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if isinstance(resp, web.HTTPException):
        raise resp
    return resp


async def cache_headers(request: web.Request, resp: web.StreamResponse) -> None:
    """Set just before the headers go out, when the status is final (a static file
    response only finds out that the file is missing at that point)."""
    if request.path.startswith("/assets/fonts/") or request.path.startswith("/assets/vendor/"):
        # cached for a week only when served: a missing file must not stay missing in caches
        resp.headers["Cache-Control"] = "public, max-age=604800" if resp.status < 400 else "no-store"
    elif request.path.startswith("/assets/") or request.path == "/":
        resp.headers["Cache-Control"] = "no-cache"


def _json_file(path) -> web.Response:
    # read in one go: the exporter replaces files whole, so this is never a partial file
    return web.Response(text=path.read_text(), content_type="application/json",
                        headers={"Cache-Control": "no-store"})


@ROUTES.get("/data/{name}.json")
async def data(req):
    name = req.match_info["name"]
    if name not in _DATA_FILES:
        raise web.HTTPNotFound()
    try:
        return _json_file(config.PUBLIC_DIR / f"{name}.json")
    except FileNotFoundError:     # the gateway has not exported yet
        return web.json_response({"error": "not published yet"}, status=503, headers={"Cache-Control": "no-store"})


@ROUTES.get("/data/programs/{task_id}.json")
async def program(req):
    task_id = req.match_info["task_id"]
    if not publish._TASK_ID_RE.match(task_id):
        raise web.HTTPNotFound()
    try:
        return _json_file(config.PUBLIC_DIR / "programs" / f"{task_id}.json")
    except FileNotFoundError:     # not a released program (or no longer one)
        raise web.HTTPNotFound()


@ROUTES.get("/data/check/{task_id}.tar.gz")
async def check_bundle(req):
    """The `hyblis check` bundle of a released, ready program (publish.check_bundle). Served only
    while that program's exported page lists it, so a program that is withdrawn or not released
    has none, whatever is left on disk."""
    task_id = req.match_info["task_id"]
    if not publish._TASK_ID_RE.match(task_id):
        raise web.HTTPNotFound()
    try:
        listed = json.loads((config.PUBLIC_DIR / "programs" / f"{task_id}.json").read_text()).get("check_tool")
        data = (config.PUBLIC_DIR / "check" / f"{task_id}.tar.gz").read_bytes()
    except (OSError, ValueError, AttributeError):
        raise web.HTTPNotFound()
    if not listed:
        raise web.HTTPNotFound()
    etag = '"' + hashlib.sha256(data).hexdigest()[:40] + '"'
    headers = {"Cache-Control": "no-cache", "ETag": etag,
               "Content-Disposition": f'attachment; filename="hyblis-check-{task_id}.tar.gz"'}
    if etag in [t.strip() for t in req.headers.get("If-None-Match", "").split(",")]:
        return web.Response(status=304, headers=headers)
    return web.Response(body=data, content_type="application/gzip", headers=headers)


_PRIVATE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{3,79}")


@ROUTES.get("/p/{token}")
async def private_page(req):
    """Private pages (scripts/deploy/investor_page.py, scripts/deploy/testnet_page.py): each one is
    run/private-pages/<name>.html, served only at /p/<name>, where <name> is the content of one of the
    *.token files there (plan.token, testnet.token). Nothing under /p/ is listed or linked; any other
    address answers exactly like an unknown page; names are compared in constant time."""
    token = req.match_info["token"]
    if os.environ.get("HYBLIS_PRIVATE_PAGES", "1") == "0" or not _PRIVATE_NAME.fullmatch(token):
        raise web.HTTPNotFound()          # e.g. the testnet site: private pages live on the main site only
    pages = config.RUN_DIR / "private-pages"
    match = None
    try:
        names = sorted(pages.glob("*.token"))
    except OSError:
        names = []
    for f in names:
        try:
            want = f.read_text().strip()
        except OSError:
            continue
        if want and hmac.compare_digest(token.encode(), want.encode()):
            match = want
    if not match:
        raise web.HTTPNotFound()
    try:
        body = (pages / f"{match}.html").read_text()
    except OSError:
        raise web.HTTPNotFound()
    return web.Response(text=body, content_type="text/html", headers={
        "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow, noarchive"})


@ROUTES.get("/config.json")
async def site_config(req):
    netuid = os.environ.get("HYBLIS_NETUID", "")
    return web.json_response({"api_base": _api_base(req), "demo": False, "network": config.network(),
                              "netuid": int(netuid) if netuid.isdigit() else None},
                             headers={"Cache-Control": "no-store"})


@ROUTES.get("/healthz")
async def healthz(req):
    return web.json_response({"ok": True})


_ASSET_REF = re.compile(r'((?:href|src)="assets/([^"?#]+\.(?:css|js)))"')
_ASSET_VER: dict = {}


def _asset_version(rel: str) -> str:
    """A short content hash of a site file, recomputed only when the file changes."""
    p = config.SITE_DIR / "assets" / rel
    try:
        st = p.stat()
    except OSError:
        return ""
    key = (st.st_mtime_ns, st.st_size)
    hit = _ASSET_VER.get(rel)
    if not hit or hit[0] != key:
        hit = (key, hashlib.sha256(p.read_bytes()).hexdigest()[:10])
        _ASSET_VER[rel] = hit
    return hit[1]


@ROUTES.get("/")
async def index(req):
    """The page, with every stylesheet and script address carrying its content hash (?v=...).
    Cloudflare tells browsers to keep /assets files for hours, so without this a browser could
    pair a new page with an old stylesheet; a changed file now gets a new address."""
    text = (config.SITE_DIR / "index.html").read_text()

    def tag(m):
        v = _asset_version(m.group(2))
        return f'{m.group(1)}?v={v}"' if v else m.group(0)
    return web.Response(text=_ASSET_REF.sub(tag, text), content_type="text/html")


def make_app() -> web.Application:
    config.check()
    app = web.Application(middlewares=[edge.https_only, security_headers])
    app.on_response_prepare.append(cache_headers)
    app.add_routes(ROUTES)
    # static assets (css, js, fonts, vendor) under /assets
    app.router.add_static("/assets/", config.SITE_DIR / "assets", show_index=False)
    return app


def main():
    web.run_app(make_app(), host=config.HOST, port=config.SITE_PORT, print=lambda *a: None)


if __name__ == "__main__":
    main()
