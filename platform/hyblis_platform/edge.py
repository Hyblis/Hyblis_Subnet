"""Rules for requests that arrive through Cloudflare (the Hyblis tunnel), shared by the gateway
and the public site. Both listen on 127.0.0.1 only, so every outside request reaches them through
cloudflared, which passes on Cloudflare's CF-Visitor header ({"scheme": "http"|"https"}).

  * A plain-http visit to a public host (config.public_hosts()) is redirected to https, so a page,
    a wallet signature or a report never travels unencrypted (301 for GET/HEAD, 308 otherwise,
    which keeps the method and body). Other hosts (local tests, 127.0.0.1) are left alone, so the
    redirect can never point anywhere but the site's own addresses.
  * Every answer for a public host carries HSTS, so browsers use https for a year without asking.
  * Every answer carries nosniff and no-referrer.
"""
from __future__ import annotations

import json

from aiohttp import web

from . import config

HSTS = "max-age=31536000; includeSubDomains"


def _host(request: web.Request) -> str:
    h = (request.headers.get("Host") or "").strip().lower()
    if h.startswith("["):                      # [v6]:port
        return h.split("]")[0] + "]"
    return h.split(":")[0]


def _visitor_scheme(request: web.Request) -> str | None:
    try:
        return json.loads(request.headers.get("CF-Visitor", "")).get("scheme")
    except (ValueError, AttributeError):
        return None


@web.middleware
async def https_only(request: web.Request, handler):
    host = _host(request)
    public = host in config.public_hosts()
    if public and _visitor_scheme(request) == "http":
        loc = f"https://{host}{request.rel_url}"
        if request.method in ("GET", "HEAD"):
            raise web.HTTPMovedPermanently(loc)
        raise web.HTTPPermanentRedirect(loc)
    try:
        resp = await handler(request)
    except web.HTTPException as ex:
        resp = ex
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if public:
        resp.headers.setdefault("Strict-Transport-Security", HSTS)
    if isinstance(resp, web.HTTPException):
        raise resp
    return resp
