"""Miner gateway + public API + internal runner endpoints (aiohttp).

Binds to 127.0.0.1 only. The public API serves the exported leaderboard/ledger.
The miner API accepts signed submissions, from the command-line miner (raw
scheme) or from a browser wallet (wallet-v1 scheme; see keys.py). The site is a
different origin, so /api/* answers CORS for the configured site origins only.
The internal API (shared-token auth)
is how the *separate* runner machine pulls jobs and posts verdicts; no PoC is
executed in this process (the static policy screen runs runner/policy_check.py
as a separate process with a time limit; see pipeline.screen).
"""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import secrets
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from aiohttp import web

from . import config, keys, models, pipeline, publish, store, edge

ROUTES = web.RouteTableDef()
MAX_BODY = 1024 * 1024          # 1 MiB
_CORS_HEADERS = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "600",
    "Vary": "Origin",
}
log = logging.getLogger("hyblis.gateway")


def _log_error(where: str, ex: BaseException) -> None:
    """One log line (no traceback): what failed, the exception type and its message."""
    def flat(s, n):
        return " ".join(str(s).split())[:n]
    log.warning("%s: %s: %s", flat(where, 200), type(ex).__name__, flat(ex, 300))


@web.middleware
async def cors_middleware(request: web.Request, handler):
    """Let the Hyblis site (a different origin) call the public and miner API from
    a browser. Only /api/* and only the configured origins; /internal/* never gets
    these headers, so a web page cannot reach the runner endpoints."""
    origin = request.headers.get("Origin", "")
    is_api = request.path.startswith("/api/")
    allowed = is_api and origin in config.cors_origins()

    def stamp(resp):
        if allowed:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers.update(_CORS_HEADERS)
        return resp

    if request.method == "OPTIONS" and is_api:
        return stamp(web.Response(status=204 if allowed else 403))
    try:
        resp = await handler(request)
    except web.HTTPException as ex:
        if is_api and ex.status >= 400:
            # API errors are JSON, so the site and the CLI can show the reason
            return stamp(web.json_response({"error": ex.reason}, status=ex.status))
        raise
    except Exception as ex:
        if not is_api:
            raise
        # an unexpected error: one log line, and still an answer the site can read
        _log_error(f"{request.method} {request.path}", ex)
        return stamp(web.json_response({"error": "internal error"}, status=500))
    return stamp(resp)


async def _run(func, *a, **k):
    return await asyncio.get_running_loop().run_in_executor(None, partial(func, *a, **k))


# Screens wait for their turn here (pipeline allows two at once), not in the shared pool
# that every other request uses.
_SCREENS = ThreadPoolExecutor(max_workers=2, thread_name_prefix="screen")


async def _screen(sid: str) -> str:
    return await asyncio.get_running_loop().run_in_executor(_SCREENS, pipeline.screen, sid)


def _known_tasks() -> set[str]:
    # Only released + ready tasks accept submissions (publish.ready_task_ids), so a
    # scaffolded task like aave-v4 (ready=false) is refused until its verification pass.
    return publish.ready_task_ids()


# ---- simple in-memory rate limit (per client key), bounded memory ----------
_BUCKET: dict[str, list[float]] = {}
_LAST_SWEEP = [0.0]
_MAX_KEYS = 100_000
_WINDOW = 3600.0


def _sweep(now: float) -> None:
    for k in list(_BUCKET):
        q = _BUCKET[k]
        while q and q[0] < now - _WINDOW:
            q.pop(0)
        if not q:
            del _BUCKET[k]


def _rate_ok(key: str, limit: int, window: float) -> bool:
    now = time.time()
    if now - _LAST_SWEEP[0] > 60:          # evict expired keys so the dict cannot grow without bound
        _LAST_SWEEP[0] = now
        _sweep(now)
    if key not in _BUCKET and len(_BUCKET) >= _MAX_KEYS:
        _sweep(now)
        if len(_BUCKET) >= _MAX_KEYS:      # still full of active keys -> shed new ones (likely a flood)
            return False
    q = _BUCKET.setdefault(key, [])
    while q and q[0] < now - window:
        q.pop(0)
    if len(q) >= limit:
        return False
    q.append(now)
    return True


def _rate_refund(key: str) -> None:
    """Take back the last charge on `key` (a request that turned out to need no quota)."""
    q = _BUCKET.get(key)
    if q:
        q.pop()


def _ip(value):
    """An IP address object, IPv4-mapped IPv6 as plain IPv4; None if `value` is not one."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _client_ip(req: web.Request) -> str:
    """The client address the per-address limit counts. Behind the reverse proxy or the
    Cloudflare Tunnel (runbook section J) every request comes from that proxy, which names the
    client in a header: config.client_ip_header(), X-Real-IP by default, CF-Connecting-IP behind
    Cloudflare. That header is used only when the request comes from a trusted proxy
    (config.trusted_proxies()), since any other client could send any value, and only when it
    holds one valid address. IPv6 clients are counted per /64, the block a single host usually holds."""
    ip = _ip(req.remote)
    if ip is not None and ip in config.trusted_proxies():
        real = _ip(req.headers.get(config.client_ip_header(), "").strip())
        if real is not None:
            ip = real
    if ip is None:
        return req.remote or "?"
    if ip.version == 6:
        return str(ipaddress.IPv6Network((int(ip) >> 64 << 64, 64)))
    return str(ip)


def _auth_internal(req: web.Request) -> bool:
    try:
        want = config.dispatch_token()
    except RuntimeError:
        return False
    got = req.headers.get("X-Hyblis-Token", "")
    # compared as bytes: compare_digest refuses str with non-ASCII characters
    return hmac.compare_digest(got.encode("utf-8", "surrogatepass"), want.encode("utf-8", "surrogatepass"))


# ---- public ----------------------------------------------------------------
@ROUTES.get("/api/health")
async def health(req):
    return web.json_response({"ok": True, "version": "0.1.0", "t": round(time.time())})


def _serve_public(name: str):
    async def handler(req):
        p = config.PUBLIC_DIR / f"{name}.json"
        if p.exists():
            return web.Response(text=p.read_text(), content_type="application/json")
        data = await _run(publish.export_all)
        return web.json_response(data.get(name, {}))
    return handler


ROUTES.get("/api/leaderboard")(_serve_public("leaderboard"))
ROUTES.get("/api/ledger")(_serve_public("ledger"))
ROUTES.get("/api/tasks")(_serve_public("tasks"))
ROUTES.get("/api/summary")(_serve_public("summary"))


@ROUTES.get("/api/program/{task_id}")
async def program_public(req):
    task_id = req.match_info["task_id"]
    if not publish._TASK_ID_RE.match(task_id):
        raise web.HTTPNotFound()
    try:
        text = (config.PUBLIC_DIR / "programs" / f"{task_id}.json").read_text()
    except FileNotFoundError:
        raise web.HTTPNotFound()
    return web.Response(text=text, content_type="application/json")


@ROUTES.get("/api/submission/{sid}")
async def submission_public(req):
    sid = req.match_info["sid"].lower()
    # full id, or an unambiguous hex prefix of at least 12 characters
    sub = await _run(store.get, sid) or await _run(store.find_by_prefix, sid)
    if not sub:
        raise web.HTTPNotFound()
    # the same fields as the public ledger row, nothing about the program
    return web.json_response({
        "hash": sub["submission_id"], "status": publish._PUBLIC_STATUS.get(sub["status"], "received"),
        "severity": sub["severity_final"] or sub["severity_claim"], "t": round(sub["received_at"]),
    })


# ---- miner -----------------------------------------------------------------
async def _replayed(sid: str) -> web.Response:
    """The receipt of a report that is already stored, for a resend of the same signed
    package (a retry after a lost response, or two copies sent at once). Only the holder
    of the signed envelope gets here, and it gets the same token; nothing is stored or
    charged again."""
    sub = await _run(store.get, sid)
    rec = await _run(store.receipt_for, sid)
    if not sub or not rec:
        raise web.HTTPConflict(reason="duplicate submission (same nonce)")
    body = {
        "submission_id": sid, "received_at": round(rec["received_at"], 3),
        "status": publish._PUBLIC_STATUS.get(sub["status"], "received"),
        "poc_sha256": sub["poc_sha256"], "server_sig": rec["server_sig"],
        "receipt_token": rec["token"], "replayed": True,
    }
    reasons = pipeline.policy_reasons(sub)
    if reasons is not None:
        body["policy"] = reasons
    return web.json_response(body, status=200)


@ROUTES.post("/api/submit")
async def submit(req):
    # Before mainnet launch the site is public but intake is closed: refused before any other work
    # (nothing is read, checked, charged or stored), with the line the site shows.
    launch = await _run(publish.launch_info)
    if not launch["intake_open"]:
        return web.json_response({"error": launch["message"]}, status=403)
    if req.content_length and req.content_length > MAX_BODY:
        raise web.HTTPRequestEntityTooLarge(max_size=MAX_BODY, actual_size=req.content_length)
    if req.content_type != "application/json":
        # A page on another site can POST text/plain without a CORS preflight; JSON forces
        # one, which only the configured site origins pass.
        raise web.HTTPUnsupportedMediaType(reason="send the report as Content-Type: application/json")
    peer = _client_ip(req)
    try:
        body = await req.json()
    except web.HTTPException:     # 413 for a body over MAX_BODY sent without a Content-Length
        raise
    except Exception:
        raise web.HTTPBadRequest(reason="invalid JSON")
    if not isinstance(body, dict):
        raise web.HTTPBadRequest(reason="expected a JSON object")
    pkg, sig = body.get("package"), body.get("sig")
    scheme = body.get("sig_scheme", keys.SCHEME_RAW)
    if not isinstance(pkg, dict) or not isinstance(sig, str) or len(sig) > 300:
        raise web.HTTPBadRequest(reason="expected {package, sig}")
    if scheme not in keys.SIG_SCHEMES:
        raise web.HTTPBadRequest(reason=f"sig_scheme must be one of {list(keys.SIG_SCHEMES)}")

    try:
        models.validate_package(pkg, await _run(_known_tasks))
    except models.ValidationError as e:
        raise web.HTTPBadRequest(reason=f"package: {e}")

    if abs(int(time.time()) - pkg["ts"]) > 86400:        # integers: ts is bounded by validate_package
        raise web.HTTPBadRequest(reason="ts too far from server time")
    prog = await _run(publish.program_public, pkg["task_id"]) or {}
    scope = prog.get("severity_scope") or []
    if scope and pkg["header"]["severity"] not in scope:
        raise web.HTTPBadRequest(reason=f"severity must be one of {scope} for this program")
    # The header's contract is part of the dedup fingerprint, so it must be one the program lists.
    assets = {a["address"].lower() for a in prog.get("assets") or []}
    if not assets:
        raise web.HTTPBadRequest(reason="this program has no contracts in scope yet, so it cannot take reports")
    if pkg["header"]["contract"].lower() not in assets:
        raise web.HTTPBadRequest(reason="contract is not in scope for this program")
    # Per-IP limit bounds work BEFORE the (costly) signature check. The per-hotkey
    # limit is charged only AFTER a valid signature, so a forged request with a
    # victim's public hotkey cannot consume the victim's quota.
    if not _rate_ok(f"ip:{peer}", 60, 3600):
        raise web.HTTPTooManyRequests(reason="rate limit")
    sid = models.submission_id(pkg)        # always the server's own hash of the package
    claimed = body.get("submission_id")
    if claimed is not None and claimed != sid:
        # The client hashed a different encoding than we did: say so plainly,
        # because the signature check below could only fail confusingly.
        raise web.HTTPBadRequest(reason="submission_id does not match the package (canonical encoding differs)")
    if not keys.verify_submission(pkg["hotkey"], pkg, sig, scheme, sid):
        raise web.HTTPUnauthorized(reason="signature does not verify for hotkey")
    if await _run(store.get, sid):
        return await _replayed(sid)        # the same signed package again
    if not _rate_ok(f"hk:{pkg['hotkey']}", limit=20, window=3600):
        raise web.HTTPTooManyRequests(reason="rate limit")

    received_at = time.time()
    payload = models.Receipt(sid, pkg["poc_sha256"], received_at, pkg["task_id"], pkg["hotkey"]).signing_payload()
    server_sig = None
    try:
        seed = config.server_seed()
        if seed:
            server_sig = keys.sign(keys.keypair_from_seed(seed), payload)
    except Exception as e:                 # e.g. a malformed HYBLIS_SERVER_SEED: the receipt goes unsigned
        _log_error("receipt signing", e)
    # Secret token so the miner (and only the miner) can re-fetch this receipt later.
    token = secrets.token_urlsafe(24)
    try:
        await _run(store.add_submission, pkg, sig, received_at, sid, scheme,
                   (token, json.dumps(payload, separators=(",", ":"), sort_keys=True), server_sig))
    except sqlite3.IntegrityError:
        # an identical copy arrived at the same moment and was stored first
        _rate_refund(f"hk:{pkg['hotkey']}")
        return await _replayed(sid)

    # The report and its receipt are stored: from here on a failure is logged, and the
    # submitter still gets the receipt.
    status = config.STATUS_RECEIVED
    try:
        status = await _screen(sid)
    except Exception as e:
        _log_error("screen", e)
        try:
            status = await _run(pipeline.queue_unscreened, sid)
        except Exception as e2:
            _log_error("screen fallback", e2)
    reasons = None
    if status == config.STATUS_REJECTED:
        try:
            reasons = pipeline.policy_reasons(await _run(store.get, sid))
        except Exception as e:
            _log_error("policy reasons", e)
    try:
        await _run(publish.export_all)
    except Exception as e:
        _log_error("export", e)
    out = {
        "submission_id": sid, "received_at": round(received_at, 3), "status": status,
        "server_sig": server_sig, "poc_sha256": pkg["poc_sha256"],
        "receipt_token": token,   # keep this secret; it is how you re-fetch your receipt
    }
    if reasons is not None:
        out["policy"] = reasons   # why the intake screen rejected it (the submitter's own PoC)
    return web.json_response(out, status=201)


@ROUTES.get("/api/receipt/{token}")
async def receipt(req):
    # Retrieval is by the SECRET token from the submit response, never by the
    # public submission_id, so walking the ledger cannot de-anonymize entries.
    token = req.match_info["token"]
    rec = await _run(store.receipt_by_token, token)
    if not rec:
        raise web.HTTPNotFound()
    # The outcome of a decided report (pipeline.researcher_result): why the runner rejected it, or what
    # it measured. Only here, behind the token the submitter holds; the public status stays as it was.
    sid = (rec.get("payload") or {}).get("submission_id")
    sub = await _run(store.get, sid) if isinstance(sid, str) else None
    rec["result"] = pipeline.researcher_result(sub) if sub else None
    return web.json_response(rec, headers={"Cache-Control": "no-store"})


# ---- internal (runner machine only) ----------------------------------------
@ROUTES.post("/internal/claim")
async def claim(req):
    if not _auth_internal(req):
        raise web.HTTPUnauthorized()
    job = await _run(pipeline.claim_for_runner)
    return web.json_response(job or {})


@ROUTES.post("/internal/verdict")
async def verdict(req):
    if not _auth_internal(req):
        raise web.HTTPUnauthorized()
    body = await req.json()
    sid, v = body.get("submission_id"), body.get("verdict")
    if not isinstance(sid, str) or not isinstance(v, dict):
        raise web.HTTPBadRequest(reason="expected {submission_id, verdict}")
    status = await _run(pipeline.on_verdict, sid, v)
    await _run(publish.export_all)
    return web.json_response({"submission_id": sid, "status": status})


def make_app() -> web.Application:
    config.check()
    store.init_db()
    config.ensure_dirs()
    publish.export_all()
    app = web.Application(client_max_size=MAX_BODY, middlewares=[edge.https_only, cors_middleware])
    app.add_routes(ROUTES)
    return app


def main():
    app = make_app()
    web.run_app(app, host=config.HOST, port=config.GATEWAY_PORT, print=lambda *a: None)


if __name__ == "__main__":
    main()
