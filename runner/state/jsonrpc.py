"""JSON-RPC plumbing for the state layer: stream framing, upstream clients, and a Unix-socket server.

* ``JsonStreamSplitter``: splits a byte stream into top-level JSON values. Foundry's IPC transport
  writes JSON values back to back (no delimiter), so framing is done by bracket depth.
* ``Client``: a small synchronous JSON-RPC client for an upstream given as an http(s) URL or a
  Unix-socket path. Used only on the operator side (collect, build, extend). Never on the runner.
* ``UnixRpcServer``: an asyncio server on a Unix socket running in a background thread. One process,
  any number of connections up to a cap, bounded buffers, request handling delegated to a handler
  object with ``handle_message(bytes) -> bytes | None``.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

USER_AGENT = "hyblis-state/1"


class FramingError(Exception):
    pass


class RpcError(Exception):
    """A JSON-RPC error object returned by the upstream."""

    def __init__(self, code, message, data=None):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.data = code, message, data


class TransportError(Exception):
    pass


class RateLimited(TransportError):
    """HTTP 429 from the upstream; `retry_after` is its Retry-After header in seconds, if it sent one."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


_OUTSIDE = re.compile(rb'["{}\[\]]')
_INSIDE = re.compile(rb'["\\]')
_MAX_DEPTH = 64


class JsonStreamSplitter:
    """Incremental splitter of a byte stream into complete top-level JSON objects/arrays."""

    def __init__(self, max_message: int = 4 << 20):
        self.max_message = max_message
        self.buf = bytearray()
        self.pos = 0          # scan position in buf
        self.depth = 0
        self.in_str = False
        self.esc = False
        self.start = -1       # start of the current top-level value

    def feed(self, data: bytes) -> list[bytes]:
        buf = self.buf
        buf += data
        out: list[bytes] = []
        i, n = self.pos, len(buf)
        depth, in_str, esc, start = self.depth, self.in_str, self.esc, self.start
        while i < n:
            if in_str:
                if esc:
                    esc = False
                    i += 1
                    continue
                m = _INSIDE.search(buf, i)
                if m is None:
                    i = n
                    break
                j = m.start()
                if buf[j] == 0x5C:
                    esc = True
                else:
                    in_str = False
                i = j + 1
                continue
            m = _OUTSIDE.search(buf, i)
            if m is None:
                if depth == 0 and bytes(buf[i:]).strip():
                    raise FramingError("data outside a JSON object")
                i = n
                break
            j = m.start()
            if depth == 0 and bytes(buf[i:j]).strip():
                raise FramingError("data outside a JSON object")
            c = buf[j]
            if c == 0x22:
                if depth == 0:
                    raise FramingError("top-level JSON string")
                in_str = True
            elif c == 0x7B or c == 0x5B:
                if depth == 0:
                    start = j
                depth += 1
                if depth > _MAX_DEPTH:
                    raise FramingError("JSON nested too deeply")
            else:
                depth -= 1
                if depth < 0:
                    raise FramingError("unbalanced JSON")
                if depth == 0:
                    out.append(bytes(buf[start:j + 1]))
                    start = -1
            i = j + 1
        # drop consumed bytes, keep the partial value (if any); at depth 0 everything was consumed
        if depth == 0:
            del buf[:]
            i, start = 0, -1
        else:
            del buf[:start]
            i -= start
            start = 0
        if len(buf) > self.max_message:
            raise FramingError(f"message larger than {self.max_message} bytes")
        self.pos, self.depth, self.in_str, self.esc, self.start = i, depth, in_str, esc, start
        return out


# ----------------------------------------------------------------------------------------------
# client (operator side only)
# ----------------------------------------------------------------------------------------------

def endpoint_label(endpoint: str) -> str:
    """What may be written into a manifest: the host of an http(s) URL (no path, key or query), or 'ipc'."""
    if endpoint.startswith(("http://", "https://")):
        return urllib.parse.urlparse(endpoint).hostname or "http"
    return "ipc"


class Client:
    """Synchronous JSON-RPC client. Thread-safe (one request at a time per instance)."""

    RETRY_HTTP = {429, 500, 502, 503, 504}
    RETRY_CODES = {429, -32005}
    # rate limits (HTTP 429, or a JSON-RPC error that says so: 429, -32005 "limit exceeded", 15 on drpc's
    # public endpoint) get their own, longer budget: a public endpoint throttles bursts for tens of seconds
    RATE_CODES = {429, -32005, 15}
    RATE_DELAYS = (1, 2, 4, 8, 15, 30, 30, 30, 30, 30, 30, 30)     # about 4 minutes in all

    def __init__(self, endpoint: str, timeout: float = 60.0, retries: int = 4, max_response: int = 256 << 20,
                 rate_delays: tuple | None = None):
        self.endpoint = endpoint
        self.timeout = timeout
        self.retries = retries
        self.rate_delays = self.RATE_DELAYS if rate_delays is None else tuple(rate_delays)
        self.rate_waits = 0
        self.max_response = max_response
        self.is_http = endpoint.startswith(("http://", "https://"))
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None
        self._split: JsonStreamSplitter | None = None
        self._id = 0
        self.calls = 0

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                finally:
                    self._sock = None

    @classmethod
    def is_rate_limit(cls, e: Exception) -> bool:
        if isinstance(e, RateLimited):
            return True
        return isinstance(e, RpcError) and (e.code in cls.RATE_CODES or "rate limit" in str(e).lower())

    def call(self, method: str, params: list):
        delay = 0.5
        attempt = rate = 0
        while True:
            try:
                return self._call_once(method, params)
            except (RpcError, TransportError) as e:
                if self.retries and self.is_rate_limit(e) and rate < len(self.rate_delays):
                    wait = self.rate_delays[rate]
                    if isinstance(e, RateLimited) and e.retry_after is not None:
                        wait = max(wait, min(e.retry_after, 60))
                    rate += 1
                    self.rate_waits += 1
                    time.sleep(wait)
                    continue
                if isinstance(e, RateLimited) or attempt >= self.retries:
                    raise
                attempt += 1
                if isinstance(e, RpcError) and e.code not in self.RETRY_CODES:
                    raise
                time.sleep(delay)
                delay *= 2

    def _call_once(self, method, params):
        with self._lock:
            self._id += 1
            self.calls += 1
            body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}).encode()
            raw = self._http(body) if self.is_http else self._ipc(body)
        try:
            d = json.loads(raw)
        except ValueError:
            raise TransportError(f"{method}: response is not JSON") from None
        if not isinstance(d, dict):
            raise TransportError(f"{method}: response is not an object")
        if d.get("error") is not None:
            err = d["error"] if isinstance(d["error"], dict) else {"code": None, "message": str(d["error"])}
            raise RpcError(err.get("code"), str(err.get("message", ""))[:500], err.get("data"))
        if "result" not in d:
            raise TransportError(f"{method}: response has no result")
        return d["result"]

    def _http(self, body: bytes) -> bytes:
        req = urllib.request.Request(self.endpoint, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = r.read(self.max_response + 1)
        except urllib.error.HTTPError as e:
            payload = e.read(4096)
            if e.code == 429:
                ra = (e.headers or {}).get("Retry-After") if hasattr(e, "headers") else None
                raise RateLimited("HTTP 429", float(ra) if ra and str(ra).strip().isdigit() else None) from None
            if e.code in self.RETRY_HTTP:
                raise TransportError(f"HTTP {e.code}") from None
            try:  # many providers return a JSON-RPC error body with HTTP 400
                d = json.loads(payload)
                if isinstance(d, dict) and isinstance(d.get("error"), dict):
                    return payload
            except ValueError:
                pass
            raise TransportError(f"HTTP {e.code}: {payload[:200]!r}") from None
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise TransportError(f"{type(e).__name__}: {e}") from None
        if len(data) > self.max_response:
            raise TransportError("response too large")
        return data

    def _ipc(self, body: bytes) -> bytes:
        try:
            if self._sock is None:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect(self.endpoint)
                self._sock, self._split = s, JsonStreamSplitter(self.max_response)
            self._sock.sendall(body)
            while True:
                chunk = self._sock.recv(1 << 20)
                if not chunk:
                    raise TransportError("upstream closed the connection")
                msgs = self._split.feed(chunk)
                if msgs:
                    if len(msgs) > 1:
                        raise TransportError("unexpected extra messages from upstream")
                    return msgs[0]
        except (OSError, FramingError) as e:
            if self._sock is not None:
                self._sock.close()
            self._sock = None
            raise TransportError(f"ipc: {e}") from None


# ----------------------------------------------------------------------------------------------
# server
# ----------------------------------------------------------------------------------------------

class UnixRpcServer:
    """Serve ``handler.handle_message(bytes) -> bytes | None`` on a Unix socket from a background thread.

    blocking=True runs the handler in a single worker thread (for handlers that call an upstream),
    so the event loop keeps accepting connections; ordering per connection is preserved.
    """

    def __init__(self, socket_path: str, handler, *, max_connections: int = 64,
                 max_message: int = 4 << 20, blocking: bool = False, socket_mode: int = 0o660):
        self.socket_path = os.path.abspath(socket_path)
        self.handler = handler
        self.max_connections = max_connections
        self.max_message = max_message
        self.blocking = blocking
        self.socket_mode = socket_mode
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self._open = 0
        self._executor = ThreadPoolExecutor(max_workers=1) if blocking else None
        self.conn_total = 0
        self.conn_rejected = 0
        self.framing_errors = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self._closed = False

    # -- lifecycle --
    def start(self) -> "UnixRpcServer":
        _prepare_socket_path(self.socket_path)
        self._thread = threading.Thread(target=self._run, name="hyblis-rpc-server", daemon=True)
        self._thread.start()
        self._ready.wait(30)
        if self._error is not None:
            raise self._error
        if not self._ready.is_set():
            raise RuntimeError("server did not start")
        return self

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._loop is not None and self._loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop)
            try:
                fut.result(10)
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(10)
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
        try:
            if stat.S_ISSOCK(os.lstat(self.socket_path).st_mode):
                os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    @property
    def open_connections(self) -> int:
        return self._open

    # -- internals --
    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            self._server = loop.run_until_complete(
                asyncio.start_unix_server(self._client, path=self.socket_path, limit=1 << 16))
            os.chmod(self.socket_path, self.socket_mode)
        except BaseException as e:  # report to start()
            self._error = e
            self._ready.set()
            loop.close()
            return
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            loop.close()

    async def _shutdown(self) -> None:
        if self._server is not None:
            self._server.close()  # stop accepting; do not wait for idle clients
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.wait(tasks, timeout=5)
        asyncio.get_running_loop().call_soon(asyncio.get_running_loop().stop)

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.conn_total += 1
        if self._open >= self.max_connections:
            self.conn_rejected += 1
            writer.close()
            return
        self._open += 1
        split = JsonStreamSplitter(self.max_message)
        loop = asyncio.get_running_loop()
        try:
            while True:
                data = await reader.read(1 << 16)
                if not data:
                    break
                self.bytes_in += len(data)
                try:
                    msgs = split.feed(data)
                except FramingError as e:
                    self.framing_errors += 1
                    err = json.dumps({"jsonrpc": "2.0", "id": None,
                                      "error": {"code": -32700, "message": f"parse error: {e}"}}).encode()
                    writer.write(err + b"\n")
                    await writer.drain()
                    break
                for m in msgs:
                    if self._executor is not None:
                        resp = await loop.run_in_executor(self._executor, self.handler.handle_message, m)
                    else:
                        resp = self.handler.handle_message(m)
                    if resp is not None:
                        self.bytes_out += len(resp) + 1
                        writer.write(resp + b"\n")
                        await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            self._open -= 1
            try:
                writer.close()
            except Exception:
                pass


def _prepare_socket_path(path: str) -> None:
    """Refuse to clobber anything but a stale socket of ours."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        d = os.path.dirname(path)
        if not os.path.isdir(d):
            raise FileNotFoundError(f"socket directory does not exist: {d}")
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise FileExistsError(f"{path} exists and is not a socket")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(1)
        s.connect(path)
    except OSError:
        os.unlink(path)  # stale socket: nobody listens
        return
    finally:
        s.close()
    raise FileExistsError(f"{path} is in use by another server")
