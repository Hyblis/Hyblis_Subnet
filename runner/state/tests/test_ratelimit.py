"""Client rate-limit handling against a local HTTP stub (127.0.0.1, ephemeral port, no network)."""
import json
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from state.jsonrpc import Client, RateLimited, RpcError  # noqa: E402


class Stub(BaseHTTPRequestHandler):
    script: list = []          # per request: ("http429", retry_after) | ("rpc", code, message) | ("ok", result)
    seen = 0

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Stub.seen += 1
        step = Stub.script.pop(0) if Stub.script else ("ok", "0x1")
        if step[0] == "http429":
            self.send_response(429)
            if step[1] is not None:
                self.send_header("Retry-After", str(step[1]))
            self.end_headers()
            self.wfile.write(b'{"error":{"code":15,"message":"rate limit"}}')
            return
        if step[0] == "rpc":
            doc = {"jsonrpc": "2.0", "id": body["id"], "error": {"code": step[1], "message": step[2]}}
        else:
            doc = {"jsonrpc": "2.0", "id": body["id"], "result": step[1]}
        out = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class RateLimitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def run_script(self, script, **kw):
        Stub.script, Stub.seen = list(script), 0
        return Client(self.url, timeout=5, **kw)

    def test_http_429_is_ridden_out(self):
        c = self.run_script([("http429", None)] * 3 + [("ok", "0x2a")], rate_delays=(0, 0, 0, 0))
        self.assertEqual(c.call("eth_blockNumber", []), "0x2a")
        self.assertEqual((Stub.seen, c.rate_waits), (4, 3))

    def test_rpc_rate_limit_codes_and_message(self):
        c = self.run_script([("rpc", 15, "You reached Public endpoint rate limit"), ("rpc", -32005, "limit exceeded"),
                             ("rpc", -32000, "Rate limit exceeded, slow down"), ("ok", "0x1")], rate_delays=(0,) * 4)
        self.assertEqual(c.call("eth_chainId", []), "0x1")
        self.assertEqual(c.rate_waits, 3)

    def test_retry_after_is_honoured(self):
        c = self.run_script([("http429", 1), ("ok", "0x1")], rate_delays=(0,))
        t0 = time.time()
        c.call("eth_chainId", [])
        self.assertGreaterEqual(time.time() - t0, 0.9)

    def test_budget_is_finite(self):
        c = self.run_script([("http429", None)] * 5, rate_delays=(0, 0))
        with self.assertRaises(RateLimited):
            c.call("eth_chainId", [])
        self.assertEqual(Stub.seen, 3)

    def test_no_retries_means_no_waiting(self):
        c = self.run_script([("http429", None), ("ok", "0x1")], retries=0)
        with self.assertRaises(RateLimited):
            c.call("eth_chainId", [])
        self.assertEqual(Stub.seen, 1)

    def test_other_errors_unchanged(self):
        c = self.run_script([("rpc", 3, "execution reverted"), ("ok", "0x1")], rate_delays=(0,))
        with self.assertRaises(RpcError):
            c.call("eth_call", [])
        self.assertEqual((Stub.seen, c.rate_waits), (1, 0))


if __name__ == "__main__":
    unittest.main()
