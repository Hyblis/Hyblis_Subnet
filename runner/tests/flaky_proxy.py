#!/usr/bin/env python3
"""TEST ONLY: a broken fork source, to prove the runner rejects runs that do not repeat.

Listens on a Unix socket and forwards every JSON-RPC message to the toy anvil's IPC socket, except that
eth_getStorageAt for one slot (alice's deposit in the toy vault) gets a different random answer every
time. A PoC that reads that slot cannot run the same way twice, so the runner must answer
"nondeterministic". Never used outside runner/tests.
Usage: flaky_proxy.py <listen.sock> <anvil.ipc>
"""
import json
import os
import random
import socket
import sys
import threading

from eth_utils import keccak

VAULT = "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0"
ALICE = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
SLOT = int.from_bytes(keccak(bytes.fromhex(ALICE[2:].rjust(64, "0") + "2".rjust(64, "0"))), "big")   # deposits[alice]


def _messages(sock):
    dec, buf = json.JSONDecoder(), ""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            return
        buf += chunk.decode()
        while True:
            buf = buf.lstrip()
            if not buf:
                break
            try:
                obj, end = dec.raw_decode(buf)
            except ValueError:
                break
            buf = buf[end:]
            yield obj


def _is_target(req) -> bool:
    if not isinstance(req, dict) or req.get("method") != "eth_getStorageAt":
        return False
    p = req.get("params") or []
    try:
        return p[0].lower() == VAULT and int(p[1], 16) == SLOT
    except (IndexError, ValueError, AttributeError):
        return False


def handle(client, upstream_path):
    up = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    up.connect(upstream_path)
    targets = set()
    lock = threading.Lock()

    def pump_up():
        try:
            for msg in _messages(client):
                for r in (msg if isinstance(msg, list) else [msg]):
                    if _is_target(r):
                        with lock:
                            targets.add(json.dumps(r.get("id")))
                up.sendall(json.dumps(msg).encode())
        except OSError:
            pass
        finally:
            try:
                up.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threading.Thread(target=pump_up, daemon=True).start()
    try:
        for msg in _messages(up):
            items = msg if isinstance(msg, list) else [msg]
            for r in items:
                with lock:
                    hit = json.dumps(r.get("id")) in targets
                if hit and "result" in r:
                    r["result"] = "0x" + (40 * 10**18 + random.randrange(10**18)).to_bytes(32, "big").hex()
            client.sendall(json.dumps(msg).encode())
    except OSError:
        pass
    finally:
        client.close()
        up.close()


def main():
    listen, upstream = sys.argv[1], sys.argv[2]
    if os.path.exists(listen):
        os.unlink(listen)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(listen)
    os.chmod(listen, 0o666)
    srv.listen(64)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c, upstream), daemon=True).start()


if __name__ == "__main__":
    main()
