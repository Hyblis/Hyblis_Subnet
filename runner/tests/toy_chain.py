#!/usr/bin/env python3
"""Local toy chain for the runner tests: anvil over IPC with the toy protocol deployed.

Everything runs as the unprivileged user (pinc): when the tests run as root, anvil, forge and cast are
started through setpriv. anvil listens on its IPC socket and, because anvil always opens an HTTP port
too, on 127.0.0.1:9866 or 9867 (whichever is free; nothing else is ever used). It is stopped by its
own PID at the end. No network, no mainnet, no public RPC.
"""
from __future__ import annotations

import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUNNER = HERE.parent
ROOT = RUNNER.parent
FOUNDRY_BIN = Path(os.environ.get("HYBLIS_ROOT", str(ROOT))) / "tools" / "foundry" / "bin"
# forge-std 1.15.0 (git clone --depth 1 -b v1.15.0 https://github.com/foundry-rs/forge-std tools/forge-std)
FORGE_STD = Path(os.environ.get("HYBLIS_FORGE_STD", str(ROOT / "tools" / "forge-std")))
USER = os.environ.get("HYBLIS_TEST_USER", "pinc")
PORTS = (9866, 9867)
FORK_BLOCK = 40
EXPECTED = {
    "Token": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
    "VaultImpl": "0xe7f1725e7734ce288f8367e1bb143e90bb3f0512",
    "Proxy": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
    "Existing": "0xdc64a140aa3e981100a9beca4e685f962f0cf6c9",
    "TxGuardVault": "0x5fc8d32690cc91d4c39d9d3abcbd16989f875707",
    "Feed": "0x0165878a594ca255338adfa4d48449f69242eb8f",
    "Lender": "0xa513e6e4b8f2a923d98304ec87f64353c4d5c853",
}


def as_user(cmd: list[str]) -> list[str]:
    if os.geteuid() == 0:
        return ["setpriv", f"--reuid={USER}", f"--regid={USER}", "--init-groups", "--", *cmd]
    return cmd


def user_env(home: Path) -> dict:
    return {"PATH": f"{FOUNDRY_BIN}:/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8", "NO_COLOR": "1",
            "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1"}


def chown(path: Path):
    if os.geteuid() != 0:
        return
    pw = pwd.getpwnam(USER)
    for dp, dns, fns in os.walk(path):
        os.chown(dp, pw.pw_uid, pw.pw_gid)
        for f in fns:
            os.chown(os.path.join(dp, f), pw.pw_uid, pw.pw_gid, follow_symlinks=False)


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


class ToyChain:
    def __init__(self, work: Path):
        self.work = work
        self.ipc = work / "anvil.ipc"
        self.home = work / "home"
        self.project = work / "toy"
        self.proc = None
        self.port = None

    def run(self, cmd, cwd=None, timeout=600, check=True) -> subprocess.CompletedProcess:
        full = as_user(["chrt", "--idle", "0", "nice", "-n", "19", *cmd])
        p = subprocess.run(full, cwd=cwd, env=user_env(self.home), capture_output=True, text=True, timeout=timeout)
        if check and p.returncode != 0:
            raise RuntimeError(f"{' '.join(cmd[:3])} failed: {p.stdout[-1500:]} {p.stderr[-1500:]}")
        return p

    def prepare_project(self):
        self.home.mkdir(parents=True, exist_ok=True)
        shutil.copytree(HERE / "toy", self.project, ignore=shutil.ignore_patterns("impact-spec.json", "manifest.json"))
        shutil.copytree(FORGE_STD, self.project / "lib" / "forge-std",
                        ignore=shutil.ignore_patterns(".git", ".github", "test"))
        solc = Path(os.environ.get("HYBLIS_ROOT", str(ROOT))) / ".home" / ".svm" / "0.8.28" / "solc-0.8.28"
        chown(self.work)
        self.run(["forge", "build", "--offline", "--use", str(solc)], cwd=self.project)

    def start(self):
        for port in PORTS:
            if port_free(port):
                self.port = port
                break
        if self.port is None:
            raise RuntimeError("ports 9866 and 9867 are both in use; refusing to pick another port")
        cmd = as_user(["chrt", "--idle", "0", "nice", "-n", "19", str(FOUNDRY_BIN / "anvil"), "--host", "127.0.0.1",
                       "--port", str(self.port), "--ipc", str(self.ipc), "--hardfork", "cancun", "--silent"])
        self.proc = subprocess.Popen(cmd, env=user_env(self.home), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     start_new_session=True)
        for _ in range(100):
            if self.ipc.exists():
                break
            time.sleep(0.1)
        else:
            self.stop()
            raise RuntimeError("anvil did not start")
        time.sleep(0.3)

    def deploy(self):
        solc = Path(os.environ.get("HYBLIS_ROOT", str(ROOT))) / ".home" / ".svm" / "0.8.28" / "solc-0.8.28"
        self.run(["forge", "script", "script/Deploy.s.sol", "--rpc-url", str(self.ipc), "--broadcast", "--slow",
                  "--offline", "--use", str(solc)], cwd=self.project)
        bc = json.loads((self.project / "broadcast" / "Deploy.s.sol" / "31337" / "run-latest.json").read_text())
        got = {t["contractName"]: t["contractAddress"].lower() for t in bc["transactions"] if t["transactionType"] == "CREATE"}
        if got != EXPECTED:
            raise RuntimeError(f"toy deployment addresses changed: {got}")
        n = self.block_number()
        self.run(["cast", "rpc", "anvil_mine", hex(FORK_BLOCK + 5 - n), "--rpc-url", str(self.ipc)])
        # the prepared project must not carry the deployment's broadcast or cache files
        shutil.rmtree(self.project / "broadcast", ignore_errors=True)

    def block_number(self) -> int:
        return int(self.run(["cast", "block-number", "--rpc-url", str(self.ipc)]).stdout.strip())

    def fork_header(self) -> dict:
        d = json.loads(self.run(["cast", "block", str(FORK_BLOCK), "--rpc-url", str(self.ipc), "--json"]).stdout)
        d = d.get("data", d)
        return {"hash": d["hash"].lower(), "timestamp": int(d["timestamp"], 16)}

    def spec_dict(self) -> dict:
        h = self.fork_header()
        text = (HERE / "toy" / "impact-spec.json").read_text()
        text = text.replace("${FORK_HASH}", h["hash"]).replace("${FORK_TS}", str(h["timestamp"]))
        return json.loads(text)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
        self.proc = None
