"""The `hyblis check` bundle works on its own, on a toy chain.

A toy task pack (runner/tests/toy, marked verified and released) goes through the real export
(publish.export_all), the bundle is downloaded from the real public site (in-process TestServer),
extracted into an empty directory, and its runner/check.py runs from there: no HYBLIS_ROOT, no
PYTHONPATH, nothing from the repository on its path. Only the toy project (the "program's Foundry
project"), a solc in ~/.svm (as forge build leaves it) and Foundry on PATH come from outside, as for a
researcher. Expected: an honest theft is VALIDATED with its function, a vm.store hidden in a helper is
REJECTED by the trace check, and a direct vm.store is REJECTED by the static screen with its line,
which uses the bundle's cut-down manifest.

Toy chain only: anvil over IPC, its HTTP port on 127.0.0.1:9868 or 9869, stopped by its own PID.
Never mainnet, no network. Heavy work at idle priority. Run as pinc (about two minutes).
"""
import asyncio
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile

tmp = pathlib.Path(tempfile.mkdtemp(prefix="hyblis-bundle-test-"))
repo = tmp / "repo"
TASKS = repo / "tasks"
os.environ["HYBLIS_DATA_DIR"] = str(tmp / "data")
os.environ["HYBLIS_PUBLIC_DIR"] = str(tmp / "public")
os.environ["HYBLIS_TASKS_DIR"] = str(TASKS)

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(ROOT / "runner" / "tests"))
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402
from hyblis_platform import config, publicsite, publish, store  # noqa: E402
import toy_chain  # noqa: E402

toy_chain.PORTS = (9868, 9869)          # this test's own ports (the runner suite uses 9866/9867)
VARIANTS = ROOT / "runner" / "tests" / "variants"
FAILS = []


def check(cond, msg):
    print(("ok   " if cond else "FAIL ") + msg, flush=True)
    if not cond:
        FAILS.append(msg)


def task_pack(chain):
    """tasks/toy as a released, ready program with a verified spec, plus one queued program."""
    t = TASKS / "toy"
    (t / "poc").mkdir(parents=True)
    m = json.loads((ROOT / "runner" / "tests" / "toy" / "manifest.json").read_text())
    m["program"] = {"name": "Toy", "platform": "planted-secret-platform", "max_rewards_usd": {"critical": 31337}}
    m["submission"].update(poc_template="tasks/toy/poc/HyblisPoC.t.sol", poc_base="tasks/toy/poc/HyblisBase.sol")
    (t / "manifest.json").write_text(json.dumps(m))
    spec = chain.spec_dict()
    spec["status"] = "verified"
    spec.pop("pending_verification", None)
    (t / "impact-spec.json").write_text(json.dumps(spec))
    shutil.copy(VARIANTS / "v01_honest_theft.sol", t / "poc" / "HyblisPoC.t.sol")
    shutil.copy(ROOT / "runner" / "sol" / "HyblisBase.sol", t / "poc" / "HyblisBase.sol")
    shutil.copytree(t, TASKS / "queued-one")
    (TASKS / "releases.json").write_text(json.dumps({"cadence": {"release_every_days": 7}, "tasks": [
        {"task_id": "toy", "label": "Toy", "status": "open", "opened_at": "2026-11-16", "severity_scope": ["medium", "low"],
         "scope_summary": "Toy protocol for tests.", "ready": True},
        {"task_id": "queued-one", "label": "Queued", "status": "queued", "ready": False}]}))


async def download() -> bytes:
    site = TestClient(TestServer(publicsite.make_app()))
    await site.start_server()
    try:
        r = await site.get("/data/check/toy.tar.gz")
        body = await r.read()
        check(r.status == 200 and r.headers["Content-Type"] == "application/gzip", "the site serves the toy bundle")
        check((await site.get("/data/check/queued-one.tar.gz")).status == 404, "a queued program has no bundle")
        return body
    finally:
        await site.close()


def run_check(bundle_dir, chain, poc, work, home):
    env = {"PATH": f"{toy_chain.FOUNDRY_BIN}:/usr/bin:/bin", "HOME": str(home), "LANG": "C.UTF-8"}
    cmd = [sys.executable, "-I", "-B", "runner/check.py", "--task", "toy", "--poc", str(poc),
           "--project", str(chain.project), "--rpc", str(chain.ipc), "--jobs-dir", str(work)]
    return subprocess.run(["chrt", "--idle", "0", "nice", "-n", "19", *cmd], cwd=bundle_dir, env=env,
                          capture_output=True, text=True, timeout=900)


def main():
    work = tmp / "work"
    work.mkdir()
    chain = toy_chain.ToyChain(work)
    try:
        chain.prepare_project()
        chain.start()
        chain.deploy()
        print(f"toy chain on {chain.ipc} (anvil HTTP 127.0.0.1:{chain.port})", flush=True)
        task_pack(chain)
        store.init_db()
        publish.export_all()
        data = asyncio.run(download())
        out = tmp / "extracted"          # a new, empty directory for the downloaded archive
        out.mkdir()
        with tarfile.open(fileobj=__import__("io").BytesIO(data), mode="r:gz") as tf:
            names = tf.getnames()
            tf.extractall(out, filter="data")
        check(names == publish.check_bundle_members("toy"), f"the bundle holds exactly the {len(names)} listed files")
        blob = "".join(p.read_text(errors="replace") for p in out.rglob("*") if p.is_file()).lower()
        cut = json.loads((out / "hyblis-check-toy" / "tasks" / "toy" / "manifest.json").read_text())
        check(set(cut) == {"task_id", "chain", "deployed", "submission"}, "the manifest holds only what check.py reads")
        check("planted-secret" not in blob and "max_rewards" not in blob, "no planted private text in any file")
        bundle_dir = out / "hyblis-check-toy"
        home = tmp / "home"                   # the researcher's home: solc where forge build puts it
        svm = home / ".svm" / "0.8.28"
        svm.mkdir(parents=True)
        os.symlink(pathlib.Path(os.environ.get("HYBLIS_ROOT", str(ROOT))) / ".home" / ".svm" / "0.8.28" / "solc-0.8.28",
                   svm / "solc-0.8.28")
        jobs = tmp / "jobs"
        jobs.mkdir()
        p = run_check(bundle_dir, chain, VARIANTS / "v01_honest_theft.sol", jobs, home)
        check(p.returncode == 0 and "VALIDATED" in p.stdout and "withdrawFor(address,uint256)" in p.stdout,
              "from the bundle: an honest theft is VALIDATED with its function" + ("" if p.returncode == 0 else f"\n{p.stdout}{p.stderr[-2000:]}"))
        p = run_check(bundle_dir, chain, VARIANTS / "v14_hidden_store_helper.sol", jobs, home)
        check(p.returncode == 1 and "REJECTED  policy:store(address,bytes32,bytes32)" in p.stdout
              and "cheatcode that is not allowed" in p.stdout,
              "from the bundle: a vm.store hidden in a helper is REJECTED by the trace check" + ("" if p.returncode == 1 else f"\n{p.stdout}{p.stderr[-2000:]}"))
        p = run_check(bundle_dir, chain, VARIANTS / "v03_store_fake_loss.sol", jobs, home)
        check(p.returncode == 1 and "REJECTED  screen" in p.stdout and "forbidden cheatcode vm.store" in p.stdout
              and "line " in p.stdout, "from the bundle: a direct vm.store is REJECTED by the static screen, with its line"
              + ("" if p.returncode == 1 else f"\n{p.stdout}{p.stderr[-2000:]}"))
        print(f"bundle: {len(data)} bytes; check.py ran from {bundle_dir}", flush=True)
    finally:
        chain.stop()
        shutil.rmtree(tmp, ignore_errors=True)
    print()
    print("ALL BUNDLE CHECKS PASS" if not FAILS else f"{len(FAILS)} BUNDLE CHECKS FAILED")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
