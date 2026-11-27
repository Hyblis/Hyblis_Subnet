#!/usr/bin/env python3
"""Reproduce one submission and emit a verdict (trace-verified validation, design "trace").

RUNS ONLY ON THE SEPARATE RUNNER MACHINE (refuses without HYBLIS_RUNNER=1). Untrusted PoCs never run
on the platform host.

Steps (design section 6):
  R1  static screen (policy_check.py, a cheap pre-filter only) and a shape check of the file;
  R2  a disposable job directory: the prepared task project (hard links, never modified), the miner's
      HyblisPoC.t.sol, the runner's own HyblisBase.sol / HyblisRuntime.sol / HyblisHarness.t.sol, the
      generated HyblisSpec.sol and a generated hardened foundry.toml; runner-file hashes recorded;
  R3  forge build (offline);
  R4  pass 1: the harness test, forge test --json -vvvv, output size-capped; analysed by trace_verdict;
  R6  pass 2: the same with HYBLIS_ATTACKER_SET = the attacker set pass 1 found;
  R8  determinism: pass 1 and pass 2 must run the PoC identically (one retry on a fresh job dir);
  R9  standalone: plain forge test of HyblisPoC.t.sol, as the bounty platform runs it, must pass and
      make the same calls into in-scope contracts (with the same outcomes), the same state-changing
      cheatcodes and HyblisBase helper calls in the same order, and no cheatcode the policy denies;
  R10 program rules (in-scope impacts, known issues, benign entry points, severity cap);
  R11 the verdict; the job directory is deleted.

Every forge process runs with a scrubbed environment (PATH, HOME and TMPDIR inside the job, the fork URL,
the job's salt and step count, and in pass 2 the attacker set; nothing else), --offline,
--no-storage-caching, a per-run timeout, an output-size limit (RLIMIT_FSIZE) and no core dumps, and with
--sandbox netns (default) inside a fresh network namespace with no interfaces (`unshare -n`, needs root;
forge itself runs as --forge-user, never as root). The fork is given as a URL, normally the path of
a read-only fork proxy's Unix socket (--fork-url). If --misses-file is given and holds anything after the
runs, the verdict is {"reproduced": false, "error": "state_miss", "state_misses": [...]} and nothing else
is decided.

Usage:
  HYBLIS_RUNNER=1 run_submission.py --task <id> --poc <file> --project <prepared task project>
      --fork-url <ipc path or URL> [--misses-file <file>] [--submission <id>] [--out verdict.json]
      [--sandbox netns|none] [--forge-user <user>] [--spec <impact-spec.json>] [--manifest <manifest.json>]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
# programs (manifest, impact spec): tasks/ by default; HYBLIS_TASKS_DIR points elsewhere (the platform reads the
# same variable), e.g. for the testnet demo program in run/demo/tasks
TASKS_DIR = Path(os.environ.get("HYBLIS_TASKS_DIR", str(ROOT / "tasks")))
sys.path.insert(0, str(HERE))
import gen_spec  # noqa: E402
import policy_check  # noqa: E402
import sanitize_foundry_toml  # noqa: E402
import trace_verdict as tv  # noqa: E402
from trace_verdict import Reject  # noqa: E402

SOL = HERE / "sol"
RUNNER_FILES = ("HyblisBase.sol", "HyblisRuntime.sol", "HyblisHarness.t.sol")
POC_FILE = "HyblisPoC.t.sol"
MAX_POC_BYTES = 256 * 1024
FORGE_VERSION = "1.9.0"
FORGE_COMMIT = "6056c5845d34205a83cf7108042adb137325c9df"   # the exact build: `forge --version` must print both lines
DEFAULT_SVM = Path(os.environ.get("HYBLIS_ROOT", str(ROOT))) / ".home" / ".svm"
RUNNER_IMPORT = re.compile(r"""import[^;]*["'][^"']*(HyblisRuntime|HyblisHarness|HyblisSpec)[^"']*["']""")


class Options:
    def __init__(self, sandbox="netns", forge_user=None, idle=True, keep_job=False, jobs_dir=None,
                 foundry_bin=None, svm_dir=None, debug=False, rlimits=True, isolate=False,
                 max_memory_gb=32, max_procs=512):
        self.sandbox = sandbox
        self.rlimits = rlimits                     # prlimit wrapper (Linux); the runner always uses it
        self.forge_user = forge_user
        self.idle = idle
        self.keep_job = keep_job
        self.jobs_dir = jobs_dir
        self.foundry_bin = Path(foundry_bin) if foundry_bin else _default_foundry_bin()
        if isinstance(svm_dir, (list, tuple)):
            self.svm_dir = [Path(d) for d in svm_dir]
        else:
            self.svm_dir = Path(svm_dir) if svm_dir else DEFAULT_SVM
        self.debug = debug
        # isolate (shared host): forge also gets its own mount and process namespaces, with tmpfs over /home,
        # /root, /tmp and /var/tmp (nothing of other users is visible) and only its own processes in /proc
        self.isolate = isolate
        self.max_memory_gb = max_memory_gb         # RLIMIT_AS per forge process
        self.max_procs = max_procs                 # RLIMIT_NPROC for the forge user (only with a dedicated user)


# The isolated sandbox (shared host, opts.isolate): as root inside fresh net + mount + pid namespaces,
# stage the few paths forge needs (bind mounts, read-only except the job and the fork socket), hide /home,
# /root, /tmp and /var/tmp behind empty tmpfs mounts, put the staged paths back at their own paths, then
# drop to the forge user. Every mount is private to the namespace: the host never sees a change.
# The forge user may be a bare numeric uid ("64123") with no account: it owns no file on the host.
def _isolate_script(binds) -> str:
    import shlex
    q = shlex.quote
    out = ["set -e", "mount -t tmpfs -o size=64k,mode=755 hyblis-stage /mnt"]
    for i, (path, ro) in enumerate(binds):
        out += [f"mkdir /mnt/b{i}", f"mount --bind {q(str(path))} /mnt/b{i}"]
        if ro:
            out.append(f"mount -o remount,bind,ro /mnt/b{i}")
    out += ["mount -t tmpfs -o size=1m,mode=755 hyblis /home",
            "mount -t tmpfs -o size=64k,mode=700 hyblis /root",
            "mount -t tmpfs -o size=256m,mode=1777 hyblis /tmp",
            "mount -t tmpfs -o size=64k,mode=1777 hyblis /var/tmp"]
    for i, (path, _) in enumerate(binds):
        out += [f"mkdir -p {q(str(path))}", f"mount --move /mnt/b{i} {q(str(path))}"]
    out += ["umount /mnt", 'exec "$@"']
    return "\n".join(out)


def _ids(user: str) -> tuple[int, int, bool]:
    """(uid, gid, has_account) for a user name or a bare numeric uid."""
    if str(user).isdigit():
        return int(user), int(user), False
    import pwd
    pw = pwd.getpwnam(user)
    return pw.pw_uid, pw.pw_gid, True


def sandbox_prefix(opts: "Options", binds=()) -> list[str]:
    """The command prefix every forge run gets (also used by the host sandbox check). `binds`:
    (path, read_only) pairs visible inside the isolated sandbox; everything else under /home is hidden."""
    if opts.sandbox != "netns" and os.geteuid() != 0:
        return []
    uid, gid, named = _ids(opts.forge_user)
    drop = ["setpriv", f"--reuid={uid}", f"--regid={gid}", "--init-groups" if named else "--clear-groups",
            "--no-new-privs", "--"]
    if opts.sandbox == "netns":
        if opts.isolate:
            return ["unshare", "--net", "--mount", "--pid", "--fork", "--mount-proc", "--",
                    "/bin/sh", "-c", _isolate_script(binds), "hyblis-sandbox", *drop]
        return ["unshare", "--net", "--", *drop]
    return drop


def limits_prefix(opts: "Options", max_bytes: int) -> list[str]:
    if not opts.rlimits:
        return []
    lim = ["prlimit", f"--fsize={max_bytes}", "--core=0", f"--as={int(opts.max_memory_gb * 1024 ** 3)}"]
    if opts.forge_user and str(opts.forge_user) not in ("root", "pinc", "0"):
        lim.append(f"--nproc={opts.max_procs}")       # counts the forge user's processes host-wide
    return lim + ["--"]


def _default_foundry_bin() -> Path:
    w = shutil.which("forge")
    if w:
        return Path(w).resolve().parent
    return Path(os.environ.get("HYBLIS_ROOT", str(ROOT))) / "tools" / "foundry" / "bin"


# ------------------------------------------------------------------ files and hashes
def sha256_file(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def pinned_hashes() -> dict:
    """runner/sol/SHA256SUMS: the runner refuses to run with runner files that differ from it."""
    out = {}
    for line in (SOL / "SHA256SUMS").read_text().splitlines():
        if line.strip():
            h, name = line.split()
            out[name] = h
    return out


def check_runner_files() -> dict:
    pins = pinned_hashes()
    got = {name: sha256_file(SOL / name) for name in RUNNER_FILES}
    for name in RUNNER_FILES:
        if pins.get(name) != got[name]:
            raise Reject("runner_error", f"runner file {name} does not match runner/sol/SHA256SUMS")
    return got


def _copy_project(src: Path, dst: Path, poc_dir: str):
    """Disposable copy: hard links for sources (never written), real copies of out/ and cache/
    (forge rewrites them). No .git, broadcast, .env files, or anything already in the PoC directory.
    Symbolic links are kept only if they point inside the project (re-created relative to the copy)."""
    src = src.resolve()
    poc_rel = Path(poc_dir)

    def link_inside(path: Path, target_dst: Path):
        real = Path(os.path.realpath(path))
        if real == src or src in real.parents:
            os.symlink(os.path.relpath(dst / real.relative_to(src), target_dst.parent), target_dst)

    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        rel = Path(dirpath).relative_to(src)
        if rel == poc_rel or poc_rel in rel.parents:
            dirnames[:] = []
            continue
        (dst / rel).mkdir(parents=True, exist_ok=True)
        keep = []
        for d in dirnames:
            if d == ".git" or (rel == Path(".") and d == "broadcast") or d.startswith(".env"):
                continue
            if os.path.islink(os.path.join(dirpath, d)):
                link_inside(Path(dirpath) / d, dst / rel / d)
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in filenames:
            if f.startswith(".env") or (f == "foundry.toml" and rel == Path(".")):
                continue
            s, d = Path(dirpath) / f, dst / rel / f
            if s.is_symlink():
                link_inside(s, d)
                continue
            top = rel.parts[0] if rel.parts else ""
            if top in ("out", "cache"):
                shutil.copy2(s, d)
            else:
                try:
                    os.link(s, d)
                except OSError:
                    shutil.copy2(s, d)


def _solc_path(cfg: dict, svm) -> str:
    """The pinned solc binary from the first svm directory that has it (never downloaded)."""
    ver = sanitize_foundry_toml.solc_version(cfg)
    if not ver:
        raise Reject("runner_error", "the task project does not pin a solc version")
    dirs = svm if isinstance(svm, (list, tuple)) else [svm]
    for d in dirs:
        p = Path(d) / ver / f"solc-{ver}"
        if p.exists():
            return str(p)
    raise Reject("runner_error", f"solc {ver} is not installed (looked in {', '.join(str(d) for d in dirs)})")


# ------------------------------------------------------------------ forge under the sandbox
class Forge:
    def __init__(self, job: Path, project: Path, opts: Options, fork_url: str, deadline: float, spec: dict):
        self.job, self.project, self.opts, self.fork_url = job, project, opts, fork_url
        self.deadline = deadline
        self.max_bytes = spec["limits"]["json_max_mb"] * 1024 * 1024
        self.run_timeout = spec["limits"]["forge_timeout_s"]
        self.home = job / "home"
        self.tmp = job / "tmp"
        for d in (self.home, self.tmp):
            d.mkdir(exist_ok=True)

    def binds(self) -> list:
        """Paths forge needs inside the isolated sandbox: its job (rw), the pinned forge and solc (ro), and
        the directory of the fork socket (rw, to connect)."""
        out = [(self.job, False), (self.opts.foundry_bin, True)]
        svm = self.opts.svm_dir if isinstance(self.opts.svm_dir, (list, tuple)) else [self.opts.svm_dir]
        out += [(Path(d), True) for d in svm if Path(d).is_dir()]
        if self.fork_url and not str(self.fork_url).startswith(("http:", "https:", "ws:", "wss:")):
            out.append((Path(self.fork_url).resolve().parent, False))
        seen, uniq = set(), []
        for pth, ro in out:
            if str(pth) not in seen:
                seen.add(str(pth)); uniq.append((pth, ro))
        return uniq

    def env(self, extra: dict) -> list[str]:
        base = {"PATH": f"{self.opts.foundry_bin}:/usr/bin:/bin", "HOME": str(self.home), "TMPDIR": str(self.tmp),
                "LANG": "C.UTF-8", "NO_COLOR": "1", "FOUNDRY_DISABLE_NIGHTLY_WARNING": "1",
                "HYBLIS_ETH_RPC": self.fork_url}
        base.update(extra)
        return [f"{k}={v}" for k, v in base.items()]

    def run(self, args: list[str], out: Path, extra_env: dict | None = None) -> int:
        remaining = self.deadline - time.time()
        if remaining <= 5:
            raise Reject("limits", "job time limit reached")
        timeout = min(self.run_timeout, remaining)
        limits = limits_prefix(self.opts, self.max_bytes)
        cmd = ["env", "-i", *self.env(extra_env or {}), *limits, str(self.opts.foundry_bin / "forge"), *args]
        if self.opts.idle:
            cmd = ["chrt", "--idle", "0", "nice", "-n", "19", *cmd]
        cmd = [*sandbox_prefix(self.opts, self.binds()), *cmd]
        err = out.with_suffix(".stderr")
        with open(out, "wb") as fo, open(err, "wb") as fe:
            p = subprocess.Popen(cmd, cwd=self.project, stdout=fo, stderr=fe, stdin=subprocess.DEVNULL,
                                 start_new_session=True)
            try:
                rc = p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
                raise Reject("limits", f"a forge run took longer than {int(timeout)} s") from None
        if rc in (-signal.SIGXFSZ, 128 + signal.SIGXFSZ) or out.stat().st_size >= self.max_bytes:
            raise Reject("limits", f"forge output above {self.max_bytes} bytes")
        if rc < 0 or rc > 128:
            raise Reject("no_json", f"forge was killed (signal {abs(rc) % 128})")
        return rc


# ------------------------------------------------------------------ static checks
def _shape_screen(poc_src: str):
    if len(poc_src.encode("utf-8")) > MAX_POC_BYTES:
        raise Reject("limits", f"PoC file above {MAX_POC_BYTES} bytes")
    code = policy_check.strip_comments(poc_src)
    if not re.search(r"\bcontract\s+HyblisPoC\b", code):
        raise Reject("poc_shape", "no contract named HyblisPoC")
    if RUNNER_IMPORT.search(code):
        raise Reject("poc_shape", "imports a runner file")


def _abi_shape(project: Path, max_steps: int) -> int:
    art = project / "out" / POC_FILE / "HyblisPoC.json"
    try:
        ids = json.loads(art.read_text())["methodIdentifiers"]
    except Exception:
        raise Reject("poc_shape", "no compiled HyblisPoC contract") from None
    names = set(ids)
    if "test_exploit()" not in names or "setUp()" not in names:
        raise Reject("poc_shape", "HyblisPoC needs setUp() and test_exploit()")
    others = sorted(n for n in names if (n.startswith("test") or n.startswith("invariant")) and n != "test_exploit()")
    if others:
        raise Reject("poc_shape", f"{len(others)} test functions besides test_exploit()")
    steps = set()
    for n in names:
        if re.match(r"^step\d+\(", n):
            m = re.fullmatch(r"step([1-9]\d*)\(\)", n)
            if not m:
                raise Reject("poc_shape", "step functions take no arguments and are numbered from step1()")
            steps.add(int(m.group(1)))
    if steps and steps != set(range(1, len(steps) + 1)):
        raise Reject("poc_shape", "steps must be step1() .. stepN() without gaps")
    if len(steps) > max_steps:
        raise Reject("limits", f"more than {max_steps} steps")
    return len(steps)


def _compile_error(text: str) -> Reject:
    lines = sorted({int(m.group(1)) for m in re.finditer(r"test/hyblis/HyblisPoC\.t\.sol:(\d+):\d+", text)})
    if lines:
        return Reject("compile", "lines " + ", ".join(str(x) for x in lines[:20]))
    if "test/hyblis/HyblisHarness.t.sol" in text:
        return Reject("poc_shape", "the runner cannot deploy HyblisPoC (constructor arguments, abstract, or missing)")
    return Reject("compile", "")


def _runtime_code_hashes(project: Path) -> dict:
    out = {}
    for name, key in (("HyblisFaucet", "faucet"), ("HyblisProbe", "probe")):
        art = json.loads((project / "out" / "HyblisRuntime.sol" / f"{name}.json").read_text())
        out[key] = hashlib.sha256(bytes.fromhex(art["deployedBytecode"]["object"][2:])).hexdigest()
    return out


# ------------------------------------------------------------------ fresh accounts (state layer)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FRESH_EOAS = 64              # attacker indices 1..64 (= limits.max_attackers at most)
FRESH_POC_CREATES = 32       # contracts the PoC creates (nonces 1..32)
FRESH_EOA_CREATES = 8        # contracts each attacker account creates (nonces 0..7)


def _create_addr(sender: str, nonce: int) -> str:
    import rlp
    from eth_utils import keccak
    return "0x" + keccak(rlp.encode([bytes.fromhex(sender[2:]), nonce]))[12:].hex()


def attacker_address(salt: str, index: int) -> str:
    """runner/sol/HyblisRuntime.sol attackerKey: key = keccak256(abi.encode(salt, index)) mod n (0 -> 1)."""
    from eth_keys import keys
    from eth_utils import keccak
    k = int.from_bytes(keccak(bytes.fromhex(salt[2:]) + index.to_bytes(32, "big")), "big") % SECP256K1_N or 1
    return "0x" + keys.PrivateKey(k.to_bytes(32, "big")).public_key.to_canonical_address().hex()


def _create2_addr(deployer: str, salt: int, init_hash: bytes) -> str:
    from eth_utils import keccak
    return "0x" + keccak(b"\xff" + bytes.fromhex(deployer[2:]) + salt.to_bytes(32, "big") + init_hash)[12:].hex()


def fresh_set(project: Path, salt: str, spec: dict) -> dict | None:
    """Addresses of this job that derive from its secret salt (state/fresh.py): the PoC's CREATE2 address,
    the attacker accounts the faucet can hand out, the contracts they create with CREATE, and CREATE2
    deployments of the PoC file's own contracts (no constructor arguments) with small salts. None if the
    PoC's init code needs library linking (its address cannot be computed; reads then stay misses).
    Coverage is bounded; anything not listed is answered from the snapshot or is a miss, as before."""
    from eth_utils import keccak
    art_dir = project / "out" / POC_FILE
    obj = json.loads((art_dir / "HyblisPoC.json").read_text())["bytecode"]["object"]
    if "__$" in obj:
        return None
    poc = "0x" + keccak(b"\xff" + bytes.fromhex(tv.HARNESS[2:]) + bytes.fromhex(salt[2:]) +
                        keccak(bytes.fromhex(obj[2:])))[12:].hex()
    hashes = []
    for f in sorted(art_dir.glob("*.json")):
        if f.name == "HyblisPoC.json":
            continue
        try:
            o = json.loads(f.read_text())["bytecode"]["object"]
        except (ValueError, KeyError, TypeError):
            continue
        if isinstance(o, str) and len(o) > 2 and "__$" not in o:
            hashes.append(keccak(bytes.fromhex(o[2:])))
    hashes = hashes[:8]
    eoas = [attacker_address(salt, i) for i in range(1, FRESH_EOAS + 1)]
    poc_created = [_create_addr(poc, n) for n in range(1, FRESH_POC_CREATES + 1)]
    eoa_created = [_create_addr(e, n) for e in eoas for n in range(FRESH_EOA_CREATES)]
    nested = [_create_addr(c, n) for c in poc_created[:8] for n in range(1, 5)]
    c2_first = [_create2_addr(d, k, h) for d in [poc] + eoas[:2] + poc_created[:1] for k in range(16) for h in hashes]
    c2_rest = [_create2_addr(d, k, h) for d in [poc] + eoas[:8] for k in range(32) for h in hashes]
    # keys = the addresses whose mapping slots are precomputed (state/fresh.py MAX_KEYS_*), most likely first
    first = [poc] + eoas[:8] + poc_created[:8] + [_create_addr(e, n) for e in eoas[:8] for n in range(2)] + c2_first
    keys = list(dict.fromkeys(first + eoas[8:] + poc_created[8:] + eoa_created + nested + c2_rest))
    partners = {c["address"] for c in spec["in_scope"]} | {t["address"] for t in spec["tokens"] if t["address"] != tv.ZERO}
    partners |= {h["address"] for h in spec["holders"]}
    return {"accounts": keys, "keys": keys, "partners": sorted(partners), "poc": poc}


# ------------------------------------------------------------------ misses (state layer)
# Rejections that judge what the PoC did, not what it could read: missing fork state cannot
# have caused them, so they stand even when the run also read outside the snapshot.
# ("template", "harness_failed", "poc_reverted" and the like are NOT here: a missing read aborts forge
# and changes the shape of its output, so those can be caused by the snapshot, not by the PoC.)
RULE_ERRORS = frozenset({"screen", "poc_shape", "compile", "limits", "impersonation",
                         "fork", "env", "time", "reentry", "capital", "helper"})


def _refusals(fork) -> list:
    """Requests the read-only fork proxy refused during this job (empty without a proxy handle)."""
    if fork is None or not hasattr(fork, "refusals"):
        return []
    try:
        return [r for r in (fork.refusals() or []) if isinstance(r, dict)]
    except Exception:
        return []


def read_misses(path: str | None, fork=None) -> list:
    out: list = []
    if fork is not None and hasattr(fork, "misses"):
        try:
            out.extend(list(fork.misses() or []))
        except Exception as e:  # a broken state layer is an infrastructure fault
            raise Reject("runner_error", f"fork handle misses() failed: {type(e).__name__}") from None
    if path and Path(path).exists():
        text = Path(path).read_text(errors="replace").strip()
        if text:
            try:
                d = json.loads(text)
                out.extend(d.get("misses", []) if isinstance(d, dict) else d if isinstance(d, list) else [d])
            except ValueError:
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        out.append(line)
    return out


def fork_block_header(fork_url: str, block: int, foundry_bin: Path | None = None) -> dict | None:
    """Hash and timestamp of a block from the fork source (cast, read-only)."""
    cast = str((foundry_bin or _default_foundry_bin()) / "cast")
    try:
        p = subprocess.run([cast, "block", str(block), "--rpc-url", fork_url, "--json"], capture_output=True,
                           text=True, timeout=60, env={"PATH": "/usr/bin:/bin", "HOME": tempfile.gettempdir()})
        d = json.loads(p.stdout)
        d = d.get("data", d)
        ts = d["timestamp"]
        return {"hash": d["hash"].lower(), "timestamp": int(ts, 16) if isinstance(ts, str) else int(ts)}
    except Exception:
        return None


# ------------------------------------------------------------------ one job
def _run_job(spec: dict, poc_src: str, project: Path, fork_url: str, opts: Options, submission_id: str,
             poc_dir: str, hashes: dict, deadline: float, fork=None) -> dict:
    job = Path(tempfile.mkdtemp(prefix="hyblis-job-", dir=opts.jobs_dir))
    timings = {}
    info = tv.runner_info(spec)
    try:
        proj = job / "project"
        proj.mkdir()
        _copy_project(project, proj, poc_dir)
        pd = proj / poc_dir
        pd.mkdir(parents=True, exist_ok=True)
        (pd / POC_FILE).write_text(poc_src)
        for name in RUNNER_FILES:
            shutil.copyfile(SOL / name, pd / name)
        (pd / "HyblisSpec.sol").write_text(gen_spec.render_solidity(spec))
        src_toml = project / "foundry.toml"
        cfg = tomllib.loads(src_toml.read_text()) if src_toml.exists() else {}
        (proj / "foundry.toml").write_text(sanitize_foundry_toml.runner_toml(cfg, _solc_path(cfg, opts.svm_dir),
                                                                             gen_spec.harness_gas_limit(spec)))
        files = {name: sha256_file(pd / name) for name in RUNNER_FILES + ("HyblisSpec.sol",)}
        files["foundry.toml"] = sha256_file(proj / "foundry.toml")
        files[POC_FILE] = hashlib.sha256(poc_src.encode()).hexdigest()
        if opts.sandbox == "netns" or os.geteuid() == 0:
            _chown_tree(job, opts.forge_user)
        forge = Forge(job, proj, opts, fork_url, deadline, spec)

        t0 = time.time()
        rc = forge.run(["build", "--offline"], job / "build.log")
        timings["build_s"] = round(time.time() - t0, 2)
        if rc != 0:
            raise _compile_error((job / "build.log").read_text(errors="replace") +
                                 (job / "build.stderr").read_text(errors="replace"))
        steps = _abi_shape(proj, spec["limits"]["max_steps"])
        code = _runtime_code_hashes(proj)
        salt = "0x" + secrets.token_hex(32)
        if fork is not None and hasattr(fork, "set_fresh"):
            t0 = time.time()
            fs = fresh_set(proj, salt, spec)
            if fs is not None:
                fork.set_fresh(fs["accounts"], fs["keys"], fs["partners"], label=submission_id)
            timings["fresh_s"] = round(time.time() - t0, 2)
        table = tv.load_selector_table()
        harness = ["test", "--json", "-vvvv", "--offline", "--no-storage-caching", "--disable-block-gas-limit",
                   "--fuzz-seed", "1", "--match-path", f"{poc_dir}/HyblisHarness.t.sol",
                   "--match-contract", "^HyblisHarness$", "--match-test", r"^test_hyblis\(\)$"]
        henv = {"HYBLIS_SALT": salt, "HYBLIS_STEPS": str(steps)}
        info = tv.runner_info(spec, files, salt, steps)
        info["sandbox"] = opts.sandbox

        t0 = time.time()
        forge.run(harness, job / "pass1.json", henv)
        timings["pass1_s"] = round(time.time() - t0, 2)
        p1 = tv.analyze_pass(tv.load_forge_json(job / "pass1.json", forge.max_bytes),
                             tv.Ctx(spec, fork_url, salt, steps, [], table, code))
        aset = [a for a in p1["attacker_order"] if a != p1["poc"]]
        t0 = time.time()
        forge.run(harness, job / "pass2.json", dict(henv, HYBLIS_ATTACKER_SET=",".join(aset)))
        timings["pass2_s"] = round(time.time() - t0, 2)
        p2 = tv.analyze_pass(tv.load_forge_json(job / "pass2.json", forge.max_bytes),
                             tv.Ctx(spec, fork_url, salt, steps, aset, table, code))
        t0 = time.time()
        forge.run(["test", "--json", "-vvvv", "--offline", "--no-storage-caching", "--fuzz-seed", "1",
                   "--memory-limit", "134217728",                       # forge's default, as judges run it
                   "--match-path", f"{poc_dir}/{POC_FILE}", "--match-contract", "^HyblisPoC$",
                   "--match-test", r"^test_exploit\(\)$"], job / "standalone.json")
        timings["standalone_s"] = round(time.time() - t0, 2)
        try:
            sd = tv.load_forge_json(job / "standalone.json", forge.max_bytes)
        except Reject as e:
            if e.code == "limits":
                raise
            raise Reject("standalone_fails", "plain forge test produced no result") from None
        for name in RUNNER_FILES + ("HyblisSpec.sol",):
            if sha256_file(pd / name) != files[name]:
                raise Reject("runner_error", f"runner file {name} changed during the job")
        v = tv.decide(p1, p2, sd, spec, info, submission_id)
        v["runner"]["timings"] = timings
        if opts.debug:
            v["debug"] = {"spec_health": p2.get("spec_health"), "pass1_impact": p1.get("impact_type"),
                          "eoas": p2.get("eoas"), "created": p2.get("created"), "job": str(job)}
        return v
    except Reject as e:
        info["timings"] = timings
        v = tv.reject_verdict(e, submission_id)
        v["runner"] = info
        if opts.debug:
            v["debug"] = {"job": str(job)}
        return v
    finally:
        if fork is not None and hasattr(fork, "clear_fresh"):
            fork.clear_fresh()
        if not opts.keep_job:
            shutil.rmtree(job, ignore_errors=True)


def _chown_tree(path: Path, user: str):
    uid, gid, _ = _ids(user)
    for dirpath, dirnames, filenames in os.walk(path):
        os.chown(dirpath, uid, gid)
        for f in filenames:
            fp = os.path.join(dirpath, f)
            if os.stat(fp).st_nlink > 1:
                continue                                   # hard link into the prepared project: leave it
            os.chown(fp, uid, gid)


# ------------------------------------------------------------------ entry points
def reproduce_with_spec(spec: dict, poc_src: str, project: Path, fork_url: str, submission_id: str = "",
                        sandbox: str = "netns", misses_file: str | None = None, fork=None,
                        manifest: dict | None = None, debug: bool = False, options: Options | None = None) -> dict:
    """The verdict for one PoC against a compiled spec (gen_spec.compile_spec)."""
    opts = options or Options(sandbox=sandbox, debug=debug)
    if options is None and sandbox == "auto":
        opts.sandbox = "netns" if os.geteuid() == 0 else "none"
    if debug:
        opts.debug = True
    started = time.time()
    deadline = started + spec["limits"]["job_timeout_s"]
    poc_dir = (manifest or {}).get("submission", {}).get("poc_dir", "test/hyblis")
    verdict = None
    try:
        if opts.sandbox not in ("netns", "none"):
            raise Reject("runner_error", f"unknown sandbox {opts.sandbox}")
        if opts.sandbox == "netns" and not opts.rlimits:
            raise Reject("runner_error", "the runner always applies the output and core-dump limits")
        if (opts.sandbox == "netns" or os.geteuid() == 0) and not opts.forge_user:
            raise Reject("runner_error", "running as root needs --forge-user (forge never runs as root)")
        if opts.sandbox == "netns" and os.geteuid() != 0:
            raise Reject("runner_error", "--sandbox netns needs root to create the network namespace")
        if poc_dir != "test/hyblis":
            raise Reject("runner_error", "the PoC directory must be test/hyblis")
        hashes = check_runner_files()
        _forge_version_ok(opts)
        if manifest is not None:
            pv, findings = policy_check.check(manifest, poc_src)
            if pv == "REJECT":
                v = tv.reject_verdict(Reject("screen", "static screen"), submission_id, deterministic=True)
                v["policy"] = [{"reason": f["reason"], "line": f["line"]} for f in findings if f["level"] == "REJECT"]
                verdict = v
        if verdict is None:
            _shape_screen(poc_src)
            for attempt in (1, 2):
                verdict = _run_job(spec, poc_src, project, fork_url, opts, submission_id, poc_dir, hashes, deadline,
                                   fork=fork)
                verdict.setdefault("runner", {})["attempts"] = attempt
                if verdict.get("error") != "nondeterministic":
                    break
    except Reject as e:
        verdict = tv.reject_verdict(e, submission_id)
        verdict["runner"] = tv.runner_info(spec)
    except Exception as e:  # never let a runner bug look like a judgement of the PoC
        verdict = tv.reject_verdict(Reject("runner_error", type(e).__name__), submission_id)
        verdict["runner"] = tv.runner_info(spec)
        if opts.debug:
            import traceback
            verdict["debug"] = {"traceback": traceback.format_exc()}
    misses = read_misses(misses_file, fork)
    final = finalize(verdict, misses, _refusals(fork), spec, submission_id)
    if final is not verdict:
        return final
    verdict.setdefault("runner", tv.runner_info(spec))
    verdict["runner"]["elapsed_s"] = round(time.time() - started, 2)
    return verdict


def finalize(verdict: dict, misses: list, refusals: list, spec, submission_id: str) -> dict:
    """Combine the engine's verdict with what the read-only fork proxy saw. Returns `verdict` itself
    when nothing changes, otherwise a new verdict.
      * a request the proxy refused (other than forge's own anvil_nodeInfo probe) means the PoC broke
        the rules: rejected as "fork", never held for state;
      * a rule violation stands whatever state was missing, so such jobs never wait and their misses
        never feed a snapshot extension;
      * otherwise any miss means nothing is decided: "state_miss", the job waits for the snapshot."""
    refused = [r for r in (refusals or []) if r.get("method") != "anvil_nodeInfo"]
    if refused:
        v = tv.reject_verdict(Reject("fork", "forbidden fork request: " + ", ".join(
            sorted({str(r.get("method"))[:40] for r in refused}))[:200]), submission_id)
        v["runner"] = tv.runner_info(spec)
        return v
    err = verdict.get("error") or ""
    if misses and (err in RULE_ERRORS or err.startswith("policy:")):
        verdict.setdefault("runner", tv.runner_info(spec))
        verdict["detail"] = ((verdict.get("detail") or "") + f" ({len(misses)} fork reads outside the snapshot ignored)").strip()[:300]
        return verdict
    if misses:
        v = tv.base_verdict(submission_id)
        v.update({"error": "state_miss", "state_misses": misses, "detail": f"{len(misses)} fork reads outside the snapshot"})
        v["runner"] = tv.runner_info(spec)
        return v
    return verdict


def forge_version_ok(stdout: str) -> bool:
    """`forge --version` of exactly the pinned build: the version line and the commit line must match in full
    (so 1.9.0-nightly, 1.9.0-dev or another commit of 1.9.0 is refused)."""
    lines = [ln.strip() for ln in stdout.splitlines()]
    return f"forge Version: {FORGE_VERSION}" in lines and f"Commit SHA: {FORGE_COMMIT}" in lines


def _forge_version_ok(opts: Options):
    try:
        p = subprocess.run([str(opts.foundry_bin / "forge"), "--version"], capture_output=True, text=True, timeout=30,
                           env={"PATH": "/usr/bin:/bin", "HOME": tempfile.gettempdir()})
        ok = p.returncode == 0 and forge_version_ok(p.stdout)
    except Exception:
        ok = False
    if not ok:
        raise Reject("runner_error", f"forge {FORGE_VERSION} (commit {FORGE_COMMIT[:7]}) is required (pinned)")


def load_task(task_id: str, spec_path: str | None = None, manifest_path: str | None = None) -> tuple[dict, dict]:
    tdir = TASKS_DIR / task_id
    manifest = json.loads(Path(manifest_path or tdir / "manifest.json").read_text())
    spec = gen_spec.compile_spec(json.loads(Path(spec_path or tdir / "impact-spec.json").read_text()))
    return manifest, spec


def reproduce(task_id: str, poc_src: str, project: Path, submission_id: str = "", fork_url: str | None = None,
              misses_file: str | None = None, fork=None, options: Options | None = None,
              spec_path: str | None = None, manifest_path: str | None = None) -> dict:
    """Entry point used by agent.py: the verdict for one submission of task `task_id`."""
    try:
        manifest, spec = load_task(task_id, spec_path, manifest_path)
    except (gen_spec.SpecError, OSError, ValueError) as e:
        v = tv.reject_verdict(Reject("runner_error", f"task spec unusable: {type(e).__name__}"), submission_id)
        return v
    if not fork_url:
        v = tv.reject_verdict(Reject("runner_error", "no fork URL"), submission_id)
        return v
    return reproduce_with_spec(spec, poc_src, Path(project), fork_url, submission_id, misses_file=misses_file,
                               fork=fork, manifest=manifest, options=options)


def main():
    if os.environ.get("HYBLIS_RUNNER") != "1":
        sys.exit("refusing to run: set HYBLIS_RUNNER=1 (this must run only on the isolated runner machine)")
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True)
    ap.add_argument("--poc", required=True)
    ap.add_argument("--project", required=True, help="prepared task foundry project dir (read only)")
    ap.add_argument("--fork-url", required=True, help="fork source: IPC socket path of the read-only fork proxy")
    ap.add_argument("--misses-file", help="file the fork proxy writes reads outside its snapshot to")
    ap.add_argument("--submission", default="")
    ap.add_argument("--out")
    ap.add_argument("--sandbox", default="netns", choices=["netns", "none"])
    ap.add_argument("--forge-user", help="unprivileged user forge runs as (required when run as root)")
    ap.add_argument("--spec", help="impact spec (default tasks/<task>/impact-spec.json)")
    ap.add_argument("--manifest", help="task manifest (default tasks/<task>/manifest.json)")
    ap.add_argument("--jobs-dir")
    ap.add_argument("--no-idle", action="store_true", help="run forge at normal priority (dedicated runner VM)")
    ap.add_argument("--keep-job", action="store_true")
    ap.add_argument("--debug", action="store_true")
    a = ap.parse_args()
    opts = Options(sandbox=a.sandbox, forge_user=a.forge_user, idle=not a.no_idle, keep_job=a.keep_job,
                   jobs_dir=a.jobs_dir, debug=a.debug)
    v = reproduce(a.task, Path(a.poc).read_text(), Path(a.project), a.submission, fork_url=a.fork_url,
                  misses_file=a.misses_file, options=opts, spec_path=a.spec, manifest_path=a.manifest)
    text = json.dumps(v, indent=1, default=str)
    if a.out:
        Path(a.out).write_text(text)
    print(text)


if __name__ == "__main__":
    main()
