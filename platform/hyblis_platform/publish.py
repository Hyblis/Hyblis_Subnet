"""Public export: the only researcher-facing view of the platform's data.

Publishes exactly what docs/decisions.md allows: submission hashes, times,
statuses, severities, and the deterministic scores from
scoring.hyblis_scoring.policy applied to the public event ledger.

Never exported: submission contents, which program a report is for (not even
as an opaque bucket: a stable id per program can be matched to its program
with one test report), the external bounty platform, bounty and payout amounts,
and the release queue (programs that have not been released yet are private;
only their next release date is published).

Everything here is built from explicit whitelists, never by copying whole
manifests, so a new private field cannot leak by accident. That includes the
downloadable `hyblis check` bundle of each released, ready program
(check_bundle): fixed runner files, the program's impact spec without its
comments, its PoC template and base, and a manifest cut down to the fields the
check tool reads.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import logging
import os
import re
import sys
import tarfile
import threading
from datetime import date, datetime, timedelta, timezone
from fractions import Fraction
from pathlib import Path

from . import config, runner_vocab, store

sys.path.insert(0, str(config.ROOT / "scoring"))
from hyblis_scoring.policy import Policy, PolicyV2, compute, compute_v2  # noqa: E402

# Statuses safe to show publicly (no external-program information).
_PUBLIC_STATUS = {
    config.STATUS_RECEIVED: "received",
    config.STATUS_SCREENING: "screening",
    config.STATUS_REPRODUCING: "reproducing",
    config.STATUS_WAITING: "reproducing",   # internal wait for fork state or a runner retry
    config.STATUS_VALIDATED: "validated",
    config.STATUS_DUPLICATE: "duplicate",
    config.STATUS_FILED: "under_review",   # do not reveal which platform
    config.STATUS_ACCEPTED: "accepted",
    config.STATUS_REJECTED: "rejected",
    config.STATUS_EXPIRED: "expired",
}
# A researcher's hotkey is attached only to findings that earned credit; failed
# or pending attempts are never tied to a researcher in public.
_CREDITED = (config.STATUS_VALIDATED, config.STATUS_FILED, config.STATUS_ACCEPTED)
_RELEASED = ("featured", "open")
_TASK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_ADDR_FIND = re.compile(r"0x[0-9a-fA-F]{40}")          # the same pattern runner/policy_check.py scans for
_COMMIT_RE = re.compile(r"^[0-9a-f]{7,40}$")
_REF_RE = re.compile(r"^(@[A-Za-z0-9_.-]{1,64}|0x[0-9a-fA-F]{40})$")
_SIG_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,80}\([A-Za-z0-9_(),\[\]]{0,400}\)$")
_SYMBOL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,24}$")
_MAX_TASK_FILE = 64 * 1024
log = logging.getLogger("hyblis.publish")


def scores(now_ts: float | None = None) -> dict:
    now_day = store.to_day(now_ts if now_ts is not None else store.now())
    # scoring policy v2 (2026-11-23): the same shares the validator writes as weights
    return compute_v2(store.load_events(), now=now_day, policy=PolicyV2())


def public_ledger() -> list[dict]:
    rows = []
    for s in store.all_submissions():
        row = {
            "id": s["submission_id"][:16],          # a hash prefix is enough to look up
            "hash": s["submission_id"],
            "t": round(s["received_at"]),
            "status": _PUBLIC_STATUS.get(s["status"], "received"),
            "severity": s["severity_final"] or s["severity_claim"],
        }
        if s["status"] in _CREDITED:
            row["hotkey"] = s["hotkey"]
        rows.append(row)
    return rows


def leaderboard(now_ts: float | None = None) -> list[dict]:
    sc = scores(now_ts)
    miners = sc["miners"]
    # counts per hotkey from the private store (counts only, no amounts)
    accepted, validated, filed = {}, {}, {}
    for s in store.all_submissions():
        hk = s["hotkey"]
        if s["status"] == config.STATUS_ACCEPTED:
            accepted[hk] = accepted.get(hk, 0) + 1
        elif s["status"] == config.STATUS_VALIDATED:
            validated[hk] = validated.get(hk, 0) + 1
        elif s["status"] == config.STATUS_FILED:
            filed[hk] = filed.get(hk, 0) + 1
    hotkeys = set(miners) | set(accepted) | set(validated) | set(filed)
    board = []
    for hk in hotkeys:
        board.append({
            "hotkey": hk,
            "score": round(miners.get(hk, 0.0) * 10000, 2),   # score = share of pool x 10000
            "accepted": accepted.get(hk, 0),
            "validated": validated.get(hk, 0),
            "under_review": filed.get(hk, 0),
        })
    board.sort(key=lambda r: (-r["score"], -r["accepted"], r["hotkey"]))
    for i, r in enumerate(board, 1):
        r["rank"] = i
    return board


# ---- programs ---------------------------------------------------------------
def _releases() -> dict:
    """tasks/releases.json (public, in git) plus, when present, the private queue
    tasks/private-queue/releases.private.json (not in git): programs not yet released, so their names
    never appear in the public repository. Queued entries are never published either way."""
    rel_path = config.TASKS_DIR / "releases.json"
    if not rel_path.exists():
        return {}
    rel = json.loads(rel_path.read_text())
    priv = config.TASKS_DIR / "private-queue" / "releases.private.json"
    if priv.exists():
        extra = json.loads(priv.read_text()).get("tasks", [])
        rel["tasks"] = list(rel.get("tasks", [])) + [t for t in extra if isinstance(t, dict)]
    return rel


def task_track(task_id: str) -> str:
    """"warmup" for a warm-up program (releases.json "track": "warmup": reproducing a real past exploit on
    its historical state, never filed with a bounty program), else "discovery"."""
    for r in _releases().get("tasks", []):
        if isinstance(r, dict) and r.get("task_id") == task_id:
            return "warmup" if r.get("track") == "warmup" else "discovery"
    return "discovery"


def _has_manifest(task_id) -> bool:
    return (isinstance(task_id, str) and bool(_TASK_ID_RE.match(task_id))
            and (config.TASKS_DIR / task_id / "manifest.json").exists())


def _released(r) -> bool:
    """A releases.json entry that is published on this network: status featured or open, and, when
    the entry lists "networks", the current one (config.network()) among them. A "networks" value
    that is not a list of names releases nothing (a typo must not publish a program everywhere)."""
    if not isinstance(r, dict) or r.get("status") not in _RELEASED:
        return False
    nets = r.get("networks")
    if nets is None:
        return True
    return isinstance(nets, list) and config.network() in nets


DEFAULT_INTAKE_MESSAGE = "Intake opens at mainnet launch."


def launch_info() -> dict:
    """Whether report intake is open, and the public line shown while it is not.

    releases.json "launch": {"intake_open": bool, "message": str}. Without that block intake follows the
    programs' own ready flags (the behaviour before launch mode). config.intake_override() (the test
    suites and the testnet stack) opens it whatever the file says."""
    launch = _releases().get("launch")
    if isinstance(launch, dict):
        is_open = launch.get("intake_open") is True
        message = " ".join(str(launch.get("message") or "").split())[:200] or DEFAULT_INTAKE_MESSAGE
    else:
        is_open, message = True, DEFAULT_INTAKE_MESSAGE
    if config.intake_override():
        is_open = True
    return {"intake_open": is_open, "message": message}


def ready_task_ids() -> set[str]:
    """Task ids that can take reports: released on this network (featured/open) AND ready, AND having
    a manifest on disk. This is the authoritative accept-list for the gateway, so a
    scaffolded-but-unverified task (ready=false) cannot receive submissions; whether intake is open
    at all is launch_info()'s answer, checked by the gateway first. A ready program's hyblis check
    bundle is published while intake is still closed, so researchers can prepare."""
    out = set()
    for r in _releases().get("tasks", []):
        tid = r.get("task_id")
        if _released(r) and r.get("ready") and _has_manifest(tid):
            out.add(tid)
    return out


TASK_KEYS = ("task_id", "label", "status", "opened_at", "featured_until", "severity_scope",
             "scope_summary", "open_for_intake", "tags")      # the fields tasks_public() publishes


def tasks_public() -> list[dict]:
    """Released programs as researchers see them (the TASK_KEYS fields). Queued programs
    are NOT listed: the release queue is private until a program opens. Neither is a program
    released only on another network. open_for_intake = ready AND intake open."""
    out = []
    intake = launch_info()["intake_open"]
    for r in _releases().get("tasks", []):
        tid = r.get("task_id")
        if not _released(r) or not _has_manifest(tid):
            continue
        out.append({
            "task_id": tid,
            "label": str(r.get("label") or tid),
            "status": r["status"],
            "opened_at": r.get("opened_at"),
            "featured_until": r.get("featured_until"),
            "severity_scope": [s for s in (r.get("severity_scope") or []) if s in config.SEVERITIES],
            "scope_summary": str(r.get("scope_summary") or ""),
            "open_for_intake": bool(r.get("ready")) and intake,
            "tags": [str(t) for t in (r.get("tags") or [])][:6],
        })
    return out


def severity_scope(task_id: str) -> list[str]:
    """Severities a released program accepts (empty when the task is unknown)."""
    for t in tasks_public():
        if t["task_id"] == task_id:
            return t["severity_scope"]
    return []


def release_info(now_ts: float | None = None) -> dict:
    """The public release rhythm: how often programs open, when the next one is due, and whether
    intake is open (with the line shown while it is not). Says nothing about which programs are
    queued. While intake is closed there is no next release date: releases start at launch."""
    rel = _releases()
    cadence = rel.get("cadence", {})
    every = max(1, int(cadence.get("release_every_days", 7)))
    tasks = rel.get("tasks", [])
    launch = launch_info()
    opened = []
    for r in tasks:
        if _released(r) and r.get("opened_at"):
            try:
                opened.append(date.fromisoformat(r["opened_at"]))
            except ValueError:
                pass
    nxt = None
    if launch["intake_open"] and opened and any(r.get("status") == "queued" for r in tasks):
        today = datetime.fromtimestamp(now_ts if now_ts is not None else store.now(), tz=timezone.utc).date()
        nxt_d = max(opened) + timedelta(days=every)
        while nxt_d < today:                       # schedule slipped: show the next slot, never a past date
            nxt_d += timedelta(days=every)
        nxt = nxt_d.isoformat()
    return {"release_every_days": every, "next_release_on": nxt,
            "intake_closes": bool(cadence.get("intake_closes", False)),
            "intake_open": launch["intake_open"],
            "intake_message": None if launch["intake_open"] else launch["message"]}


def _task_file(task_id: str, rel, limit: int = _MAX_TASK_FILE) -> Path | None:
    """A file a task's manifest or spec names: relative to the repository ("tasks/<id>/..."), or
    absolute; only inside that task's own directory, a regular file of at most `limit` bytes."""
    if not isinstance(rel, str) or not rel or "\0" in rel:
        return None
    tdir = (config.TASKS_DIR / task_id).resolve()
    path = Path(rel)
    path = (path if path.is_absolute() else config.TASKS_DIR.parent / path).resolve()
    if tdir not in path.parents or not path.is_file() or path.stat().st_size > limit:
        return None
    return path


def _task_text(task_id: str, rel) -> str | None:
    p = _task_file(task_id, rel)
    return p.read_text() if p else None


def _verified_spec(task_id: str) -> dict | None:
    """The task's impact spec when the runner can judge with it: status verified, nothing pending.
    Until then nothing derived from it is published (a draft holds placeholders and work notes)."""
    try:
        spec = json.loads((config.TASKS_DIR / task_id / "impact-spec.json").read_text())
    except (OSError, ValueError):
        return None
    if (not isinstance(spec, dict) or spec.get("task_id") != task_id or spec.get("status") != "verified"
            or spec.get("pending_verification")):
        return None
    return spec


def _units(raw, decimals) -> str | None:
    """A raw token amount in whole units ("10000000000000", 6 -> "10,000,000")."""
    try:
        v = Fraction(int(str(raw)), 10 ** int(decimals))
    except (TypeError, ValueError):
        return None
    whole = v.numerator // v.denominator
    frac = v - whole
    text = f"{whole:,}"
    if frac:
        digits = str(frac.numerator * 10 ** int(decimals) // frac.denominator).rjust(int(decimals), "0").rstrip("0")
        text += "." + digits
    return text


def runner_terms(task_id: str) -> dict | None:
    """The program-specific runner rules a researcher needs (capital tokens and caps, the trusted
    helpers the program allows, time and size limits), from the verified impact spec only."""
    spec = _verified_spec(task_id)
    if spec is None:
        return None
    capital = []
    for t in spec.get("tokens") or []:
        if isinstance(t, dict) and t.get("capital") and _SYMBOL_RE.match(str(t.get("symbol", ""))) \
                and _ADDR_RE.match(str(t.get("address", ""))):
            capital.append({"symbol": t["symbol"], "address": t["address"],
                            "cap": _units(t.get("capital_cap"), t.get("decimals", 18))})
    as_role = []
    for a in spec.get("trusted_actions") or []:
        if isinstance(a, dict) and all(_REF_RE.match(str(a.get(k, ""))) for k in ("role", "target")) \
                and _SIG_RE.match(str(a.get("sig", ""))):
            as_role.append({"role": a["role"], "target": a["target"], "function": a["sig"],
                            "max_calls": a.get("max_calls") if type(a.get("max_calls")) is int else None})
    set_price = []
    for f in spec.get("price_feeds") or []:
        if isinstance(f, dict) and _REF_RE.match(str(f.get("feed", ""))) and type(f.get("max_move_bps")) is int:
            set_price.append({"feed": f["feed"], "token": str(f.get("token", ""))[:24], "max_move_bps": f["max_move_bps"]})
    lim = spec.get("limits") or {}
    limits = {k: lim[k] for k in ("max_warp_s", "max_roll", "max_steps", "max_attackers")
              if type(lim.get(k)) is int}
    return {"capital": capital[:20], "as_role": as_role[:30], "set_price": set_price[:30], "limits": limits}


def program_public(task_id: str) -> dict | None:
    """Everything a researcher needs to work on one released program. Built from a
    whitelist: nothing about the external platform or rewards is copied."""
    base = next((t for t in tasks_public() if t["task_id"] == task_id), None)
    if base is None:
        return None
    tdir = config.TASKS_DIR / task_id
    m = json.loads((tdir / "manifest.json").read_text())
    chain, code, policy, sub = m.get("chain", {}), m.get("code", {}), m.get("policy", {}), m.get("submission", {})
    rules_path = tdir / "program-rules.json"
    rules = json.loads(rules_path.read_text()) if rules_path.exists() else {}

    fork_block = chain.get("fork_block") if type(chain.get("fork_block")) is int else None
    assets = [{"name": str(k), "address": v} for k, v in (m.get("deployed") or {}).items()
              if isinstance(v, str) and _ADDR_RE.match(v)]
    sev_map = rules.get("severity_by_impact") or {}
    impacts = [{"impact": str(i), "severity": sev_map[i]} for i in (rules.get("in_scope_impacts") or [])
               if sev_map.get(i) in base["severity_scope"]]

    limits = policy.get("limits") or {}
    # Until the verification pass pins the fork block and the in-scope contracts, the program's template
    # is a scaffold (no block, no addresses): it is published with the verified scope, not before.
    pending = fork_block is None or not assets
    out = dict(base)
    out.update({
        "chain_id": chain.get("chain_id") if type(chain.get("chain_id")) is int else None,
        "fork_block": fork_block,
        "repo": code.get("repo") if isinstance(code.get("repo"), str) and code["repo"].startswith("https://") else None,
        "commit": code.get("commit") if _COMMIT_RE.match(str(code.get("commit", ""))) else None,
        "assets": assets,
        "poc_rules": [str(x) for x in (policy.get("rules") or [])][:12],
        "limits": {k: limits[k] for k in ("runtime_s", "memory_gb") if isinstance(limits.get(k), (int, float))},
        "trusted_roles": [str(x) for x in (rules.get("trusted_roles") or [])][:20],
        "in_scope_impacts": impacts,
        "out_of_scope": [str(x) for x in (rules.get("out_of_scope") or [])][:30],
        "poc_template": None if pending else _task_text(task_id, sub.get("poc_template")),
        "poc_base": _task_text(task_id, sub.get("poc_base")),
        "allowed_cheatcodes": [list(x) for x in runner_vocab.ALLOWED_CHEATCODES],
        "runner_terms": runner_terms(task_id),
        "check_tool": None,                        # set by the export when the bundle is published
        "verification_pending": pending,
    })
    return out


# ---- the hyblis check bundle ----------------------------------------------------------------------
# The researcher's local copy of the runner (runner/check.py), per released and ready program whose
# impact spec is verified. Strict whitelist: these runner files, and per task exactly the four files
# below. Security never depends on the runner files being secret (runner/README.md).
CHECK_RUNNER_FILES = ("check.py", "run_submission.py", "trace_verdict.py", "gen_spec.py",
                      "sanitize_foundry_toml.py", "policy_check.py", "vm_selectors.json")
CHECK_SOL_FILES = ("HyblisBase.sol", "HyblisHarness.t.sol", "HyblisRuntime.sol", "SHA256SUMS")
CHECK_TASK_FILES = ("manifest.json", "impact-spec.json", "poc/HyblisPoC.t.sol", "poc/HyblisBase.sol")


def check_bundle_members(task_id: str) -> list[str]:
    """The exact member list of a task's bundle, in archive order."""
    top = f"hyblis-check-{task_id}"
    return ([f"{top}/README.md"] + [f"{top}/runner/{n}" for n in CHECK_RUNNER_FILES]
            + [f"{top}/runner/sol/{n}" for n in CHECK_SOL_FILES]
            + [f"{top}/tasks/{task_id}/{n}" for n in CHECK_TASK_FILES])


def _abi_signatures(task_id: str, rel) -> list[str]:
    """Function signatures of an ABI file the spec names, as runner/gen_spec.py derives them."""
    p = _task_file(task_id, rel, limit=8 * 1024 * 1024)
    if p is None:
        raise ValueError(f"abi_file {rel!r} is not a file inside the task directory")
    data = json.loads(p.read_text())
    abi = data["abi"] if isinstance(data, dict) else data

    def typ(x):
        t = x["type"]
        if t.startswith("tuple"):
            return "(" + ",".join(typ(c) for c in x["components"]) + ")" + t[len("tuple"):]
        return t
    return [f"{i['name']}({','.join(typ(x) for x in i.get('inputs', []))})"
            for i in abi if isinstance(i, dict) and i.get("type") == "function"]


def check_spec(task_id: str, spec: dict) -> dict:
    """The impact spec as shipped: comments (keys starting with "_" or ending in "_note") removed and
    every abi_file replaced by the signatures it holds, appended to `functions` exactly as gen_spec
    reads them, so the spec compiles to the same thing without the ABI files."""
    def strip(v):
        if isinstance(v, dict):
            return {k: strip(x) for k, x in v.items() if not (k.startswith("_") or k.endswith("_note"))}
        if isinstance(v, list):
            return [strip(x) for x in v]
        return v
    out = strip(spec)
    out.pop("pending_verification", None)
    for c in out.get("in_scope") or []:
        if isinstance(c, dict) and "abi_file" in c:
            c["functions"] = list(c.get("functions") or []) + _abi_signatures(task_id, c.pop("abi_file"))
    return out


def check_manifest(task_id: str, m: dict) -> dict:
    """The manifest as shipped: only what runner/check.py reads. The fork (chain id and pinned block),
    every in-scope address the static screen looks for (runner/policy_check.py scans every string under
    "deployed" except "token" entries), and the PoC directory. No program, platform, rewards or notes."""
    chain = m.get("chain") or {}
    if type(chain.get("fork_block")) is not int or type(chain.get("chain_id")) is not int:
        raise ValueError("manifest has no pinned chain id and fork block")
    deployed = {}

    def walk(v, path):
        if isinstance(v, str):
            for i, a in enumerate(_ADDR_FIND.findall(v)):
                deployed[path + (f"#{i + 1}" if i else "")] = a
        elif isinstance(v, dict):
            for k, x in v.items():
                if k != "token":
                    walk(x, f"{path}.{k}" if path else str(k))
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, f"{path}[{i}]")
    walk(m.get("deployed") or {}, "")
    return {"task_id": task_id, "chain": {"chain_id": chain["chain_id"], "fork_block": chain["fork_block"]},
            "deployed": deployed, "submission": {"poc_dir": "test/hyblis"}}


def _check_readme(task_id: str, detail: dict) -> str:
    v, build = runner_vocab.FORGE_VERSION, runner_vocab.FOUNDRY_BUILD
    repo = detail.get("repo") or "the program's repository (see the program page)"
    at = f" at commit {detail['commit']}" if detail.get("commit") else ""
    return f"""# hyblis check: {detail['label']}

Run your proof of concept the way the Hyblis runner judges it, on your own machine, before you submit.
It is the runner's own code: the same harness, the same verdict engine and this program's impact spec.
You see the same verdict and the same reasons the runner gives.

## What you need

- Foundry {v} exactly (build {build}), installed with foundryup: forge and cast on your PATH.
  Any other version is refused.
- Python 3.11 or newer with eth-abi and eth-utils: python3 -m pip install eth-abi eth-utils
- The program's Foundry project: {repo}{at}, with its dependencies installed.
  Run forge build in it once, so the solc version it pins is installed under ~/.svm.
- Your own RPC for chain {detail.get('chain_id')} that serves block {detail.get('fork_block')}: an archive node you run, or
  anvil forked from it (anvil --fork-url <your archive node> --fork-block-number {detail.get('fork_block')}).
  Do not use a third-party RPC provider for an unreported bug: it sees every account and storage
  slot your proof reads.

## Commands

    tar xzf hyblis-check-{task_id}.tar.gz
    cd hyblis-check-{task_id}
    python3 runner/check.py --task {task_id} --poc /path/to/HyblisPoC.t.sol \\
        --project /path/to/the/program/project --rpc <your RPC URL or IPC path>

Start your proof from tasks/{task_id}/poc/HyblisPoC.t.sol and keep tasks/{task_id}/poc/HyblisBase.sol
beside it (as test/hyblis/ in the project, so plain forge test runs it too).
Add --json for the full verdict, --keep to keep forge's output. Exit code: 0 validated, 1 rejected,
2 could not run (check the setup above).

## What it checks

- Every cheatcode call, one by one, in Foundry's own trace. Only the allowed ones pass.
- Your proof runs twice, then once as plain forge test; the runs must agree.
- Impact is measured on the protocol itself, on the exploited fork and on a clean copy of the same
  block. Your asserts and logs are ignored.

It runs without the runner's network sandbox, and your RPC is yours, so a pass here is a strong signal,
not a promise: the runner's verdict on the submitted file is the one that counts.

## Files

- runner/: check.py and the runner files it uses (run_submission.py, trace_verdict.py, gen_spec.py,
  policy_check.py, sanitize_foundry_toml.py, vm_selectors.json, sol/).
- tasks/{task_id}/: impact-spec.json, manifest.json (the fields the check reads), poc/HyblisPoC.t.sol
  (the template) and poc/HyblisBase.sol.
"""


def _tar_gz(files: list[tuple[str, bytes]], mtime: int) -> bytes:
    """A gzip'd ustar archive of regular files only, with fixed owner, mode and time, so the same
    inputs always give the same bytes."""
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=mtime, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data in files:
                info = tarfile.TarInfo(name)
                info.size, info.mtime, info.mode = len(data), mtime, 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


_BUNDLE_CACHE: dict[str, tuple] = {}     # task_id -> (inputs key, bytes): exports run after every report


def check_bundle(task_id: str, detail: dict) -> bytes | None:
    """The bundle of one program, or None when it gets none (not ready, spec not verified). Rebuilt
    only when an input file (by path, size and modification time) or the README text changed."""
    if task_id not in ready_task_ids():
        return None
    spec = _verified_spec(task_id)
    if spec is None:
        return None
    tdir = config.TASKS_DIR / task_id
    m = json.loads((tdir / "manifest.json").read_text())
    sub = m.get("submission") or {}
    tpl, base = _task_file(task_id, sub.get("poc_template")), _task_file(task_id, sub.get("poc_base"))
    if tpl is None or base is None:
        raise ValueError("the manifest names no PoC template or HyblisBase.sol inside the task")
    runner = runner_vocab.RUNNER_DIR
    if base.read_bytes() != (runner / "sol" / "HyblisBase.sol").read_bytes():
        raise ValueError("the task's HyblisBase.sol differs from runner/sol/HyblisBase.sol")
    pins = dict(reversed(line.split()) for line in (runner / "sol" / "SHA256SUMS").read_text().splitlines() if line.strip())
    for name in ("HyblisBase.sol", "HyblisRuntime.sol", "HyblisHarness.t.sol"):   # check.py refuses files that differ
        if pins.get(name) != hashlib.sha256((runner / "sol" / name).read_bytes()).hexdigest():
            raise ValueError(f"runner/sol/{name} does not match runner/sol/SHA256SUMS")
    shipped = [runner / n for n in CHECK_RUNNER_FILES] + [runner / "sol" / n for n in CHECK_SOL_FILES]
    srcs = shipped + [tdir / "manifest.json", tdir / "impact-spec.json", tpl, base]
    abis = [_task_file(task_id, c["abi_file"], limit=8 * 1024 * 1024) for c in spec.get("in_scope") or []
            if isinstance(c, dict) and c.get("abi_file")]
    readme = _check_readme(task_id, detail)
    stats = [(p, p.stat()) for p in srcs + [a for a in abis if a is not None]]
    key = (readme, tuple((str(p), st.st_mtime_ns, st.st_size) for p, st in stats))
    hit = _BUNDLE_CACHE.get(task_id)
    if hit and hit[0] == key:
        return hit[1]
    mtime = int(max(st.st_mtime for _, st in stats))
    blobs = [readme.encode()] + [p.read_bytes() for p in shipped]
    blobs += [json.dumps(check_manifest(task_id, m), indent=1).encode() + b"\n",
              json.dumps(check_spec(task_id, spec), indent=1).encode() + b"\n",
              tpl.read_bytes(), base.read_bytes()]
    data = _tar_gz(list(zip(check_bundle_members(task_id), blobs)), mtime)
    _BUNDLE_CACHE[task_id] = (key, data)
    return data


def _export_check_bundle(task_id: str, detail: dict) -> dict | None:
    """Write data/check/<task_id>.tar.gz (only when its bytes changed); its public facts, or None."""
    try:
        data = check_bundle(task_id, detail)
    except Exception as e:                       # one program's broken pack must not stop the export
        log.warning("check bundle for %s not published: %s: %s", task_id, type(e).__name__, " ".join(str(e).split())[:300])
        return None
    if data is None:
        return None
    path = config.PUBLIC_DIR / "check" / f"{task_id}.tar.gz"
    try:
        same = path.read_bytes() == data
    except OSError:
        same = False
    if not same:
        _write(path, data)
    return {"path": f"data/check/{task_id}.tar.gz", "file": f"hyblis-check-{task_id}.tar.gz",
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "foundry": runner_vocab.FORGE_VERSION}


def settlement_info(now_ts: float | None = None) -> dict:
    """When the vault next settles. Amounts are private; the schedule is not."""
    now = now_ts if now_ts is not None else store.now()
    period = config.SETTLEMENT_PERIOD_DAYS
    day0 = store.epoch_day0()
    k = int((now - day0) // (period * 86400)) + 1
    return {"period_days": period, "next_at": round(day0 + k * period * 86400)}


def _write(path, text: str | bytes) -> None:
    """Replace `path` in one step: write a temporary file beside it, then rename it over
    the old one, so a reader gets the old file or the new one, never a partial one. The
    temporary name does not end in .json or .tar.gz, so no /data route and no sweep below sees it."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        if isinstance(text, bytes):
            tmp.write_bytes(text)
        else:
            tmp.write_text(text)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


_export_cond = threading.Condition()
_export_running = False
_export_next: dict | None = None      # the follow-up export that waiting callers share


def export_all(now_ts: float | None = None) -> dict:
    """Write every public file; returns what was written.

    Safe from several threads at once (the gateway exports after every submit and verdict):
    exports never overlap, so an older snapshot cannot replace a newer one, and the calls
    made while one runs share a single follow-up export. It starts after all of them were
    made, so it includes their changes: at most one export runs and one waits."""
    global _export_running, _export_next
    with _export_cond:
        ticket = None
        if _export_running or _export_next is not None:
            if _export_next is not None:             # a follow-up is already due: share its result
                ticket = _export_next
                _export_cond.wait_for(lambda: ticket["done"])
                if "error" in ticket:
                    raise ticket["error"]
                return ticket["data"]
            ticket = _export_next = {"done": False}  # run the follow-up when the current one ends
            _export_cond.wait_for(lambda: not _export_running)
            _export_next = None
        _export_running = True
    result = {}
    try:
        result["data"] = _export_files(now_ts)
    except BaseException as e:
        result["error"] = e
    with _export_cond:
        _export_running = False
        if ticket is not None:
            ticket.update(result, done=True)
        _export_cond.notify_all()
    if "error" in result:
        raise result["error"]
    return result["data"]


def _export_files(now_ts: float | None) -> dict:
    config.ensure_dirs()
    sc = scores(now_ts)
    ledger = public_ledger()
    board = leaderboard(now_ts)
    tasks = tasks_public()
    summary = {
        "pool": {"miners_share": round(sum(sc["miners"].values()), 6), "burn_share": round(sc["burn"], 6),
                 "pools": {k: round(v, 6) for k, v in (sc.get("pools") or {}).items()}, "policy": sc["policy"]},
        "counts": {
            "submissions": len(ledger),
            "validated": sum(1 for r in ledger if r["status"] in ("validated", "under_review", "accepted")),
            "accepted": sum(1 for r in ledger if r["status"] == "accepted"),
            "researchers": len(board),
            "open_programs": len(tasks),
        },
        "releases": release_info(now_ts),
        "settlement": settlement_info(now_ts),
        "generated_at": round(now_ts if now_ts is not None else store.now()),
    }
    data = {"ledger": ledger, "leaderboard": board, "tasks": tasks, "summary": summary}
    for name, payload in data.items():
        _write(config.PUBLIC_DIR / f"{name}.json", json.dumps(payload, indent=1))
    _write(config.PUBLIC_DIR / "scoring-policy.json", json.dumps(PolicyV2().__dict__, indent=1, default=str))

    pdir, cdir = config.PUBLIC_DIR / "programs", config.PUBLIC_DIR / "check"
    pdir.mkdir(parents=True, exist_ok=True)
    cdir.mkdir(parents=True, exist_ok=True)
    keep, keep_bundles = set(), set()
    for t in tasks:
        detail = program_public(t["task_id"])
        if detail is not None:
            detail["check_tool"] = _export_check_bundle(t["task_id"], detail)
            if detail["check_tool"]:
                keep_bundles.add(f"{t['task_id']}.tar.gz")
            _write(pdir / f"{t['task_id']}.json", json.dumps(detail, indent=1))
            keep.add(f"{t['task_id']}.json")
    for stale in pdir.glob("*.json"):              # a program that is no longer released disappears
        if stale.name not in keep:
            stale.unlink()
    for stale in cdir.glob("*.tar.gz"):            # and so does its bundle (also when it stops being ready)
        if stale.name not in keep_bundles:
            stale.unlink()
    data["pool"] = summary["pool"]                 # kept for older callers
    data["generated_at"] = summary["generated_at"]
    return data
