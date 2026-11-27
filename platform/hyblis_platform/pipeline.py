"""Submission lifecycle: static screen -> dispatch to the runner -> verdict ->
dedup -> (operator files) -> platform outcome -> settlement eligibility.

Scoring events mirror scoring.hyblis_scoring.policy.Event so the public
leaderboard is exactly the published scoring code applied to the public ledger.
The *finding id* is the submission_id of the first valid submission; a program
is recorded only as its opaque bucket id.
"""
from __future__ import annotations

import json
import logging
import re
import subprocess
import sys
import threading

from . import config, publish, runner_vocab, store
from .dedup import fingerprint

SEV_ORDER = {s: i for i, s in enumerate(config.SEVERITIES)}
log = logging.getLogger("hyblis.pipeline")

# The static policy checker runs as its own process (runner/policy_check.py), so a PoC that
# is slow to check can never stall the gateway, and it gets a hard time limit.
POLICY_CHECK = config.ROOT / "runner" / "policy_check.py"
SCREEN_TIMEOUT_S = 10
_SCREEN_SLOTS = threading.BoundedSemaphore(2)          # at most two screens at once
_EXIT_CODES = {"PASS": 0, "FLAG": 1, "REJECT": 2}
MAX_POLICY_REASONS = 20                                 # shown to the submitter


def min_severity(a: str, b: str) -> str:
    return a if SEV_ORDER[a] <= SEV_ORDER[b] else b


def _policy_check(task_id: str, poc: str) -> tuple[str, list]:
    """(verdict, findings) of runner/policy_check.py for this PoC. A check that runs over
    SCREEN_TIMEOUT_S or fails in any way is a REJECT with that reason (and one log line)."""
    def failed(reason, detail):
        log.warning("%s (task %s, %d bytes): %s", reason, task_id, len(poc), " ".join(str(detail).split())[:300])
        return "REJECT", [{"level": "REJECT", "reason": reason, "line": None}]

    manifest = config.TASKS_DIR / task_id / "manifest.json"
    with _SCREEN_SLOTS:
        try:
            # -I: no PYTHON* variables, no user site, no script directory on sys.path
            p = subprocess.run([sys.executable, "-I", str(POLICY_CHECK), str(manifest), "-"],
                               input=poc.encode("utf-8"), capture_output=True, env={},
                               timeout=SCREEN_TIMEOUT_S)
        except subprocess.TimeoutExpired:        # the child has been killed
            return failed("policy check timed out", f"over {SCREEN_TIMEOUT_S} s")
        except Exception as e:
            return failed("policy check failed", f"{type(e).__name__}: {e}")
    try:
        out = json.loads(p.stdout)
        verdict, findings = out["verdict"], out["findings"]
    except (ValueError, TypeError, KeyError):
        verdict = findings = None
    if not isinstance(verdict, str) or _EXIT_CODES.get(verdict) != p.returncode or not isinstance(findings, list):
        last = (p.stderr.decode("utf-8", "replace").strip().splitlines() or ["no error output"])[-1]
        return failed("policy check failed", f"exit {p.returncode}: {last}")
    return verdict, findings


def screen(sid: str) -> str:
    """Run the static policy pre-filter (safe, no PoC execution). Returns the new
    status. REJECT -> rejected; PASS/FLAG -> screening (queued for the runner)."""
    sub = store.get(sid)
    if not sub or sub["status"] != config.STATUS_RECEIVED:
        return sub["status"] if sub else "missing"
    pkg = json.loads(sub["package_json"])
    verdict, findings = _policy_check(sub["task_id"], pkg["poc"])
    pj = json.dumps({"verdict": verdict, "findings": findings}, separators=(",", ":"))
    if verdict == "REJECT":
        store.set_status(sid, config.STATUS_REJECTED, policy_verdict=verdict, policy_json=pj,
                         reject_reason="policy", rejected_at=store.now())
        return config.STATUS_REJECTED
    store.set_status(sid, config.STATUS_SCREENING, policy_verdict=verdict, policy_json=pj)
    return config.STATUS_SCREENING


def queue_unscreened(sid: str) -> str:
    """For a report the screen could not process: queue it for the runner anyway rather
    than leave it in 'received', which nothing picks up. The runner runs the same policy
    check before it executes anything. Returns the status."""
    sub = store.get(sid)
    if sub and sub["status"] == config.STATUS_RECEIVED:
        store.set_status(sid, config.STATUS_SCREENING)
        return config.STATUS_SCREENING
    return sub["status"] if sub else "missing"


def policy_reasons(sub: dict) -> list[dict] | None:
    """Why the intake screen rejected this report, as [{reason, line}] (REJECT findings only,
    at most MAX_POLICY_REASONS); None when it did not reject it. For the submitter only:
    the reasons describe their own PoC against the published rules."""
    if sub["status"] != config.STATUS_REJECTED or sub.get("reject_reason") != "policy":
        return None
    try:
        findings = json.loads(sub.get("policy_json") or "{}").get("findings") or []
    except (ValueError, AttributeError):
        findings = []
    out = [{"reason": str(f.get("reason", "")), "line": f.get("line") if type(f.get("line")) is int else None}
           for f in findings if isinstance(f, dict) and f.get("level") == "REJECT"]
    return out[:MAX_POLICY_REASONS]


# ---- the submitter's own result (GET /api/receipt/<token>; never on a public surface) ----------------
# Codes the platform itself sets (the runner's codes and texts come from runner_vocab.ERRORS).
PLATFORM_REASONS = {
    "not_accepted": "The report passed validation, but it was turned down in the review after validation "
                    "or by the bounty platform. It earns no credit.",
    "platform_duplicate": "The report passed validation, but the bounty platform matched it to an earlier "
                          "report of the same bug. It earns no credit.",
    "duplicate": "An earlier report of the same bug (same contract, function and impact type) was received "
                 "first. The earliest valid report takes the credit.",
    "expired": "The report passed validation, but no platform outcome arrived before the cut-off.",
    "not_reproduced": "The runner did not validate the report.",
}
_FINISHED = (config.STATUS_VALIDATED, config.STATUS_DUPLICATE, config.STATUS_FILED, config.STATUS_ACCEPTED,
             config.STATUS_REJECTED, config.STATUS_EXPIRED)
_CODE_RE = re.compile(r"^[a-z_]{1,40}(:[A-Za-z0-9_(),\[\]]{1,160})?$")
_FN_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,80}(\([A-Za-z0-9_(),\[\]]{0,400}\))?$")
_IMPACTS = ("funds_loss", "unauthorized_mint", "insolvency", "funds_freeze", "griefing", "accounting_error", "dos")
_CTRL = re.compile(r"[\x00-\x1f\x7f]+")
MAX_DETAIL = 300


def _clean(text, limit: int) -> str:
    """One line of plain text, at most `limit` characters (shown escaped by the site)."""
    return _CTRL.sub(" ", str(text if text is not None else "")).strip()[:limit]


def _runner_error(verdict: dict) -> str:
    """The rejection code of a negative runner verdict, from the runner's fixed vocabulary only."""
    code = verdict.get("error")
    if isinstance(code, str) and _CODE_RE.match(code) and code.split(":", 1)[0] in runner_vocab.ERRORS:
        return code
    if code:                                   # not a code the runner defines: say nothing more
        return "not_reproduced"
    if verdict.get("reproduced") and not verdict.get("deterministic"):
        return "nondeterministic"
    return "no_impact"


def _policy_lines(items) -> list[dict]:
    out = []
    for f in items if isinstance(items, list) else []:
        if isinstance(f, dict) and f.get("reason"):
            line = f.get("line") if type(f.get("line")) is int and f.get("line") > 0 else None
            out.append({"reason": _clean(f["reason"], 200), "line": line})
    return out[:MAX_POLICY_REASONS]


def researcher_result(sub: dict) -> dict | None:
    """What the submitter may see about their own report once it is decided, for the receipt endpoint
    (the secret receipt token is the only way in). None while it is still in progress; only
    {"status": "waiting"} while it waits for the runner (no detail: the reason is operational).

    Shape: {status, error, explanation, detail, policy: [{reason, line}]} plus, when the runner
    validated the proof, {impact_type, measured_severity, changed_function}. `status` uses the public
    names (a filed report is "under_review"), `error` is a code from the runner's fixed vocabulary or
    one of PLATFORM_REASONS, `explanation` is the fixed text for that code, and `detail` is the
    runner's own note (runner-written; never text from the PoC). Never anything about the program's
    external platform, amounts, other people's reports or which report a duplicate matched."""
    status = sub.get("status")
    if status == config.STATUS_WAITING:
        return {"status": "waiting"}
    if status not in _FINISHED:
        return None
    try:
        verdict = json.loads(sub.get("measured_json") or "{}")
    except ValueError:
        verdict = {}
    if not isinstance(verdict, dict):
        verdict = {}
    out = {"status": publish._PUBLIC_STATUS.get(status, "received"), "error": None, "explanation": "", "detail": "",
           "policy": []}
    if status == config.STATUS_REJECTED and sub.get("reject_reason") == "policy":
        # the intake screen (runner/policy_check.py as its own process) rejected it
        out.update(error="screen", explanation=runner_vocab.explain("screen"),
                   policy=_policy_lines(policy_reasons(sub)))
        return out
    if status == config.STATUS_REJECTED and sub.get("reject_reason") == "not_reproduced":
        code = _runner_error(verdict)
        out.update(error=code, explanation=runner_vocab.explain(code) or PLATFORM_REASONS["not_reproduced"],
                   detail=_clean(verdict.get("detail"), MAX_DETAIL) if code != "not_reproduced" else "",
                   policy=_policy_lines(verdict.get("policy")))
        return out
    # the runner validated the proof; what came after is the platform's own decision
    if status == config.STATUS_REJECTED:
        code = "platform_duplicate" if sub.get("reject_reason") == "duplicate" else "not_accepted"
        out.update(error=code, explanation=PLATFORM_REASONS[code])
    elif status == config.STATUS_DUPLICATE:
        out.update(error="duplicate", explanation=PLATFORM_REASONS["duplicate"])
    elif status == config.STATUS_EXPIRED:
        out.update(error="expired", explanation=PLATFORM_REASONS["expired"])
    if verdict.get("reproduced") and verdict.get("impact_type"):
        fn = verdict.get("changed_function")
        out.update(
            impact_type=verdict["impact_type"] if verdict["impact_type"] in _IMPACTS else None,
            measured_severity=verdict.get("measured_severity") if verdict.get("measured_severity") in config.SEVERITIES else None,
            changed_function=fn if isinstance(fn, str) and _FN_RE.match(fn) else None)
    return out


def claim_for_runner() -> dict | None:
    """Atomically take the oldest screened submission and mark it reproducing.
    Returns the job the runner needs (package + task id), or None."""
    pending = store.list_by_status(config.STATUS_SCREENING)
    if not pending:
        return None
    sub = pending[0]
    store.set_status(sub["submission_id"], config.STATUS_REPRODUCING)
    pkg = json.loads(sub["package_json"])
    return {
        "submission_id": sub["submission_id"],
        "task_id": sub["task_id"],
        "poc": pkg["poc"],
        "header": pkg["header"],
        "policy_verdict": sub["policy_verdict"],
    }


def on_verdict(sid: str, verdict: dict) -> str:
    """Process a runner verdict. Expected shape:
        {"reproduced": bool, "deterministic": bool,
         "impact_type": str, "measured_severity": "low|..|critical",
         "changed_function": str, "changed_contract": str, "evidence": {...}, "error": str?}
    changed_contract/changed_function are what the runner measured (its impact anchor), never the header's.
    """
    sub = store.get(sid)
    if not sub or sub["status"] != config.STATUS_REPRODUCING:
        return sub["status"] if sub else "missing"
    mj = json.dumps(verdict, separators=(",", ":"), sort_keys=True)

    # Runner problems that say nothing about the proof are retried, never held against it.
    err = verdict.get("error") or ""
    if err in config.RUNNER_RETRY_ERRORS:
        return _hold_for_retry(sub, err, verdict, mj)

    ok = bool(verdict.get("reproduced")) and bool(verdict.get("deterministic")) and bool(verdict.get("impact_type"))
    if not ok:
        store.set_status(sid, config.STATUS_REJECTED, measured_json=mj,
                         reject_reason="not_reproduced", rejected_at=store.now())
        return config.STATUS_REJECTED

    # 'Same bug' is keyed only on what the runner MEASURED: the in-scope contract and function whose
    # state backs the impact. The miner's header never steers dedup; a positive verdict without
    # them is a runner fault, retried like one.
    if not verdict.get("changed_contract") or not verdict.get("changed_function"):
        return _hold_for_retry(sub, "runner_error", dict(verdict, error="runner_error",
                               detail="validated verdict without a measured contract and function"), mj)
    sev = min_severity(sub["severity_claim"], verdict.get("measured_severity", sub["severity_claim"]))
    fp = fingerprint(sub["task_id"], verdict["changed_contract"], verdict["changed_function"], verdict["impact_type"])
    if publish.task_track(sub["task_id"]) == "warmup":
        return _warmup_validated(sub, sev, fp, mj)
    this_key = (sub["received_at"], sid)

    # Dedup, 'first valid wins', correct even when verdicts arrive out of order:
    #  1) if a same-bug finding is already filed/accepted, it is locked -> this is a duplicate;
    #  2) else if an earlier-received validated finding exists -> this is a duplicate of it;
    #  3) else this wins, and any LATER validated finding of the same bug is demoted to duplicate.
    # 'Same bug' = same fingerprint, or the same PoC for the same task. The fingerprint uses the runner's
    # measured changed_contract and changed_function (never the header's contract, which the miner chooses);
    # the PoC hash also catches the same file resubmitted.
    locked = store.locked_same_fp(fp, sid, sub["task_id"], sub["poc_sha256"])
    if locked:
        store.set_status(sid, config.STATUS_DUPLICATE, measured_json=mj, fingerprint=fp,
                         severity_final=sev, dup_of=locked["submission_id"])
        return config.STATUS_DUPLICATE

    earlier = store.earliest_validated(fp, sid, sub["task_id"], sub["poc_sha256"])
    if earlier and (earlier["received_at"], earlier["submission_id"]) <= this_key:
        store.set_status(sid, config.STATUS_DUPLICATE, measured_json=mj, fingerprint=fp,
                         severity_final=sev, dup_of=earlier["submission_id"])
        return config.STATUS_DUPLICATE

    store.set_status(sid, config.STATUS_VALIDATED, measured_json=mj, fingerprint=fp, severity_final=sev)
    # provisional points decay from the APPROVAL time, not from submission time.
    store.append_event(store.to_day(store.now()), "approved", sid,
                       store.program_bucket(sub["task_id"]), sev, [[sub["hotkey"], 1.0]])
    if earlier:
        # `earlier` was validated first but is actually the LATER submission -> demote it.
        store.set_status(earlier["submission_id"], config.STATUS_DUPLICATE, dup_of=sid)
        store.append_event(store.to_day(store.now()), "revoked", earlier["submission_id"],
                           store.program_bucket(earlier["task_id"]),
                           earlier["severity_final"] or earlier["severity_claim"], [[earlier["hotkey"], 1.0]])
    return config.STATUS_VALIDATED


def _warmup_validated(sub: dict, sev: str, fp: str, mj: str) -> str:
    """Warm-up track: every miner who reproduces the known exploit earns once (a "support" event for the
    warm-up pool); nothing is filed. A second reproduction by the same hotkey, or the same proof file
    already validated for another hotkey (a copy), is a duplicate and earns nothing."""
    sid = sub["submission_id"]
    prior = store.warmup_prior(sub["task_id"], sid, sub["hotkey"], sub["poc_sha256"])
    if prior:
        store.set_status(sid, config.STATUS_DUPLICATE, measured_json=mj, fingerprint=fp,
                         severity_final=sev, dup_of=prior["submission_id"])
        return config.STATUS_DUPLICATE
    store.set_status(sid, config.STATUS_VALIDATED, measured_json=mj, fingerprint=fp, severity_final=sev)
    store.append_event(store.to_day(store.now()), "support", sid, store.program_bucket(sub["task_id"]), sev,
                       [[sub["hotkey"], 1.0]])
    return config.STATUS_VALIDATED


def _merge_misses(old_json: str | None, new: list) -> str:
    """Union of missing fork-state items, stable order, bounded."""
    try:
        old = json.loads(old_json or "[]")
    except ValueError:
        old = []
    seen, out = set(), []
    for m in list(old if isinstance(old, list) else []) + list(new if isinstance(new, list) else []):
        key = json.dumps(m, sort_keys=True, separators=(",", ":"))
        if key not in seen:
            seen.add(key)
            out.append(m)
    return json.dumps(out[:5000], separators=(",", ":"), sort_keys=True)


def _hold_for_retry(sub: dict, err: str, verdict: dict, mj: str) -> str:
    """state_miss: wait until the operator extends the program's snapshot (release_waiting).
    Other runner errors: back to the queue, at most RUNNER_MAX_ATTEMPTS times, then wait."""
    sid = sub["submission_id"]
    attempts = int(sub.get("runner_attempts") or 0) + 1
    if err == "state_miss":
        # A run stops at its first missing read, so an honest job reports a handful of items; cap what
        # one job can add so it cannot crowd the program's extend list.
        mine = list(verdict.get("state_misses") or [])[:config.RUNNER_MAX_MISSES_PER_JOB]
        store.set_status(sid, config.STATUS_WAITING, measured_json=mj, runner_attempts=attempts,
                         wait_reason="state", state_misses=_merge_misses(sub.get("state_misses"), mine))
        return config.STATUS_WAITING
    if attempts < config.RUNNER_MAX_ATTEMPTS:
        store.set_status(sid, config.STATUS_SCREENING, measured_json=mj, runner_attempts=attempts)
        return config.STATUS_SCREENING
    store.set_status(sid, config.STATUS_WAITING, measured_json=mj, runner_attempts=attempts, wait_reason="runner")
    return config.STATUS_WAITING


def pending_state_misses(task_id: str) -> list:
    """Every fork-state item that waiting jobs of this program could not read: the input for
    `runner/state/snapshot.py extend`. Operator only (the list says where exploits look)."""
    merged = "[]"
    for sub in store.list_by_status(config.STATUS_WAITING):
        if sub["task_id"] == task_id and sub.get("wait_reason") == "state":
            merged = _merge_misses(merged, json.loads(sub.get("state_misses") or "[]"))
    return json.loads(merged)


def release_waiting(task_id: str, reason: str = "state") -> list[str]:
    """Send this program's waiting jobs back to the runner queue (after the snapshot was
    extended, or after a runner fault was fixed). Returns the released submission ids."""
    out = []
    for sub in store.list_by_status(config.STATUS_WAITING):
        if sub["task_id"] == task_id and (sub.get("wait_reason") or "") == reason:
            store.set_status(sub["submission_id"], config.STATUS_SCREENING, wait_reason=None,
                             runner_attempts=0 if reason == "runner" else sub.get("runner_attempts") or 0)
            out.append(sub["submission_id"])
    return out


class IllegalTransition(Exception):
    pass


def mark_filed(sid: str, platform_ref: str) -> None:
    """Operator records that the report was filed on the external platform.
    Only a validated finding may be filed."""
    sub = store.get(sid)
    if not sub:
        raise IllegalTransition(f"{sid}: not found")
    if sub["status"] != config.STATUS_VALIDATED:
        raise IllegalTransition(f"{sid}: can only file a validated finding, not {sub['status']}")
    store.set_status(sid, config.STATUS_FILED, platform_ref=platform_ref, filed_at=store.now())


def platform_accepted(sid: str, bounty_usd: float, period: int | None = None) -> None:
    sub = store.get(sid)
    if not sub:
        raise IllegalTransition(f"{sid}: not found")
    if sub["status"] != config.STATUS_FILED:
        # only a filed finding earns a payout; this blocks accepting a duplicate/rejected one
        raise IllegalTransition(f"{sid}: can only accept a filed finding, not {sub['status']}")
    if period is None:
        period = int(store.to_day(store.now()) // config.SETTLEMENT_PERIOD_DAYS)
    store.set_status(sid, config.STATUS_ACCEPTED, accepted_at=store.now(),
                     bounty_usd=bounty_usd, settle_period=period)
    sev = sub["severity_final"] or sub["severity_claim"]
    # paid event: confirms the provisional finding at full points and restarts decay.
    store.append_event(store.to_day(store.now()), "paid", sid,
                       store.program_bucket(sub["task_id"]), sev, [[sub["hotkey"], 1.0]])


def platform_rejected(sid: str, reason: str = "invalid") -> None:
    sub = store.get(sid)
    if not sub:
        raise IllegalTransition(f"{sid}: not found")
    if sub["status"] not in (config.STATUS_FILED, config.STATUS_VALIDATED):
        raise IllegalTransition(f"{sid}: can only reject a filed/validated finding, not {sub['status']}")
    store.set_status(sid, config.STATUS_REJECTED, rejected_at=store.now(), reject_reason=reason)
    if reason == "invalid":
        store.append_event(store.to_day(store.now()), "rejected_invalid", sid,
                           store.program_bucket(sub["task_id"]),
                           sub["severity_final"] or sub["severity_claim"], [[sub["hotkey"], 1.0]])
    else:
        store.append_event(store.to_day(store.now()), "rejected_duplicate", sid,
                           store.program_bucket(sub["task_id"]),
                           sub["severity_final"] or sub["severity_claim"], [[sub["hotkey"], 1.0]])


def expire_stale() -> int:
    """Move findings with no platform outcome past the cut-off to expired."""
    n = 0
    cutoff = store.now() - config.CUTOFF_DAYS * 86400
    for status in (config.STATUS_VALIDATED, config.STATUS_FILED):
        for sub in store.list_by_status(status):
            if sub["received_at"] < cutoff:
                store.set_status(sub["submission_id"], config.STATUS_EXPIRED)
                store.append_event(store.to_day(store.now()), "revoked", sub["submission_id"],
                                   store.program_bucket(sub["task_id"]),
                                   sub["severity_final"] or sub["severity_claim"], [[sub["hotkey"], 1.0]])
                n += 1
    return n
