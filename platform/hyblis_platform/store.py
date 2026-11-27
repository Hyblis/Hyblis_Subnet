"""SQLite storage for the finding ledger.

Privacy boundary (docs/decisions.md, 2026-11-16):
  * PRIVATE (this DB only): full package/PoC, header text, measured impact,
    external platform name, program name, bounty amount, payout amount,
    reviewer identity, and the salted program bucket of the scoring events
    (a stable per-program id: published next to a report it would tell
    which program has open findings).
  * PUBLIC (exported to platform/public/): submission hash, received time,
    status, severity and a deterministic reputation score.

The store is synchronous; the async gateway calls it through a thread executor.
"""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from typing import Iterable, Optional

from . import config
from .canonical import digest, sha256_hex

SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
    submission_id   TEXT PRIMARY KEY,
    task_id         TEXT NOT NULL,
    hotkey          TEXT NOT NULL,
    received_at     REAL NOT NULL,
    status          TEXT NOT NULL,
    severity_claim  TEXT NOT NULL,
    severity_final  TEXT,
    title           TEXT NOT NULL,
    contract        TEXT NOT NULL,
    function        TEXT NOT NULL,
    description     TEXT NOT NULL,
    poc_sha256      TEXT NOT NULL,
    package_json    TEXT NOT NULL,          -- full signed package (private)
    envelope_sig    TEXT NOT NULL,          -- miner signature (see sig_scheme)
    sig_scheme      TEXT NOT NULL DEFAULT 'raw',  -- 'raw' | 'wallet-v1' (keys.py)
    policy_verdict  TEXT,                   -- PASS/FLAG/REJECT
    policy_json     TEXT,
    measured_json   TEXT,                   -- runner verdict (private)
    fingerprint     TEXT,                   -- measured dedup fingerprint
    dup_of          TEXT,                   -- submission_id this duplicates
    bounty_usd      REAL,                   -- private
    platform_ref    TEXT,                   -- private external reference
    filed_at        REAL,
    accepted_at     REAL,
    rejected_at     REAL,
    reject_reason   TEXT,                   -- 'invalid' | 'duplicate' | 'out_of_scope' | ...
    settle_period   INTEGER,                -- settlement period index once accepted
    updated_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_sub_fp ON submissions(fingerprint);
CREATE INDEX IF NOT EXISTS ix_sub_status ON submissions(status);
CREATE INDEX IF NOT EXISTS ix_sub_hotkey ON submissions(hotkey);

-- Receipts are retrievable only with a secret token handed to the miner at
-- submit time, never by the public submission_id. This keeps the receipt's
-- task_id/hotkey/poc_sha256 out of reach of anyone walking the public ledger.
CREATE TABLE IF NOT EXISTS receipts (
    submission_id   TEXT PRIMARY KEY,
    token           TEXT NOT NULL,
    received_at     REAL NOT NULL,
    payload_json    TEXT NOT NULL,
    server_sig      TEXT
);
CREATE INDEX IF NOT EXISTS ix_receipt_token ON receipts(token);

-- Public scoring event ledger (mirrors scoring.hyblis_scoring.policy.Event).
CREATE TABLE IF NOT EXISTS events (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    t           REAL NOT NULL,              -- days since EPOCH_DAY0
    kind        TEXT NOT NULL,
    finding     TEXT NOT NULL,
    program     TEXT NOT NULL,              -- opaque bucket id (never the real name)
    severity    TEXT NOT NULL,
    credit_json TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""


def now() -> float:
    return time.time()


@contextmanager
def _conn():
    config.ensure_dirs()
    c = sqlite3.connect(config.DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    try:
        yield c
        c.commit()
    finally:
        c.close()


def _ensure_column(c, table: str, column: str, decl: str) -> None:
    cols = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def init_db() -> None:
    with _conn() as c:
        c.executescript(SCHEMA)
        _ensure_column(c, "submissions", "sig_scheme", "TEXT NOT NULL DEFAULT 'raw'")
        _ensure_column(c, "submissions", "runner_attempts", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(c, "submissions", "wait_reason", "TEXT")
        _ensure_column(c, "submissions", "state_misses", "TEXT")
        if c.execute("SELECT v FROM meta WHERE k='epoch_day0'").fetchone() is None:
            # Day 0 for the scoring clock: fixed at first init so day math is stable.
            c.execute("INSERT INTO meta(k, v) VALUES('epoch_day0', ?)", (str(now()),))
        if c.execute("SELECT v FROM meta WHERE k='program_salt'").fetchone() is None:
            import secrets
            c.execute("INSERT INTO meta(k, v) VALUES('program_salt', ?)", (secrets.token_hex(16),))


def _meta(c, k: str, default: str = "") -> str:
    row = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return row["v"] if row else default


def epoch_day0() -> float:
    with _conn() as c:
        return float(_meta(c, "epoch_day0", str(now())))


def to_day(ts: float) -> float:
    return (ts - epoch_day0()) / 86400.0


def program_bucket(task_id: str) -> str:
    """Opaque, stable, salted id for a task, used as the program of the scoring
    events (the per-program limits group by it). Private: never exported."""
    with _conn() as c:
        salt = _meta(c, "program_salt", "")
    return sha256_hex((salt + "|" + task_id).encode())[:12]


# ---- writes ----------------------------------------------------------------
def add_submission(pkg: dict, envelope_sig: str, received_at: float, sid: str, sig_scheme: str = "raw",
                   receipt: Optional[tuple] = None) -> None:
    """Store a new submission. `receipt` = (token, payload_json, server_sig) is stored in
    the same transaction, so a stored report always has its receipt. Raises
    sqlite3.IntegrityError when the submission id is already stored."""
    h = pkg["header"]
    with _conn() as c:
        c.execute(
            """INSERT INTO submissions
               (submission_id, task_id, hotkey, received_at, status, severity_claim,
                title, contract, function, description, poc_sha256, package_json,
                envelope_sig, sig_scheme, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (sid, pkg["task_id"], pkg["hotkey"], received_at, config.STATUS_RECEIVED,
             h["severity"], h["title"], h["contract"].lower(), h["function"],
             h["description"], pkg["poc_sha256"],
             __import__("json").dumps(pkg, separators=(",", ":"), sort_keys=True, ensure_ascii=False),
             envelope_sig, sig_scheme, received_at),
        )
        if receipt is not None:
            token, payload_json, server_sig = receipt
            c.execute("INSERT INTO receipts VALUES (?,?,?,?,?)", (sid, token, received_at, payload_json, server_sig))


def save_receipt(sid: str, token: str, received_at: float, payload_json: str, server_sig: Optional[str]) -> None:
    with _conn() as c:
        c.execute("INSERT OR REPLACE INTO receipts VALUES (?,?,?,?,?)",
                  (sid, token, received_at, payload_json, server_sig))


def receipt_by_token(token: str) -> Optional[dict]:
    """Look up a receipt by its secret token (not by submission_id)."""
    with _conn() as c:
        row = c.execute("SELECT payload_json, server_sig FROM receipts WHERE token=?", (token,)).fetchone()
        return {"payload": __import__("json").loads(row["payload_json"]), "server_sig": row["server_sig"]} if row else None


def receipt_for(sid: str) -> Optional[dict]:
    """The stored receipt of a submission, token included. Only for answering a resend of
    the same signed package (whoever holds that envelope already submitted it)."""
    with _conn() as c:
        row = c.execute("SELECT token, received_at, server_sig FROM receipts WHERE submission_id=?", (sid,)).fetchone()
        return dict(row) if row else None


def set_status(sid: str, status: str, **fields) -> None:
    cols = ", ".join(f"{k}=?" for k in fields)
    sets = (cols + ", " if cols else "") + "status=?, updated_at=?"
    vals = list(fields.values()) + [status, now(), sid]
    with _conn() as c:
        c.execute(f"UPDATE submissions SET {sets} WHERE submission_id=?", vals)


def get(sid: str) -> Optional[dict]:
    with _conn() as c:
        row = c.execute("SELECT * FROM submissions WHERE submission_id=?", (sid,)).fetchone()
        return dict(row) if row else None


def find_by_prefix(prefix: str) -> Optional[dict]:
    """The single submission whose id starts with `prefix` (lower-case hex, at
    least 12 characters). None when there is no match or the prefix is ambiguous."""
    prefix = prefix.lower()
    if len(prefix) < 12 or len(prefix) > 64 or any(ch not in "0123456789abcdef" for ch in prefix):
        return None
    with _conn() as c:
        rows = c.execute("SELECT * FROM submissions WHERE submission_id >= ? AND submission_id < ? LIMIT 2",
                         (prefix, prefix + "g")).fetchall()
        return dict(rows[0]) if len(rows) == 1 else None


def warmup_prior(task_id: str, exclude_sid: str, hotkey: str, poc_sha256: str) -> Optional[dict]:
    """An earlier validated reproduction of the same warm-up program by this hotkey, or of the same
    proof file by any hotkey."""
    with _conn() as c:
        r = c.execute("SELECT * FROM submissions WHERE task_id=? AND submission_id!=? AND status=? "
                      "AND (hotkey=? OR poc_sha256=?) ORDER BY received_at, submission_id LIMIT 1",
                      (task_id, exclude_sid, config.STATUS_VALIDATED, hotkey, poc_sha256)).fetchone()
        return dict(r) if r else None


def list_by_status(status: str) -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM submissions WHERE status=? ORDER BY received_at", (status,))]


def locked_same_fp(fingerprint: str, exclude_sid: str, task_id: Optional[str] = None,
                   poc_sha256: Optional[str] = None) -> Optional[dict]:
    """A same-fingerprint finding that is already filed or accepted. Once a finding
    is filed externally it is the canonical one and cannot be demoted, so any later
    (even earlier-received) submission of the same bug is a duplicate of it.
    With task_id and poc_sha256, a finding of that task with the same PoC also counts
    as the same bug, whatever its fingerprint."""
    locked = (config.STATUS_FILED, config.STATUS_ACCEPTED)
    qmarks = ",".join("?" * len(locked))
    with _conn() as c:
        row = c.execute(
            f"""SELECT * FROM submissions
                WHERE (fingerprint=? OR (task_id=? AND poc_sha256=?)) AND submission_id<>?
                  AND status IN ({qmarks})
                ORDER BY received_at ASC, submission_id ASC LIMIT 1""",
            (fingerprint, task_id, poc_sha256, exclude_sid, *locked)).fetchone()
        return dict(row) if row else None


def earliest_validated(fingerprint: str, exclude_sid: str, task_id: Optional[str] = None,
                       poc_sha256: Optional[str] = None) -> Optional[dict]:
    """The currently-validated (not yet filed) same-fingerprint finding with the
    earliest (received_at, submission_id). Used to settle 'first valid wins' even
    when verdicts arrive out of order. task_id and poc_sha256 as in locked_same_fp."""
    with _conn() as c:
        row = c.execute(
            """SELECT * FROM submissions
               WHERE (fingerprint=? OR (task_id=? AND poc_sha256=?)) AND submission_id<>? AND status=?
               ORDER BY received_at ASC, submission_id ASC LIMIT 1""",
            (fingerprint, task_id, poc_sha256, exclude_sid, config.STATUS_VALIDATED)).fetchone()
        return dict(row) if row else None


def append_event(t_day: float, kind: str, finding: str, program_bucket_id: str,
                 severity: str, credit: list) -> None:
    import json
    with _conn() as c:
        c.execute(
            """INSERT INTO events (t, kind, finding, program, severity, credit_json, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (t_day, kind, finding, program_bucket_id, severity, json.dumps(credit), now()))


def load_events() -> list:
    """Return scoring.hyblis_scoring.policy.Event objects for the public ledger."""
    import json
    import sys
    from pathlib import Path
    sys.path.insert(0, str(config.ROOT / "scoring"))
    from hyblis_scoring.policy import Event  # type: ignore
    out = []
    with _conn() as c:
        for r in c.execute("SELECT * FROM events ORDER BY t, seq"):
            if r["kind"] == "support":           # warm-up reproduction: one point for its miner
                hk = json.loads(r["credit_json"])[0][0]
                out.append(Event(t=r["t"], kind="support", finding=r["finding"], miner=hk, points=1.0, seq=r["seq"]))
                continue
            out.append(Event(t=r["t"], kind=r["kind"], finding=r["finding"], program=r["program"],
                             severity=r["severity"], credit=tuple(tuple(x) for x in json.loads(r["credit_json"])),
                             seq=r["seq"]))
    return out


def all_submissions() -> list[dict]:
    with _conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM submissions ORDER BY received_at")]
