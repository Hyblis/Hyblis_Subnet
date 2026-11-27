"""Static configuration: paths, ports, constants. No I/O, no secrets.

Secrets (the internal dispatch token, the server signing key) come from env vars
loaded by env.sh / the start scripts, never from this file.
"""
from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path

# ---- paths -----------------------------------------------------------------
ROOT = Path(os.environ.get("HYBLIS_ROOT", str(Path(__file__).resolve().parents[2])))   # the repository root
DATA_DIR = Path(os.environ.get("HYBLIS_DATA_DIR", str(ROOT / "platform" / "data")))   # private DB (git-ignored)
PUBLIC_DIR = Path(os.environ.get("HYBLIS_PUBLIC_DIR", str(ROOT / "platform" / "public")))  # public JSON exports
SITE_DIR = ROOT / "platform" / "site"          # static front-end
# task packs (manifest, impact spec, PoC template); HYBLIS_TASKS_DIR only for test fixtures, whose
# manifests name their files as "tasks/<id>/...", so the directory must be called "tasks"
TASKS_DIR = Path(os.environ.get("HYBLIS_TASKS_DIR", str(ROOT / "tasks")))
RUN_DIR = ROOT / "run"
LOG_DIR = ROOT / "logs"

DB_PATH = DATA_DIR / "hyblis.db"

# ---- ports (see docs/ports.md; reserved block 9850-9869, 127.0.0.1 only) ----
HOST = "127.0.0.1"
GATEWAY_PORT = int(os.environ.get("HYBLIS_GATEWAY_PORT", 9850))   # miner + internal + public API
SITE_PORT = int(os.environ.get("HYBLIS_SITE_PORT", 9851))        # static site

# ---- domain model ----------------------------------------------------------
SEVERITIES = ("low", "medium", "high", "critical")

# Submission lifecycle (public statuses on the ledger).
STATUS_RECEIVED = "received"       # signed, stored, awaiting static policy check
STATUS_SCREENING = "screening"     # static policy PASS/FLAG; queued for the runner
STATUS_REPRODUCING = "reproducing" # dispatched to the isolated runner
STATUS_VALIDATED = "validated"     # reproduced with measured impact; eligible to file
STATUS_DUPLICATE = "duplicate"     # a valid earlier submission has the same fingerprint
STATUS_FILED = "filed"             # submitted to the bounty platform by the operator
STATUS_ACCEPTED = "accepted"       # platform accepted; counts for settlement
STATUS_REJECTED = "rejected"       # platform rejected, or failed reproduction/policy
STATUS_EXPIRED = "expired"         # no platform outcome before the cut-off
STATUS_WAITING = "waiting"         # INTERNAL: the runner needs more fork state, or the runner failed;
                                   # shown publicly as "reproducing". Released back to screening.

# Runner errors that say nothing about the proof itself: the job is retried, never rejected.
RUNNER_RETRY_ERRORS = ("state_miss", "runner_error", "infra_error")
RUNNER_MAX_ATTEMPTS = 3   # infrastructure retries before a job waits for the operator
RUNNER_MAX_MISSES_PER_JOB = 32   # missing fork-state items one job may add to its program's extend list

PUBLIC_STATUSES = (
    STATUS_RECEIVED, STATUS_SCREENING, STATUS_REPRODUCING, STATUS_VALIDATED,
    STATUS_DUPLICATE, STATUS_FILED, STATUS_ACCEPTED, STATUS_REJECTED, STATUS_EXPIRED,
)

# A submission that failed the static policy screen.
STATUS_POLICY_REJECTED = STATUS_REJECTED

# Timing targets (hours) from docs/final-plan-2026-11-16.md, for monitoring only.
TARGET_VERDICT_H = 1
TARGET_VERDICT_HARD_H = 6
TARGET_FILE_END_TO_END_H = 12
CUTOFF_DAYS = 180

# Settlement (private): per-finding cap tied to the bounty, carry-over, burn deadline.
SETTLEMENT_PERIOD_DAYS = 30
CAP_ALPHA_PER_USD = float(os.environ.get("HYBLIS_CAP_ALPHA_PER_USD", "0"))  # 0 = no cap set yet
BURN_AFTER_DAYS = 365

# ---- secrets from env (never hard-coded) -----------------------------------
def dispatch_token() -> str:
    """Shared secret the runner machine uses on /internal/* endpoints."""
    tok = os.environ.get("HYBLIS_DISPATCH_TOKEN", "")
    if not tok:
        raise RuntimeError("HYBLIS_DISPATCH_TOKEN is not set (see scripts/start_platform.sh)")
    return tok


def server_seed() -> str | None:
    """Hex seed for the server receipt-signing key; None if unset (dev mode)."""
    return os.environ.get("HYBLIS_SERVER_SEED") or None


def cors_origins() -> set[str]:
    """Browser origins allowed to call the public/miner API (the Hyblis site).
    Comma-separated in HYBLIS_CORS_ORIGINS; defaults to the local site port."""
    raw = os.environ.get("HYBLIS_CORS_ORIGINS", f"http://127.0.0.1:{SITE_PORT},http://localhost:{SITE_PORT}")
    return {o.strip().rstrip("/") for o in raw.split(",") if o.strip()}


def public_hosts() -> set[str]:
    """The site's public host names (hyblis.com, www.hyblis.com): the hosts of the https origins in
    HYBLIS_CORS_ORIGINS. edge.https_only redirects plain-http visits to these hosts only."""
    from urllib.parse import urlsplit
    out = set()
    for o in cors_origins():
        u = urlsplit(o)
        if u.scheme == "https" and u.hostname:
            out.add(u.hostname.lower())
    return out


NETWORKS = ("mainnet", "testnet")


def network() -> str:
    """The subnet this platform serves: HYBLIS_NETWORK, "mainnet" (the default) or "testnet".
    A program whose releases.json entry lists "networks" is released only on those networks.
    Any other value is a configuration error, raised (the services refuse to start)."""
    v = os.environ.get("HYBLIS_NETWORK", "").strip().lower() or "mainnet"
    if v not in NETWORKS:
        raise ValueError(f"HYBLIS_NETWORK must be one of {', '.join(NETWORKS)} (got {v!r})")
    return v


def intake_override() -> bool | None:
    """HYBLIS_INTAKE_OPEN=1 opens intake whatever releases.json says, for the test suites and the
    testnet stack only: it is honoured on testnet and ignored on mainnet, so production cannot be
    opened by an environment variable. None = no override (releases.json "launch" decides)."""
    if os.environ.get("HYBLIS_INTAKE_OPEN", "").strip() == "1" and network() == "testnet":
        return True
    return None


_HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def client_ip_header() -> str:
    """The request header in which the trusted proxy names the client: HYBLIS_CLIENT_IP_HEADER,
    default X-Real-IP (nginx). Behind the Cloudflare Tunnel it is CF-Connecting-IP, the header
    Cloudflare adds. A value that is not a header name is a configuration error, raised."""
    v = os.environ.get("HYBLIS_CLIENT_IP_HEADER", "").strip() or "X-Real-IP"
    if not _HEADER_RE.match(v):
        raise ValueError(f"HYBLIS_CLIENT_IP_HEADER is not a header name: {v!r}")
    return v


def check() -> None:
    """Validate the settings that are read per request, so a typo stops a service at start."""
    network()
    client_ip_header()


def trusted_proxies() -> frozenset:
    """Peers allowed to name the real client in the client-address header (client_ip_header):
    the reverse proxy or tunnel in front of the gateway (runbook section J). Comma-separated
    addresses in HYBLIS_TRUSTED_PROXIES; defaults to this host's loopback, where that proxy runs.
    Entries that are not IP addresses are ignored."""
    out = set()
    for part in os.environ.get("HYBLIS_TRUSTED_PROXIES", "127.0.0.1,::1").split(","):
        try:
            out.add(ipaddress.ip_address(part.strip()))
        except ValueError:
            pass
    return frozenset(out)


_LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def public_api_base(host: str | None) -> str:
    """Base URL the site's JavaScript uses to reach the gateway, for a request whose Host
    header names `host` (no port). HYBLIS_PUBLIC_API_BASE wins when set; '' means same
    origin (site and API behind one domain). Unset, the local gateway port is right only
    for a browser on this machine; a visitor from anywhere else came through the proxy,
    which serves the API on the site's own origin."""
    base = os.environ.get("HYBLIS_PUBLIC_API_BASE")
    if base is not None:
        return base.rstrip("/")
    return f"http://127.0.0.1:{GATEWAY_PORT}" if host in _LOOPBACK_HOSTS else ""


def ensure_dirs() -> None:
    for d in (DATA_DIR, PUBLIC_DIR, RUN_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)
