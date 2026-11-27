"""Hyblis scoring engine (policy v1).

Pure and deterministic: the same events, `now` and policy always give the same weights. Validators
will run exactly this code on the signed event ledger, so it must stay free of I/O, randomness and
local clocks (`now` is the finalized block time).

Model (agreed 2026-11-14):
- Discovery track, in two stages:
  * internal approval  -> provisional points = severity points x provisional_fraction, decaying from approval
  * platform paid      -> provisional replaced by full points (final severity), decaying from payment
  * platform rejected  -> provisional removed; "invalid" also adds a strike (duplicates do not)
- Absolute scale: each point is worth `share_per_point` of the miner pool (not normalised against
  other miners). A cap per program and an overall discovery cap apply. Whatever is not earned goes
  to the subnet owner UID, where the chain withholds it (burn/recycle).
- Support track (optional): accepted security tests, own scale, own decay, own cap.
- Miners with `strikes_to_suspend` strikes earn nothing; their share is burned.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

SEVERITIES = ("low", "medium", "high", "critical")


@dataclass(frozen=True)
class Policy:
    version: str = "v1"
    severity_points: dict = field(default_factory=lambda: {"low": 1, "medium": 3, "high": 10, "critical": 30})
    provisional_fraction: float = 0.30
    share_per_point: float = 0.02          # 1 point = 2% of the miner pool (at full strength)
    half_life_days: float = 30.0
    expiry_days: float = 120.0
    program_cap: float = 0.25              # one program can take at most 25% of the miner pool
    discovery_cap: float = 0.85
    support_share_per_point: float = 0.01
    support_half_life_days: float = 7.0
    support_expiry_days: float = 28.0
    support_cap: float = 0.15
    strikes_to_suspend: int = 3
    provisional_min_paid: int = 0          # provisional points only for miners with >= N paid findings (trial period)

    def decay(self, age_days: float, support: bool = False) -> float:
        hl = self.support_half_life_days if support else self.half_life_days
        ex = self.support_expiry_days if support else self.expiry_days
        if age_days < 0 or age_days >= ex:
            return 0.0
        return 2.0 ** (-age_days / hl)


@dataclass(frozen=True)
class Event:
    """One ledger entry. `t` is in days (any fixed origin); `kind` is one of:
    approved(finding, program, severity, credit), paid(finding, severity[, usd]),
    rejected_invalid(finding), rejected_duplicate(finding), revoked(finding),
    support(miner, points)."""
    t: float
    kind: str
    finding: str = ""
    program: str = ""
    severity: str = ""
    credit: tuple = ()          # ((hotkey, fraction), ...) fractions sum to 1
    miner: str = ""
    points: float = 0.0
    usd: float = 0.0
    seq: int = 0                # ledger sequence, breaks ties deterministically


def compute(events: Iterable[Event], now: float, policy: Policy = Policy()) -> dict:
    """Return {"miners": {hotkey: share}, "burn": share, "discovery": share, "support": share,
    "per_program": {program: share}, "suspended": [...]}. Shares are fractions of the miner pool."""
    findings: dict = {}
    strikes: dict = {}
    paid_count: dict = {}
    support_raw: dict = {}
    for e in sorted((e for e in events if e.t <= now), key=lambda e: (e.t, e.seq)):
        if e.kind == "approved":
            if e.finding in findings:
                continue   # a finding is credited once (duplicates are grouped before they reach the ledger)
            total = sum(f for _, f in e.credit)
            if not e.credit or abs(total - 1.0) > 1e-9:
                raise ValueError(f"credit for {e.finding} must sum to 1")
            findings[e.finding] = {"program": e.program, "credit": e.credit, "state": "provisional",
                                   "severity": e.severity, "t0": e.t}
        elif e.kind == "paid":
            f = findings.get(e.finding)
            if f and f["state"] == "provisional":
                f.update(state="confirmed", severity=e.severity or f["severity"], t0=e.t)
                for hk, _ in f["credit"]:
                    paid_count[hk] = paid_count.get(hk, 0) + 1
        elif e.kind in ("rejected_invalid", "rejected_duplicate", "revoked"):
            f = findings.get(e.finding)
            if f and f["state"] in ("provisional", "confirmed"):
                f["state"] = "removed"
                if e.kind == "rejected_invalid":
                    for hk, _ in f["credit"]:
                        strikes[hk] = strikes.get(hk, 0) + 1
        elif e.kind == "support":
            age = now - e.t
            support_raw[e.miner] = support_raw.get(e.miner, 0.0) + e.points * policy.decay(age, support=True)

    suspended = {hk for hk, n in strikes.items() if n >= policy.strikes_to_suspend}

    # discovery shares, before caps: per program, per miner
    prog_miner: dict = {}
    for f in findings.values():
        if f["state"] == "removed":
            continue
        pts = policy.severity_points[f["severity"]]
        if f["state"] == "provisional":
            pts *= policy.provisional_fraction
        share = pts * policy.share_per_point * policy.decay(now - f["t0"])
        if share <= 0:
            continue
        for hk, frac in f["credit"]:
            if hk in suspended:
                continue
            if f["state"] == "provisional" and paid_count.get(hk, 0) < policy.provisional_min_paid:
                continue                    # still in trial: earns only once a platform pays
            pm = prog_miner.setdefault(f["program"], {})
            pm[hk] = pm.get(hk, 0.0) + share * frac

    miners: dict = {}
    per_program: dict = {}
    for prog in sorted(prog_miner):
        total = sum(prog_miner[prog].values())
        scale = min(1.0, policy.program_cap / total) if total > 0 else 0.0
        per_program[prog] = total * scale
        for hk, s in prog_miner[prog].items():
            miners[hk] = miners.get(hk, 0.0) + s * scale
    discovery = sum(miners.values())
    if discovery > policy.discovery_cap:
        k = policy.discovery_cap / discovery
        miners = {hk: s * k for hk, s in miners.items()}
        per_program = {p: s * k for p, s in per_program.items()}
        discovery = policy.discovery_cap

    sup = {hk: p * policy.support_share_per_point for hk, p in support_raw.items() if hk not in suspended and p > 0}
    support = sum(sup.values())
    if support > policy.support_cap:
        k = policy.support_cap / support
        sup = {hk: s * k for hk, s in sup.items()}
        support = policy.support_cap
    for hk, s in sup.items():
        miners[hk] = miners.get(hk, 0.0) + s

    burn = max(0.0, 1.0 - discovery - support)
    return {"miners": dict(sorted(miners.items())), "burn": burn, "discovery": discovery, "support": support,
            "per_program": per_program, "suspended": sorted(suspended), "policy": policy.version}


def to_u16_weights(result: dict, owner_hotkey: str) -> dict:
    """Integer weights for set_weights: miners plus the owner hotkey for the burned remainder.
    Largest-remainder rounding to 65535 total, ties broken by hotkey, so all validators agree."""
    shares = dict(result["miners"])
    shares[owner_hotkey] = shares.get(owner_hotkey, 0.0) + result["burn"]
    total = sum(shares.values()) or 1.0
    raw = {hk: s / total * 65535 for hk, s in shares.items()}
    w = {hk: int(v) for hk, v in raw.items()}
    rest = 65535 - sum(w.values())
    for hk in sorted(raw, key=lambda h: (-(raw[h] - w[h]), h))[:rest]:
        w[hk] += 1
    return {hk: v for hk, v in sorted(w.items()) if v > 0}


# ---- policy v2 (proposed 2026-11-23): pay at validation, top up at acceptance --------------------
# Why: in v1 everything not earned goes to the owner UID. The chain now treats weight on owner keys as
# burned miner incentive and cuts the subnet's emission share with it, so with few findings v1 burns
# most of the pool and is penalised. v2 is relative: each epoch the whole miner pool goes to miners
# who earned something, split between three pools; a pool with nobody in it passes its share to the
# others. Weight goes to the owner UID only when no miner has earned anything at all. Planned
# emission that is not yet justified is burned through the chain's explicit burn slot instead, which
# does not count as miner burn.

@dataclass(frozen=True)
class PolicyV2:
    version: str = "v2"
    # shares of the miner pool; a pool with no eligible miner passes its share to the others
    pools: dict = field(default_factory=lambda: {"validated": 0.60, "accepted": 0.25, "warmup": 0.15})
    severity_points: dict = field(default_factory=lambda: {"low": 1, "medium": 3, "high": 10, "critical": 30})
    # validated: from the runner's verdict (measured severity), fades out over about 30 days
    validated_half_life_days: float = 10.0
    validated_expiry_days: float = 30.0
    # accepted: from the platform's acceptance (final severity; bounty amounts stay private), 90 days
    accepted_half_life_days: float = 30.0
    accepted_expiry_days: float = 90.0
    # warm-up track: points per reproduced historical exploit ("support" events), short-lived
    warmup_half_life_days: float = 7.0
    warmup_expiry_days: float = 28.0
    strikes_to_suspend: int = 3
    # share of the miner pool sent to the owner UID (burned by the chain) whenever miners earned something;
    # the chain counts it as miner burn and scales the subnet's TAO emission by (1 - burn). 0 = off.
    miner_burn: float = 0.0

    def decay(self, age_days: float, pool: str) -> float:
        hl = getattr(self, f"{pool}_half_life_days")
        ex = getattr(self, f"{pool}_expiry_days")
        if age_days < 0 or age_days >= ex:
            return 0.0
        return 2.0 ** (-age_days / hl)


def compute_v2(events: Iterable[Event], now: float, policy: PolicyV2 = PolicyV2()) -> dict:
    """Return {"miners": {hotkey: share}, "burn": share, "pools": {pool: share paid}, "suspended": [...],
    "policy": "v2"}. Shares are fractions of the miner pool; miners + burn = 1. `burn` is 1 when no miner
    earned anything (the owner UID takes the pool), otherwise policy.miner_burn."""
    findings: dict = {}
    strikes: dict = {}
    warm_raw: dict = {}
    for e in sorted((e for e in events if e.t <= now), key=lambda e: (e.t, e.seq)):
        if e.kind == "approved":
            if e.finding in findings:
                continue
            total = sum(f for _, f in e.credit)
            if not e.credit or abs(total - 1.0) > 1e-9:
                raise ValueError(f"credit for {e.finding} must sum to 1")
            findings[e.finding] = {"credit": e.credit, "state": "validated", "severity": e.severity,
                                   "t_val": e.t, "t_acc": None, "final": None}
        elif e.kind == "paid":
            f = findings.get(e.finding)
            if f and f["state"] == "validated":
                f.update(state="accepted", final=e.severity or f["severity"], t_acc=e.t)
        elif e.kind in ("rejected_invalid", "rejected_duplicate", "revoked"):
            f = findings.get(e.finding)
            if f and f["state"] in ("validated", "accepted"):
                f["state"] = "removed"
                if e.kind == "rejected_invalid":
                    for hk, _ in f["credit"]:
                        strikes[hk] = strikes.get(hk, 0) + 1
        elif e.kind == "support":
            w = e.points * policy.decay(now - e.t, "warmup")
            if w > 0:
                warm_raw[e.miner] = warm_raw.get(e.miner, 0.0) + w

    suspended = {hk for hk, n in strikes.items() if n >= policy.strikes_to_suspend}
    raw = {p: {} for p in policy.pools}

    def add(pool, credit, pts):
        for hk, frac in credit:
            if hk not in suspended and pts > 0:
                raw[pool][hk] = raw[pool].get(hk, 0.0) + pts * frac

    for f in findings.values():
        if f["state"] == "removed":
            continue
        add("validated", f["credit"], policy.severity_points[f["severity"]] * policy.decay(now - f["t_val"], "validated"))
        if f["state"] == "accepted":
            add("accepted", f["credit"], policy.severity_points[f["final"]] * policy.decay(now - f["t_acc"], "accepted"))
    for hk, w in warm_raw.items():
        if hk not in suspended:
            raw["warmup"][hk] = raw["warmup"].get(hk, 0.0) + w

    live = {p: s for p, s in policy.pools.items() if sum(raw[p].values()) > 0}
    norm = sum(live.values())
    miners: dict = {}
    pools_paid: dict = {p: 0.0 for p in policy.pools}
    for p, share in live.items():
        total = sum(raw[p].values())
        for hk, v in raw[p].items():
            miners[hk] = miners.get(hk, 0.0) + share / norm * v / total
        pools_paid[p] = share / norm
    if miners:
        mb = min(max(float(policy.miner_burn), 0.0), 1.0)
        miners = {hk: v * (1.0 - mb) for hk, v in miners.items()}
        burn = mb
    else:
        burn = 1.0
    return {"miners": dict(sorted(miners.items())), "burn": burn, "pools": pools_paid,
            "suspended": sorted(suspended), "policy": policy.version}
