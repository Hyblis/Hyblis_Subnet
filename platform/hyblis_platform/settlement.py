"""Vault settlement (PRIVATE). Turns accepted findings into concrete payout
instructions for the payout-operator vault (option A, decided 2026-11-16).

Rules (docs/final-plan-2026-11-16.md):
  * Pay only platform-accepted findings, split by the bounty each earned.
  * With a per-finding cap configured (the production case), a finding stays an
    OUTSTANDING CLAIM from its acceptance period until it is paid up to its cap,
    so a finding accepted while the vault is low is still paid from later accrual.
    With no cap configured (cap = 0), settlement is per acceptance period: a
    finding shares only the balance available in the period it was accepted
    (the vault accrues continuously, so it is not empty in steady state).
  * Per-finding cap = cap_alpha_per_usd x bounty_usd. Alpha freed by a cap, or by
    a period with no active claim, stays in the vault (carry-over).
  * Burn alpha that has waited longer than the burn deadline (~12 periods) — but
    only AFTER that period's claims have been paid, so a late winner is never
    denied alpha that burns in the same period.
  * The operator can pay accepted hotkeys and burn expired funds; it can never
    send funds to itself (enforced on-chain by HyblisVault, mirrored here).

Pure and deterministic: identical inputs give identical payout plans.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from . import config, store


@dataclass
class Bucket:
    period: int          # settlement period the alpha accrued in
    alpha: float


@dataclass
class Plan:
    payouts: list = field(default_factory=list)   # {finding, hotkey, alpha, period, bounty_usd}
    burns: list = field(default_factory=list)     # {alpha, accrued_period, burn_period}
    carry_end: float = 0.0
    by_hotkey: dict = field(default_factory=dict) # hotkey -> total alpha
    by_finding: dict = field(default_factory=dict)# finding -> total alpha
    periods: list = field(default_factory=list)   # per-period summary


def settle(accrual: dict[int, float], accepted: list[dict], cap_alpha_per_usd: float = 0.0,
           burn_after_periods: int = 12, current_period: int | None = None) -> Plan:
    """accrual[p]  = alpha entering the vault during period p.
    accepted      = [{finding, hotkey, bounty_usd, period}] (period = acceptance period).
    cap_alpha_per_usd = 0 disables the cap. current_period lets burns fire up to the
    chain's current period even if accrual has no key there. Returns a Plan.
    """
    plan = Plan()
    buckets: list[Bucket] = []
    capped = cap_alpha_per_usd > 0
    claims = []
    for a in accepted:
        cap = cap_alpha_per_usd * max(0.0, a["bounty_usd"]) if capped else math.inf
        claims.append({"finding": a["finding"], "hotkey": a["hotkey"],
                       "bounty": max(0.0, a["bounty_usd"]), "accept_period": int(a["period"]),
                       "paid": 0.0, "cap": cap})
    seen_periods = set(accrual) | {c["accept_period"] for c in claims}
    if not seen_periods:
        return plan
    start, last = min(seen_periods), max(seen_periods)
    if current_period is not None:
        last = max(last, int(current_period))

    for p in range(start, last + 1):
        if accrual.get(p, 0.0) > 0:
            buckets.append(Bucket(p, float(accrual[p])))

        # ---- pay active claims BEFORE burning ----
        available = sum(b.alpha for b in buckets)
        # With a cap, a claim persists from its acceptance period until it is capped.
        # Without a cap, it is active only in its acceptance period (per-period settlement).
        if capped:
            active = [c for c in claims if c["accept_period"] <= p and c["paid"] + 1e-12 < c["cap"]]
        else:
            active = [c for c in claims if c["accept_period"] == p]
        row = {"period": p, "accrued": accrual.get(p, 0.0), "available": available,
               "paid": 0.0, "burned": 0.0, "active_claims": len(active)}
        if active and available > 1e-12:
            tot_bounty = sum(c["bounty"] for c in active) or 1.0
            want = {}
            for c in active:
                share = available * c["bounty"] / tot_bounty
                share = min(share, c["cap"] - c["paid"])
                want[c["finding"]] = max(0.0, share)
            s = sum(want.values())
            if s > available:                       # float guard: never pay more than held
                f = available / s
                want = {k: v * f for k, v in want.items()}
                s = sum(want.values())
            # draw FIFO (oldest alpha leaves first, so it does not burn)
            to_draw = s
            for b in buckets:
                if to_draw <= 1e-12:
                    break
                take = min(b.alpha, to_draw)
                b.alpha -= take
                to_draw -= take
            for c in active:
                amt = want[c["finding"]]
                if amt <= 1e-12:
                    continue
                c["paid"] += amt
                plan.payouts.append({"finding": c["finding"], "hotkey": c["hotkey"], "alpha": amt,
                                     "period": p, "bounty_usd": c["bounty"]})
                plan.by_hotkey[c["hotkey"]] = plan.by_hotkey.get(c["hotkey"], 0.0) + amt
                plan.by_finding[c["finding"]] = plan.by_finding.get(c["finding"], 0.0) + amt
            row["paid"] = s

        # ---- burn aged buckets AFTER paying ----
        burned = 0.0
        keep: list[Bucket] = []
        for b in buckets:
            if p - b.period >= burn_after_periods and b.alpha > 1e-12:
                plan.burns.append({"alpha": b.alpha, "accrued_period": b.period, "burn_period": p})
                burned += b.alpha
            elif b.alpha > 1e-12:
                keep.append(b)
        buckets = keep
        row["burned"] = burned
        plan.periods.append(row)

    plan.carry_end = sum(b.alpha for b in buckets)
    return plan


def plan_from_store(accrual: dict[int, float], cap_alpha_per_usd: float | None = None,
                    current_period: int | None = None) -> Plan:
    """Build a settlement plan from accepted submissions in the store.
    `accrual` maps settlement-period index -> alpha that entered the vault then.
    cap defaults to config.CAP_ALPHA_PER_USD. current_period defaults to the latest
    period seen in accrual/acceptances; pass it to force burns up to 'now'.
    """
    cap = config.CAP_ALPHA_PER_USD if cap_alpha_per_usd is None else cap_alpha_per_usd
    accepted = []
    for sub in store.all_submissions():
        if sub["status"] == config.STATUS_ACCEPTED and sub["settle_period"] is not None:
            accepted.append({"finding": sub["submission_id"], "hotkey": sub["hotkey"],
                             "bounty_usd": float(sub["bounty_usd"] or 0.0), "period": int(sub["settle_period"])})
    burn_after = max(1, config.BURN_AFTER_DAYS // config.SETTLEMENT_PERIOD_DAYS)
    return settle(accrual, accepted, cap, burn_after, current_period)
