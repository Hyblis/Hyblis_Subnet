#!/usr/bin/env python3
"""Simulate policy v2 over two years: how often the miner pool has nobody to pay (all of it goes to the
owner UID, which the chain penalises), how many miners earn, and how concentrated the pool is.
25 miners; validated findings arrive at a Poisson rate per month; 60% are accepted 4-8 weeks later,
25% end as duplicates, 15% as invalid; severity mix low 40% / medium 45% / high 12% / critical 3%.
Warm-up track (optional): 10 miners each reproduce a historical exploit about every 2 weeks.
Deterministic (fixed seeds). Usage: python scoring/sim_v2.py [--runs 100]"""
import random, statistics, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from hyblis_scoring.policy import Event, PolicyV2, compute_v2

DAYS, STEP, MINERS = 730, 2, [f"m{i}" for i in range(25)]


def ledger(rate, warmup, seed):
    rnd, ev, seq = random.Random(seed), [], 0
    t = 0.0
    while True:
        t += rnd.expovariate(rate / 30.0)
        if t >= DAYS:
            break
        seq += 1; f = f"f{seq}"
        sev = rnd.choices(["low", "medium", "high", "critical"], [40, 45, 12, 3])[0]
        ev.append(Event(t=t, kind="approved", finding=f, program="p", severity=sev, credit=((rnd.choice(MINERS), 1.0),), seq=seq))
        out, lag = rnd.random(), rnd.uniform(28, 56)
        kind = "paid" if out < 0.60 else ("rejected_duplicate" if out < 0.85 else "rejected_invalid")
        seq += 1; ev.append(Event(t=t + lag, kind=kind, finding=f, severity=sev, seq=seq))
    if warmup:
        for m in MINERS[:10]:
            t = rnd.uniform(0, 14)
            while t < DAYS:
                seq += 1; ev.append(Event(t=t, kind="support", miner=m, points=1.0, seq=seq))
                t += rnd.uniform(7, 21)
    return ev


def run(rate, warmup, runs):
    burn_days, earners, top = [], [], []
    for s in range(runs):
        ev = ledger(rate, warmup, 1000 * s + int(rate * 100))
        b = n = 0; tops = []
        days = list(range(30, DAYS, STEP))          # from month 2 (the first month has nothing to judge yet)
        for d in days:
            r = compute_v2(ev, now=d)
            if r["burn"] >= 1.0:
                b += 1
            else:
                n += len(r["miners"]); tops.append(max(r["miners"].values()))
        burn_days.append(b / len(days)); earners.append(n / max(1, len(days) - b))
        top.append(statistics.mean(tops) if tops else 1.0)
    return statistics.mean(burn_days), statistics.mean(earners), statistics.mean(top)


if __name__ == "__main__":
    runs = int(sys.argv[sys.argv.index("--runs") + 1]) if "--runs" in sys.argv else 100
    print(f"policy v2, {runs} runs x 2 years, days 30-730 every {STEP} days")
    print(f"{'findings/month':>15} {'warm-up':>8} {'epochs with nobody to pay':>27} {'miners earning':>15} {'top miner share':>16}")
    for rate in (0.25, 0.5, 1, 2, 4):
        for warm in (False, True):
            b, n, t = run(rate, warm, runs)
            print(f"{rate:>15} {'yes' if warm else 'no':>8} {b:>26.0%} {n:>15.1f} {t:>15.0%}")
