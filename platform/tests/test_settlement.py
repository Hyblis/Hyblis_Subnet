"""Settlement unit tests (pure). Claims persist until paid/capped; burns fire
after paying and up to current_period."""
import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from hyblis_platform import settlement

def approx(a, b, e=1e-6): assert abs(a - b) < e, (a, b)

# bounty-ratio split within one period
acc = [{"finding": "a", "hotkey": "A", "bounty_usd": 1000, "period": 0},
       {"finding": "b", "hotkey": "B", "bounty_usd": 3000, "period": 0}]
p = settlement.settle({0: 40.0}, acc, 0.0, 12)
approx(p.by_finding["a"], 40 * 1000 / 4000); approx(p.by_finding["b"], 40 * 3000 / 4000)
approx(p.carry_end, 0.0)
print("ok split")

# carry-over then pay when the winner's period arrives
p = settlement.settle({0: 10.0, 1: 10.0}, [{"finding": "a", "hotkey": "A", "bounty_usd": 1, "period": 1}], 0.0, 12)
approx(p.by_finding["a"], 20.0); approx(p.carry_end, 0.0)
print("ok carry")

# per-finding cap leaves remainder in the vault
p = settlement.settle({0: 100.0}, [{"finding": "a", "hotkey": "A", "bounty_usd": 500, "period": 0}], 0.001, 12)
approx(p.by_finding["a"], 0.5); approx(p.carry_end, 99.5)
print("ok cap")

# FINDING 9 regression (capped mode): a finding accepted while the vault is low is
# still paid from LATER accrual, bounded by its cap.
p = settlement.settle({5: 1000.0}, [{"finding": "a", "hotkey": "A", "bounty_usd": 100, "period": 3}],
                      cap_alpha_per_usd=1.0, burn_after_periods=12)   # cap = 1.0 * 100 = 100
approx(p.by_finding["a"], 100.0)   # paid from period-5 accrual despite acceptance in period 3
approx(p.carry_end, 900.0)
print("ok late-accrual pays earlier finding (capped)")

# without a cap, settlement is per acceptance period: an empty period pays nothing later
p = settlement.settle({5: 1000.0}, [{"finding": "a", "hotkey": "A", "bounty_usd": 100, "period": 3}], 0.0, 12)
assert "a" not in p.by_finding, p.by_finding
print("ok per-period when uncapped")

# FINDING 7 regression: a winner in the burn period is PAID before the bucket burns
p = settlement.settle({0: 100.0}, [{"finding": "a", "hotkey": "A", "bounty_usd": 1, "period": 12}], 0.0, 12)
approx(p.by_finding["a"], 100.0)
assert not p.burns, p.burns
print("ok pay-before-burn")

# burn genuinely fires when nobody claims in time (finding 10: current_period forces it)
p = settlement.settle({0: 7.0}, [], 0.0, 12, current_period=20)
approx(sum(b["alpha"] for b in p.burns), 7.0); assert not p.payouts
print("ok burn via current_period")

# FIFO: older alpha leaves first so a timely payout avoids burn
p = settlement.settle({0: 10.0, 5: 10.0}, [{"finding": "a", "hotkey": "A", "bounty_usd": 1, "period": 5}], 0.0, 12)
approx(p.by_finding["a"], 20.0); assert not p.burns
print("ok fifo")

# never pays more than held, even with many claims
p = settlement.settle({0: 5.0}, [{"finding": f"f{i}", "hotkey": f"h{i}", "bounty_usd": 1000, "period": 0} for i in range(10)], 0.0, 12)
approx(sum(x["alpha"] for x in p.payouts), 5.0); approx(p.carry_end, 0.0)
print("ok conservation")

# empty
p = settlement.settle({}, [], 0.0, 12)
assert not p.payouts and p.carry_end == 0.0
print("ALL SETTLEMENT TESTS PASS")
