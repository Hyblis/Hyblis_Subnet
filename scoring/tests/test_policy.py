import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hyblis_scoring.policy import Event, Policy, compute, to_u16_weights  # noqa: E402

P = Policy()


def approved(t, fid, miner, sev="high", prog="p1", seq=0, credit=None):
    return Event(t=t, kind="approved", finding=fid, program=prog, severity=sev,
                 credit=credit or ((miner, 1.0),), seq=seq)


class TestPolicy(unittest.TestCase):
    def test_empty_ledger_burns_everything(self):
        r = compute([], now=10)
        self.assertEqual(r["miners"], {})
        self.assertAlmostEqual(r["burn"], 1.0)

    def test_lone_low_is_not_a_windfall(self):
        r = compute([approved(0, "f1", "a", "low")], now=0)
        self.assertAlmostEqual(r["miners"]["a"], 1 * 0.3 * 0.02)      # 0.6% of the pool, not 100%
        self.assertAlmostEqual(r["burn"], 1 - 0.006)

    def test_paid_replaces_provisional_and_restarts_decay(self):
        ev = [approved(0, "f1", "a", "high"), Event(t=60, kind="paid", finding="f1", severity="high")]
        self.assertAlmostEqual(compute(ev, now=59)["miners"]["a"], 10 * 0.3 * 0.02 * 2 ** (-59 / 30))
        self.assertAlmostEqual(compute(ev, now=60)["miners"]["a"], 10 * 0.02)
        self.assertAlmostEqual(compute(ev, now=90)["miners"]["a"], 10 * 0.02 * 0.5)

    def test_expiry(self):
        ev = [approved(0, "f1", "a", "high"), Event(t=1, kind="paid", finding="f1", severity="high")]
        self.assertGreater(compute(ev, now=1 + 119.9)["miners"].get("a", 0), 0)
        self.assertNotIn("a", compute(ev, now=1 + 120)["miners"])

    def test_paid_with_downgraded_severity(self):
        ev = [approved(0, "f1", "a", "critical"), Event(t=5, kind="paid", finding="f1", severity="medium")]
        self.assertAlmostEqual(compute(ev, now=5)["miners"]["a"], 3 * 0.02)

    def test_rejections_and_strikes(self):
        ev = [approved(0, f"f{i}", "spam", "high", seq=i) for i in range(3)]
        ev += [Event(t=10 + i, kind="rejected_invalid", finding=f"f{i}", seq=10 + i) for i in range(2)]
        r = compute(ev, now=12)
        self.assertNotIn("spam", r["suspended"])
        self.assertAlmostEqual(r["miners"]["spam"], 10 * 0.3 * 0.02 * 2 ** (-12 / 30))   # only f2 left
        ev.append(Event(t=13, kind="rejected_invalid", finding="f2", seq=20))
        r = compute(ev + [approved(14, "f9", "spam", "high", seq=21)], now=14)
        self.assertIn("spam", r["suspended"])
        self.assertNotIn("spam", r["miners"])          # suspended miners earn nothing, even on new findings

    def test_duplicate_rejection_is_not_a_strike(self):
        ev = [approved(0, "f1", "a"), Event(t=5, kind="rejected_duplicate", finding="f1")]
        r = compute(ev, now=5)
        self.assertEqual(r["suspended"], [])
        self.assertNotIn("a", r["miners"])

    def test_same_finding_credited_once(self):
        ev = [approved(0, "f1", "a"), approved(1, "f1", "sybil")]
        self.assertNotIn("sybil", compute(ev, now=1)["miners"])

    def test_shared_credit(self):
        ev = [approved(0, "f1", "a", credit=(("a", 0.75), ("b", 0.25)))]
        r = compute(ev, now=0)
        self.assertAlmostEqual(r["miners"]["a"], 10 * 0.3 * 0.02 * 0.75)
        self.assertAlmostEqual(r["miners"]["a"] / r["miners"]["b"], 3.0)
        with self.assertRaises(ValueError):
            compute([approved(0, "f2", "a", credit=(("a", 0.5),))], now=0)

    def test_program_cap(self):
        ev = []
        for i in range(5):
            ev += [approved(0, f"c{i}", f"m{i}", "critical", prog="weak", seq=2 * i),
                   Event(t=0, kind="paid", finding=f"c{i}", severity="critical", seq=2 * i + 1)]
        r = compute(ev, now=0)                              # raw 5 x 60% = 300% of pool
        self.assertAlmostEqual(r["per_program"]["weak"], 0.25)
        self.assertAlmostEqual(sum(r["miners"].values()), 0.25)
        self.assertAlmostEqual(r["burn"], 0.75)

    def test_discovery_cap_across_programs(self):
        ev = []
        for p in range(5):
            ev += [approved(0, f"c{p}", f"m{p}", "critical", prog=f"p{p}", seq=2 * p),
                   Event(t=0, kind="paid", finding=f"c{p}", severity="critical", seq=2 * p + 1)]
        r = compute(ev, now=0)                              # 5 programs x 25% cap = 125% -> capped at 85%
        self.assertAlmostEqual(r["discovery"], 0.85)
        self.assertAlmostEqual(r["burn"], 0.15)

    def test_support_track(self):
        ev = [Event(t=0, kind="support", miner=f"s{i}", points=10, seq=i) for i in range(5)]
        r = compute(ev, now=0)                              # raw 5 x 10% = 50% -> capped at 15%
        self.assertAlmostEqual(r["support"], 0.15)
        self.assertAlmostEqual(compute(ev, now=7)["support"], 0.15 * 1.0)   # still above cap after one half-life
        self.assertAlmostEqual(compute(ev, now=28)["support"], 0.0)

    def test_trial_period_blocks_provisional_until_first_payment(self):
        pol = Policy(provisional_min_paid=1)
        ev = [approved(0, "f1", "new", "high", seq=1)]
        self.assertNotIn("new", compute(ev, now=1, policy=pol)["miners"])
        ev += [Event(t=10, kind="paid", finding="f1", severity="high", seq=2), approved(11, "f2", "new", "high", prog="p2", seq=3)]
        r = compute(ev, now=11, policy=pol)
        self.assertAlmostEqual(r["miners"]["new"], 10 * 0.02 * 2 ** (-1 / 30) + 10 * 0.3 * 0.02)

    def test_deterministic_regardless_of_input_order(self):
        ev = [approved(0, "f1", "a", seq=1), approved(0, "f2", "b", "low", seq=2),
              Event(t=3, kind="paid", finding="f1", severity="high", seq=3)]
        self.assertEqual(compute(ev, now=4), compute(list(reversed(ev)), now=4))

    def test_u16_weights_sum_and_owner_burn(self):
        r = compute([approved(0, "f1", "a"), approved(0, "f2", "b", "low", seq=1)], now=0)
        w = to_u16_weights(r, owner_hotkey="OWNER")
        self.assertEqual(sum(w.values()), 65535)
        self.assertGreater(w["OWNER"], w["a"])
        self.assertTrue(math.isclose(w["a"] / 65535, r["miners"]["a"], abs_tol=2 / 65535))


if __name__ == "__main__":
    unittest.main()
