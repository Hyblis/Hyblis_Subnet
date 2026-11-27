"""Unit tests for policy v2 (scoring/hyblis_scoring/policy.py: PolicyV2, compute_v2)."""
import sys, pathlib, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from hyblis_scoring.policy import Event, PolicyV2, compute_v2, to_u16_weights  # noqa: E402

P = PolicyV2()


def ap(t, f, hk, sev="medium", seq=0):
    return Event(t=t, kind="approved", finding=f, program="p", severity=sev, credit=((hk, 1.0),), seq=seq)


class V2(unittest.TestCase):
    def test_nothing_earned_burns_all(self):
        r = compute_v2([], now=10)
        self.assertEqual(r["miners"], {}); self.assertEqual(r["burn"], 1.0)

    def test_one_validated_finding_takes_the_whole_pool(self):
        r = compute_v2([ap(0, "f1", "A")], now=1)
        self.assertAlmostEqual(r["miners"]["A"], 1.0); self.assertEqual(r["burn"], 0.0)
        self.assertAlmostEqual(r["pools"]["validated"], 1.0)

    def test_validated_reward_expires_after_30_days(self):
        self.assertEqual(compute_v2([ap(0, "f1", "A")], now=30.1)["burn"], 1.0)

    def test_split_between_pools_and_severity(self):
        ev = [ap(0, "f1", "A", "medium", 1), ap(0, "f2", "B", "high", 2),
              Event(t=1, kind="paid", finding="f1", severity="medium", seq=3),
              Event(t=1, kind="support", miner="C", points=5, seq=4)]
        r = compute_v2(ev, now=1)
        self.assertAlmostEqual(sum(r["miners"].values()), 1.0)
        self.assertAlmostEqual(r["pools"]["validated"], 0.60); self.assertAlmostEqual(r["pools"]["accepted"], 0.25)
        self.assertAlmostEqual(r["pools"]["warmup"], 0.15)
        self.assertAlmostEqual(r["miners"]["C"], 0.15)                      # alone in the warm-up pool
        # validated pool by severity (medium 3, high 10, equal age) + A alone in the accepted pool
        dv = P.decay(1, "validated")
        self.assertAlmostEqual(r["miners"]["B"], 0.60 * 10 * dv / (13 * dv))
        self.assertAlmostEqual(r["miners"]["A"], 0.60 * 3 / 13 + 0.25)

    def test_empty_pool_passes_its_share_on(self):
        r = compute_v2([ap(0, "f1", "A"), Event(t=0, kind="support", miner="C", points=1, seq=2)], now=0)
        self.assertAlmostEqual(r["miners"]["A"], 0.60 / 0.75); self.assertAlmostEqual(r["miners"]["C"], 0.15 / 0.75)

    def test_rejection_stops_rewards_and_invalid_counts_a_strike(self):
        ev = [ap(0, "f1", "A", seq=1), Event(t=2, kind="rejected_invalid", finding="f1", seq=2)]
        self.assertEqual(compute_v2(ev, now=3)["burn"], 1.0)
        ev = [ap(0, f"f{i}", "A", seq=i) for i in range(4)] + \
             [Event(t=1, kind="rejected_invalid", finding=f"f{i}", seq=10 + i) for i in range(3)]
        r = compute_v2(ev, now=2)
        self.assertIn("A", r["suspended"]); self.assertEqual(r["burn"], 1.0)   # 3 strikes: f3 earns nothing

    def test_acceptance_outlives_validation(self):
        ev = [ap(0, "f1", "A", seq=1), Event(t=20, kind="paid", finding="f1", severity="high", seq=2),
              ap(40, "f2", "B", seq=3)]
        r = compute_v2(ev, now=45)                      # f1's validation expired, its acceptance has not
        self.assertAlmostEqual(r["miners"]["A"], 0.25 / 0.85); self.assertAlmostEqual(r["miners"]["B"], 0.60 / 0.85)

    def test_u16_weights_sum_and_owner_only_on_full_burn(self):
        r = compute_v2([ap(0, "f1", "A", seq=1), ap(0, "f2", "B", "high", seq=2)], now=1)
        w = to_u16_weights(r, "OWNER")
        self.assertEqual(sum(w.values()), 65535); self.assertNotIn("OWNER", w)
        self.assertEqual(to_u16_weights(compute_v2([], now=1), "OWNER"), {"OWNER": 65535})

    def test_miner_burn_takes_its_share_only_when_miners_earned(self):
        P2 = PolicyV2(miner_burn=0.20)
        r = compute_v2([ap(0, "f1", "A", seq=1), ap(0, "f2", "B", "high", seq=2)], now=1, policy=P2)
        self.assertAlmostEqual(sum(r["miners"].values()), 0.80); self.assertAlmostEqual(r["burn"], 0.20)
        w = to_u16_weights(r, "OWNER")
        self.assertEqual(sum(w.values()), 65535); self.assertAlmostEqual(w["OWNER"] / 65535, 0.20, places=4)
        self.assertEqual(compute_v2([], now=1, policy=P2)["burn"], 1.0)
        self.assertEqual(PolicyV2().miner_burn, 0.0)          # off unless set

    def test_deterministic(self):
        ev = [ap(0, "f1", "A", seq=1), ap(0.5, "f2", "B", "low", seq=2)]
        self.assertEqual(compute_v2(list(reversed(ev)), now=3), compute_v2(ev, now=3))


if __name__ == "__main__":
    unittest.main()
