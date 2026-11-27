# Incentive mechanism (scoring policy v2)

Hyblis pays miners straight through the subnet's weights. Nothing is held in a team key. Every validator runs the
same scoring code (`scoring/hyblis_scoring/policy.py`, `compute_v2`) on the same public scoring ledger and sets the
same weights.

## What earns

Each epoch the miner pool is split between three pools:

| Pool | Share | What earns it | Duration |
|---|---|---|---|
| Validated findings | 60% | The runner reproduced the proof and measured the impact. Weighted by **measured** severity. | Half-life 10 days, ends after 30 days |
| Acceptance bonus | 25% | The program accepted the finding. Weighted by its **final** severity. | Half-life 30 days, ends after 90 days |
| Warm-up track | 15% | A reproduction of a real past exploit on its historical chain state (programs marked `"track": "warmup"`). One reward per miner per exploit. | Half-life 7 days, ends after 28 days |

Severity points: Low 1 · Medium 3 · High 10 · Critical 30.

- **Relative, not absolute.** Inside a pool, each miner gets a share proportional to its points. A pool with nobody
  in it passes its share to the other pools, so the whole miner pool goes to miners who earned something.
- **One finding keeps earning.** Rewards fade over the durations above, so a good finding earns across many epochs,
  not only the one it landed in.
- **Measured severity can only go down.** The severity used is the lower of the miner's claim and what the runner
  measured.

## What does not earn

- **Duplicates.** "Same bug" is keyed on what the runner measured: the in-scope contract and function behind the
  impact (and the same proof file). The earliest valid report wins.
- **Rejected findings.** A finding rejected as invalid stops earning and counts a strike; a duplicate stops earning
  without a strike. Three strikes suspend the hotkey.
- **Owner keys.** A hotkey under the subnet owner's coldkey never receives miner weight.

## Determinism

`compute_v2` is pure: no I/O, no randomness, no local clock (`now` is the finalized block time). Weights are
converted to u16 with largest-remainder rounding and ties broken by hotkey, so independent validators produce
identical rows. Tests: `scoring/tests/test_policy_v2.py`, `validator/test_weights.py`.

## Simulation

`scoring/sim_v2.py` replays two years of synthetic ledgers (25 miners, several finding rates) and reports how
often the pool has nobody to pay, how many miners earn and the top miner's share. With the warm-up track active,
10–15 miners earn in every epoch and no single miner averages above about half of the pool.
